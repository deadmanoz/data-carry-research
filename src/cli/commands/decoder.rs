use crate::config::{output_paths, AppConfig, BitcoinRpcConfig};
use crate::decoder::{DecodedData, ProtocolDecoder};
use crate::errors::{AppError, AppResult};
use crate::rpc::BitcoinRpcClient;
use clap::{Args, Subcommand};
use corepc_client::bitcoin::consensus;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Fetch command types
#[derive(Subcommand, Clone)]
pub enum FetchCommands {
    /// Fetch a single transaction from Bitcoin Core RPC
    Tx {
        /// Transaction ID to fetch
        txid: String,

        /// Protocol directory (counterparty, stamps, omni) for output routing
        #[arg(long)]
        protocol: Option<String>,

        /// Custom output filename (without .json extension)
        #[arg(long)]
        output: Option<String>,

        /// Custom output root directory (default: ./output_data/fetched for fetched transactions)
        #[arg(long, default_value = output_paths::FETCHED_BASE)]
        output_dir: PathBuf,

        /// Also fetch all input transactions
        #[arg(long)]
        with_inputs: bool,

        /// Auto-detect protocol using Stage 4 decoder
        #[arg(long)]
        auto_detect: bool,

        /// Bitcoin RPC URL (overrides config.toml)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Bitcoin RPC username (overrides config.toml)
        #[arg(long)]
        rpc_username: Option<String>,

        /// Bitcoin RPC password (overrides config.toml)
        #[arg(long)]
        rpc_password: Option<String>,
    },

    /// Batch fetch transactions from file or stdin
    Batch {
        /// File containing TXIDs (one per line), or stdin if omitted
        #[arg(long)]
        file: Option<PathBuf>,

        /// Protocol directory for all transactions
        #[arg(long)]
        protocol: Option<String>,

        /// Also fetch input transactions for each
        #[arg(long)]
        with_inputs: bool,

        /// Concurrent fetch limit
        #[arg(long, default_value = "4")]
        parallel: usize,

        /// Custom output root directory (default: ./output_data/fetched for fetched transactions)
        #[arg(long, default_value = output_paths::FETCHED_BASE)]
        output_dir: PathBuf,

        /// Bitcoin RPC URL (overrides config.toml)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Bitcoin RPC username (overrides config.toml)
        #[arg(long)]
        rpc_username: Option<String>,

        /// Bitcoin RPC password (overrides config.toml)
        #[arg(long)]
        rpc_password: Option<String>,
    },

    /// Scan test fixtures and fetch missing input transactions
    ScanInputs {
        /// Glob pattern for fixture files (e.g., tests/test_data/omni/*.json)
        pattern: String,

        /// Output directory for input transactions
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Bitcoin RPC URL (overrides config.toml)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Bitcoin RPC username (overrides config.toml)
        #[arg(long)]
        rpc_username: Option<String>,

        /// Bitcoin RPC password (overrides config.toml)
        #[arg(long)]
        rpc_password: Option<String>,
    },
}

// Individual command structures
#[derive(Args)]
pub struct TestRpcCommand {
    /// Bitcoin RPC URL
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Bitcoin RPC username
    #[arg(long)]
    pub rpc_username: Option<String>,

    /// Bitcoin RPC password
    #[arg(long)]
    pub rpc_password: Option<String>,
}

impl TestRpcCommand {
    pub async fn run(&self) -> AppResult<()> {
        test_rpc_connection(
            self.rpc_url.clone(),
            self.rpc_username.clone(),
            self.rpc_password.clone(),
        )
        .await
    }
}

#[derive(Args)]
pub struct DecodeTxidCommand {
    /// Transaction ID to decode
    pub txid: String,

    /// Output directory for decoded data
    #[arg(long, default_value = output_paths::DECODED_BASE)]
    pub output_dir: PathBuf,

    /// Bitcoin RPC URL (overrides config.toml)
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Bitcoin RPC username (overrides config.toml)
    #[arg(long)]
    pub rpc_username: Option<String>,

    /// Bitcoin RPC password (overrides config.toml)
    #[arg(long)]
    pub rpc_password: Option<String>,

    /// Skip file output and only return protocol classification (for bulk testing)
    #[arg(long)]
    pub no_output: bool,

    /// Show verbose output with detailed decoding process information
    #[arg(long, short = 'v')]
    pub verbose: bool,
}

impl DecodeTxidCommand {
    pub async fn run(&self) -> AppResult<()> {
        run_decode_txid(
            self.txid.clone(),
            self.output_dir.clone(),
            self.rpc_url.clone(),
            self.rpc_username.clone(),
            self.rpc_password.clone(),
            self.no_output,
            self.verbose,
        )
        .await
    }
}

#[derive(Args)]
pub struct FetchCommand {
    #[command(subcommand)]
    pub fetch_type: FetchCommands,
}

impl FetchCommand {
    pub async fn run(&self) -> AppResult<()> {
        run_fetch_command(&self.fetch_type).await
    }
}

#[derive(Args)]
pub struct Arc4Command {
    /// Transaction ID to analyse
    pub txid: String,

    /// Show raw P2MS data before decryption
    #[arg(long)]
    pub show_raw: bool,

    /// Output format: text, hex, json
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Bitcoin RPC URL (overrides config.toml)
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Bitcoin RPC username (overrides config.toml)
    #[arg(long)]
    pub rpc_username: Option<String>,

    /// Bitcoin RPC password (overrides config.toml)
    #[arg(long)]
    pub rpc_password: Option<String>,
}

impl Arc4Command {
    pub async fn run(&self) -> AppResult<()> {
        run_arc4(
            self.txid.clone(),
            self.show_raw,
            self.format.clone(),
            self.rpc_url.clone(),
            self.rpc_username.clone(),
            self.rpc_password.clone(),
        )
        .await
    }
}

// Implementation functions
async fn test_rpc_connection(
    rpc_url: Option<String>,
    rpc_username: Option<String>,
    rpc_password: Option<String>,
) -> AppResult<()> {
    info!("=== Testing Bitcoin RPC Connection ===");

    // Load configuration or use defaults
    let app_config = AppConfig::get_defaults().map_err(|e| AppError::Config(e.to_string()))?;
    let mut rpc_config = app_config.bitcoin_rpc;

    // Override with CLI arguments
    if let Some(url) = rpc_url {
        rpc_config.url = url;
    }
    if let Some(username) = rpc_username {
        rpc_config.username = username;
    }
    if let Some(password) = rpc_password {
        rpc_config.password = password;
    }

    info!("Testing connection to: {}", rpc_config.url);
    info!("Username: {}", rpc_config.username);

    match crate::rpc::BitcoinRpcClient::new(rpc_config).await {
        Ok(client) => {
            info!("✅ RPC connection successful!");

            // Test a simple RPC call
            match client.test_connection().await {
                Ok(()) => {
                    println!("✅ Bitcoin RPC connection test PASSED");
                    println!("Connection is working correctly!");
                }
                Err(e) => {
                    error!("❌ RPC connection test failed: {}", e);
                    return Err(AppError::Config(format!("RPC test failed: {}", e)));
                }
            }
        }
        Err(e) => {
            error!("❌ Failed to create RPC client: {}", e);
            println!("❌ Bitcoin RPC connection test FAILED");
            println!("Error: {}", e);
            println!("\nTroubleshooting tips:");
            println!("1. Check that Bitcoin Core is running");
            println!("2. Verify the RPC URL is correct");
            println!("3. Ensure RPC credentials are valid");
            println!("4. Check that RPC server is enabled in bitcoin.conf");

            return Err(AppError::Config(format!(
                "RPC client creation failed: {}",
                e
            )));
        }
    }

    Ok(())
}

async fn run_decode_txid(
    txid: String,
    output_dir: PathBuf,
    rpc_url: Option<String>,
    rpc_username: Option<String>,
    rpc_password: Option<String>,
    no_output: bool,
    verbose: bool,
) -> AppResult<()> {
    if no_output {
        info!(
            "Starting transaction decoding for TXID: {} (no-output mode)",
            txid
        );
    } else {
        info!("Starting transaction decoding for TXID: {}", txid);
        info!("Output directory: {}", output_dir.display());
    }

    // Load configuration, allowing CLI overrides
    let config = AppConfig::load()
        .map_err(|e| AppError::Config(format!("Failed to load configuration: {}", e)))?;

    // Build RPC configuration with CLI overrides
    let rpc_config = BitcoinRpcConfig {
        url: rpc_url.unwrap_or(config.bitcoin_rpc.url),
        username: rpc_username.unwrap_or(config.bitcoin_rpc.username),
        password: rpc_password.unwrap_or(config.bitcoin_rpc.password),
        max_retries: config.bitcoin_rpc.max_retries,
        timeout_seconds: config.bitcoin_rpc.timeout_seconds,
        initial_backoff_ms: config.bitcoin_rpc.initial_backoff_ms,
        backoff_multiplier: config.bitcoin_rpc.backoff_multiplier,
        max_backoff_seconds: config.bitcoin_rpc.max_backoff_seconds,
        concurrent_requests: config.bitcoin_rpc.concurrent_requests,
    };

    // Initialise the decoder - use temp directory if no-output mode
    let actual_output_dir = if no_output {
        std::env::temp_dir().join("stamps_decoder_temp")
    } else {
        output_dir
    };

    let decoder = ProtocolDecoder::new(rpc_config, actual_output_dir)
        .await
        .map_err(|e| AppError::Config(format!("Failed to initialise decoder: {}", e)))?;

    info!("Decoder initialised successfully, attempting to decode transaction...");

    // Attempt to decode the transaction using verbose version if requested
    let decode_result = if verbose {
        decoder.decode_txid_verbose(&txid, true).await
    } else {
        decoder.decode_txid(&txid).await
    };

    match decode_result {
        Ok(Some(decoded_data)) => {
            if no_output {
                match &decoded_data {
                    DecodedData::BitcoinStamps { data } => match data {
                        crate::decoder::BitcoinStampsData::Image(decoded_image) => {
                            println!(
                                "TXID:{} TYPE:IMAGE FORMAT:{:?} SIZE:{}",
                                txid, decoded_image.format, decoded_image.size_bytes
                            );
                        }
                        crate::decoder::BitcoinStampsData::Json(decoded_json) => {
                            println!(
                                "TXID:{} TYPE:JSON PROTOCOL:{:?} SIZE:{}",
                                txid, decoded_json.json_type, decoded_json.size_bytes
                            );
                        }
                        crate::decoder::BitcoinStampsData::Html(decoded_html) => {
                            println!("TXID:{} TYPE:HTML SIZE:{}", txid, decoded_html.size_bytes);
                        }
                        crate::decoder::BitcoinStampsData::Compressed(decoded_compressed) => {
                            println!(
                                "TXID:{} TYPE:COMPRESSED ALGORITHM:{} SIZE:{}",
                                txid,
                                decoded_compressed.compression_type,
                                decoded_compressed.size_bytes
                            );
                        }
                        crate::decoder::BitcoinStampsData::Data(decoded_data) => {
                            println!("TXID:{} TYPE:DATA SIZE:{}", txid, decoded_data.size_bytes);
                        }
                    },
                    DecodedData::Counterparty { data } => {
                        println!(
                            "TXID:{} TYPE:COUNTERPARTY MESSAGE:{:?} SIZE:{}",
                            txid,
                            data.message_type,
                            data.raw_data.len()
                        );
                    }
                    DecodedData::Omni { data } => {
                        println!(
                            "TXID:{} TYPE:OMNI MESSAGE:{:?} SIZE:{} PACKETS:{}",
                            txid,
                            data.message_type,
                            data.deobfuscated_payload.len(),
                            data.packet_count
                        );
                    }
                    DecodedData::Chancecoin { data } => {
                        println!(
                            "TXID:{} TYPE:Chancecoin MESSAGE:{:?} SIZE:{}",
                            txid,
                            data.message_type,
                            data.data.len()
                        );
                    }
                    DecodedData::PPk { data } => {
                        let odin_str = data
                            .odin_identifier
                            .as_ref()
                            .map(|o| format!(" ODIN:{}", o.full_identifier))
                            .unwrap_or_default();
                        println!(
                            "TXID:{} TYPE:PPk VARIANT:{:?} CONTENT_TYPE:{}{}",
                            txid, data.variant, data.content_type, odin_str
                        );
                    }
                    DecodedData::DataStorage(data) => {
                        println!(
                            "TXID:{} TYPE:DATASTORAGE PATTERN:{} SIZE:{}",
                            txid,
                            data.pattern,
                            data.decoded_data.len()
                        );
                    }
                    DecodedData::LikelyDataStorage(data) => {
                        println!(
                            "TXID:{} TYPE:LIKELYDATASTORAGE PATTERN:{}",
                            txid, data.pattern_type
                        );
                    }
                }
            } else {
                match decoded_data {
                    DecodedData::BitcoinStamps { data } => match data {
                        crate::decoder::BitcoinStampsData::Image(decoded_image) => {
                            info!("✅ Successfully decoded Bitcoin Stamps image!");
                            info!("📄 {}", decoded_image.summary());
                        }
                        crate::decoder::BitcoinStampsData::Json(decoded_json) => {
                            info!("✅ Successfully decoded Bitcoin Stamps JSON data!");
                            info!("📄 {}", decoded_json.summary());
                        }
                        crate::decoder::BitcoinStampsData::Html(decoded_html) => {
                            info!("✅ Successfully decoded Bitcoin Stamps HTML!");
                            info!("📄 {}", decoded_html.summary());
                        }
                        crate::decoder::BitcoinStampsData::Compressed(decoded_compressed) => {
                            info!("✅ Successfully decoded Bitcoin Stamps compressed data!");
                            info!("📄 {}", decoded_compressed.summary());
                        }
                        crate::decoder::BitcoinStampsData::Data(decoded_data) => {
                            info!("✅ Successfully decoded Bitcoin Stamps raw data!");
                            info!("📄 {}", decoded_data.summary());
                        }
                    },
                    DecodedData::Counterparty { data } => {
                        info!("✅ Successfully decoded Counterparty data!");
                        info!("📄 Message Type: {:?}", data.message_type);
                        info!("📄 Size: {} bytes", data.raw_data.len());
                        info!("📄 File: {}", data.file_path.display());
                    }
                    DecodedData::Omni { data } => {
                        info!("✅ Successfully decoded Omni Layer data!");
                        info!(
                            "📄 Message Type: {:?} (Type {})",
                            data.message_type, data.message_type as u32
                        );
                        info!("📄 Sender: {}", data.sender_address);
                        info!("📄 Packets: {}", data.packet_count);
                        info!("📄 Size: {} bytes", data.deobfuscated_payload.len());
                        info!("📄 File: {}", data.file_path.display());
                    }
                    DecodedData::Chancecoin { data } => {
                        info!("✅ Successfully decoded Chancecoin data!");
                        info!("📄 Message Type: {:?}", data.message_type);
                        info!("📄 Size: {} bytes", data.data.len());
                        info!("📄 File: {}", data.file_path.display());
                    }
                    DecodedData::PPk { data } => {
                        info!("✅ Successfully decoded PPk protocol data!");
                        info!("📄 Variant: {:?}", data.variant);
                        info!("📄 Content Type: {}", data.content_type);
                        if let Some(ref odin) = data.odin_identifier {
                            info!("📄 ODIN: {}", odin.full_identifier);
                            info!(
                                "   • Block: {} (time: {})",
                                odin.block_height, odin.block_time
                            );
                            info!("   • TX index: {}", odin.tx_index);
                            info!("   • DSS: {}", odin.dss);
                        }
                        if let Some(ref rt_json) = data.rt_json {
                            info!(
                                "📄 RT JSON fields: {}",
                                rt_json.as_object().map(|o| o.len()).unwrap_or(0)
                            );
                        }
                        info!("📄 File: {}", data.file_path.display());
                    }
                    DecodedData::DataStorage(data) => {
                        info!("✅ Successfully decoded DataStorage data!");
                        info!("📄 Pattern: {}", data.pattern);
                        info!("📄 Size: {} bytes", data.decoded_data.len());
                        if let Some(metadata) = data.metadata.as_object() {
                            if let Some(total_pubkeys) = metadata.get("total_pubkeys") {
                                info!("📄 Total pubkeys: {}", total_pubkeys);
                            }
                        }
                        // Note: DataStorage saves to multiple files in pattern-specific subdirectories
                    }
                    DecodedData::LikelyDataStorage(data) => {
                        info!("✅ Successfully classified as Likely Data Storage!");
                        info!("📄 Pattern Type: {}", data.pattern_type);
                        info!("📄 Details: {}", data.details);
                        info!("📄 Metadata file: {}", data.file_path.display());
                    }
                }
            }
        }
        Ok(None) => {
            if no_output {
                println!("TXID:{} TYPE:NONE", txid);
            } else {
                info!("ℹ️  Transaction analysis complete:");
                info!("   • Transaction {} was processed", txid);
                info!("   • Result: No recognised protocol detected");
                info!("   • Checked: Bitcoin Stamps, Counterparty, Omni, DataStorage");
            }
        }
        Err(e) => {
            // Check if this is a "transaction not found" error
            let error_str = e.to_string();
            if error_str.contains("does not exist in the blockchain") {
                if no_output {
                    println!("TXID:{} TYPE:ERROR ERROR:NOT_FOUND", txid);
                } else {
                    info!("ℹ️  Transaction analysis complete:");
                    info!("   • Transaction {} does not exist", txid);
                    info!("   • This transaction was not found in the blockchain or mempool");
                    info!("   • Please verify the transaction ID is correct");
                }
            } else if no_output {
                println!(
                    "TXID:{} TYPE:ERROR ERROR:{}",
                    txid,
                    error_str.replace(' ', "_")
                );
            } else {
                error!("❌ Failed to decode transaction {}: {}", txid, e);
                return Err(AppError::Config(format!("Decoding failed: {}", e)));
            }
        }
    }

    Ok(())
}

async fn run_fetch_command(fetch_type: &FetchCommands) -> AppResult<()> {
    match fetch_type {
        FetchCommands::Tx {
            txid,
            protocol,
            output,
            output_dir,
            with_inputs,
            auto_detect,
            rpc_url,
            rpc_username,
            rpc_password,
        } => {
            info!("Fetching transaction: {}", txid);

            // Load RPC configuration
            let app_config = AppConfig::load().unwrap_or_else(|_| {
                AppConfig::get_defaults().expect("Failed to create default config")
            });
            let mut rpc_config = app_config.bitcoin_rpc;

            // Override with CLI arguments
            if let Some(url) = rpc_url {
                rpc_config.url = url.clone();
            }
            if let Some(username) = rpc_username {
                rpc_config.username = username.clone();
            }
            if let Some(password) = rpc_password {
                rpc_config.password = password.clone();
            }

            // Create RPC client
            let rpc_client = BitcoinRpcClient::new(rpc_config.clone()).await?;

            // Fetch transaction
            let transaction = rpc_client.get_transaction(txid).await?;

            // Determine protocol directory
            let protocol_dir = if *auto_detect {
                // Use decoder to detect protocol (with temp dir for detection artifacts)
                let temp_dir = std::env::temp_dir().join("data-carry-decoder");
                fs::create_dir_all(&temp_dir)?;
                let decoder = ProtocolDecoder::new(rpc_config, temp_dir).await?;
                match decoder.decode_txid(txid).await {
                    Ok(Some(decoded)) => {
                        let detected_protocol = match decoded {
                            DecodedData::BitcoinStamps { .. } => "stamps",
                            DecodedData::Counterparty { .. } => "counterparty",
                            DecodedData::Omni { .. } => "omni",
                            DecodedData::Chancecoin { .. } => "chancecoin",
                            DecodedData::PPk { .. } => "ppk",
                            DecodedData::DataStorage(_) => "datastorage",
                            DecodedData::LikelyDataStorage(_) => "likely_data_storage",
                        };
                        info!("Auto-detected protocol: {}", detected_protocol);
                        detected_protocol
                    }
                    Ok(None) => {
                        warn!("Could not auto-detect protocol, using 'unknown'");
                        "unknown"
                    }
                    Err(e) => {
                        warn!("Protocol detection failed: {}, using 'unknown'", e);
                        "unknown"
                    }
                }
            } else {
                protocol.as_deref().unwrap_or("stamps")
            };

            // Create output directory
            let protocol_path = output_dir.join(protocol_dir);
            fs::create_dir_all(&protocol_path)?;

            // Determine output filename
            let filename = output.as_ref().map(|s| s.as_str()).unwrap_or(txid);
            let output_file = protocol_path.join(format!("{}.json", filename));

            // Convert transaction to JSON
            let serialized = consensus::serialize(&transaction);
            let tx_hex = hex::encode(&serialized);

            // Create JSON object matching Bitcoin Core RPC format
            let tx_json = serde_json::json!({
                "txid": txid,
                "hash": transaction.compute_wtxid().to_string(),
                "version": transaction.version.0,
                "size": serialized.len(),
                "vsize": transaction.vsize(),
                "weight": transaction.weight().to_wu(),
                "locktime": transaction.lock_time.to_consensus_u32(),
                "vin": transaction.input.iter().map(|input| {
                    serde_json::json!({
                        "txid": input.previous_output.txid.to_string(),
                        "vout": input.previous_output.vout,
                        "scriptSig": {
                            "asm": format!("{:?}", input.script_sig),
                            "hex": hex::encode(input.script_sig.as_bytes())
                        },
                        "sequence": input.sequence.0,
                    })
                }).collect::<Vec<_>>(),
                "vout": transaction.output.iter().enumerate().map(|(n, output)| {
                    serde_json::json!({
                        "value": output.value.to_btc(),
                        "n": n,
                        "scriptPubKey": {
                            "asm": format!("{:?}", output.script_pubkey),
                            "hex": hex::encode(output.script_pubkey.as_bytes()),
                            "type": if output.script_pubkey.is_p2pkh() {
                                "pubkeyhash"
                            } else if output.script_pubkey.is_p2sh() {
                                "scripthash"
                            } else if output.script_pubkey.is_p2wpkh() {
                                "witness_v0_keyhash"
                            } else if output.script_pubkey.is_p2wsh() {
                                "witness_v0_scripthash"
                            } else if output.script_pubkey.is_op_return() {
                                "nulldata"
                            } else if output.script_pubkey.is_multisig() {
                                "multisig"
                            } else {
                                "nonstandard"
                            }
                        }
                    })
                }).collect::<Vec<_>>(),
                "hex": tx_hex,
            });

            // Write to file
            fs::write(&output_file, serde_json::to_string_pretty(&tx_json)?)?;

            // Validate
            let vin_count = transaction.input.len();
            let vout_count = transaction.output.len();

            println!("✓ Fetched transaction: {}", txid);
            println!("  - VIN entries: {}", vin_count);
            println!("  - VOUT entries: {}", vout_count);
            println!("  - Saved to: {}", output_file.display());

            if vin_count == 0 {
                warn!("⚠️  Transaction has no inputs (coinbase or unusual tx)");
            }

            // Fetch inputs if requested
            if *with_inputs {
                println!("\nFetching input transactions...");
                let inputs_dir = protocol_path.join("inputs");
                fs::create_dir_all(&inputs_dir)?;

                let mut fetched = 0;
                let mut skipped = 0;

                for input in &transaction.input {
                    let input_txid = input.previous_output.txid.to_string();
                    let input_file = inputs_dir.join(format!("{}.json", input_txid));

                    if input_file.exists() {
                        skipped += 1;
                        continue;
                    }

                    match rpc_client.get_transaction(&input_txid).await {
                        Ok(input_tx) => {
                            let serialized = consensus::serialize(&input_tx);
                            let tx_hex = hex::encode(&serialized);

                            let input_json = serde_json::json!({
                                "txid": input_txid,
                                "hash": input_tx.compute_wtxid().to_string(),
                                "version": input_tx.version.0,
                                "hex": tx_hex,
                                "vin": input_tx.input.iter().map(|i| serde_json::json!({
                                    "txid": i.previous_output.txid.to_string(),
                                    "vout": i.previous_output.vout,
                                })).collect::<Vec<_>>(),
                                "vout": input_tx.output.iter().enumerate().map(|(n, o)| serde_json::json!({
                                    "value": o.value.to_btc(),
                                    "n": n,
                                })).collect::<Vec<_>>(),
                            });

                            fs::write(&input_file, serde_json::to_string_pretty(&input_json)?)?;
                            fetched += 1;
                            println!("  ✓ {}", input_txid);
                        }
                        Err(e) => {
                            warn!("  ✗ Failed to fetch {}: {}", input_txid, e);
                        }
                    }
                }

                println!(
                    "\nInput transactions: {} fetched, {} already existed",
                    fetched, skipped
                );
            }

            Ok(())
        }

        FetchCommands::Batch {
            file,
            protocol,
            with_inputs,
            parallel,
            output_dir,
            rpc_url,
            rpc_username,
            rpc_password,
        } => {
            info!("Batch fetching transactions (parallel: {})", parallel);

            // Load RPC configuration
            let app_config = AppConfig::load().unwrap_or_else(|_| {
                AppConfig::get_defaults().expect("Failed to create default config")
            });
            let mut rpc_config = app_config.bitcoin_rpc;

            if let Some(url) = rpc_url {
                rpc_config.url = url.clone();
            }
            if let Some(username) = rpc_username {
                rpc_config.username = username.clone();
            }
            if let Some(password) = rpc_password {
                rpc_config.password = password.clone();
            }

            // Read TXIDs from file or stdin
            let txids: Vec<String> = if let Some(file_path) = file {
                let file = fs::File::open(file_path)
                    .map_err(|e| AppError::Config(format!("Failed to open file: {}", e)))?;
                let reader = BufReader::new(file);
                reader
                    .lines()
                    .map_while(Result::ok)
                    .filter(|line| !line.trim().is_empty())
                    .collect()
            } else {
                // Read from stdin
                let stdin = std::io::stdin();
                let reader = BufReader::new(stdin);
                reader
                    .lines()
                    .map_while(Result::ok)
                    .filter(|line| !line.trim().is_empty())
                    .collect()
            };

            if txids.is_empty() {
                return Err(AppError::Config("No TXIDs provided".to_string()));
            }

            println!("Fetching {} transactions...", txids.len());

            // Create RPC client
            let rpc_client = Arc::new(BitcoinRpcClient::new(rpc_config).await?);

            let protocol_dir = protocol.as_deref().unwrap_or("unknown");
            let protocol_path = output_dir.join(protocol_dir);
            fs::create_dir_all(&protocol_path)?;

            // Use Arc for shared state across tasks
            let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let failed_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            // Create semaphore for concurrency control
            let semaphore = Arc::new(tokio::sync::Semaphore::new(*parallel));

            // Spawn concurrent fetch tasks
            let mut tasks = Vec::new();

            for txid in txids {
                let rpc_client = Arc::clone(&rpc_client);
                let protocol_path = protocol_path.clone();
                let success_count = Arc::clone(&success_count);
                let failed_count = Arc::clone(&failed_count);
                let semaphore = Arc::clone(&semaphore);
                let with_inputs = *with_inputs;

                let task = tokio::spawn(async move {
                    // Acquire semaphore permit
                    let _permit = semaphore.acquire().await.unwrap();

                    let output_file = protocol_path.join(format!("{}.json", txid));

                    if output_file.exists() {
                        println!("  ⊙ {} (already exists)", txid);
                        success_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Ok::<(), AppError>(());
                    }

                    match rpc_client.get_transaction(&txid).await {
                        Ok(transaction) => {
                            let serialized = consensus::serialize(&transaction);
                            let tx_hex = hex::encode(&serialized);

                            let tx_json = serde_json::json!({
                                "txid": txid,
                                "hex": tx_hex,
                                "vin": transaction.input.iter().map(|i| serde_json::json!({
                                    "txid": i.previous_output.txid.to_string(),
                                    "vout": i.previous_output.vout,
                                })).collect::<Vec<_>>(),
                                "vout": transaction.output.iter().enumerate().map(|(n, o)| serde_json::json!({
                                    "value": o.value.to_btc(),
                                    "n": n,
                                    "scriptPubKey": {
                                        "hex": hex::encode(o.script_pubkey.as_bytes()),
                                        "type": if o.script_pubkey.is_multisig() { "multisig" } else { "other" }
                                    }
                                })).collect::<Vec<_>>(),
                            });

                            fs::write(&output_file, serde_json::to_string_pretty(&tx_json)?)?;

                            // Fetch inputs if requested
                            if with_inputs {
                                let inputs_dir = protocol_path.join("inputs");
                                fs::create_dir_all(&inputs_dir)?;

                                for input in &transaction.input {
                                    let input_txid = input.previous_output.txid.to_string();
                                    let input_file =
                                        inputs_dir.join(format!("{}.json", input_txid));

                                    if input_file.exists() {
                                        continue;
                                    }

                                    match rpc_client.get_transaction(&input_txid).await {
                                        Ok(input_tx) => {
                                            let serialized = consensus::serialize(&input_tx);
                                            let tx_hex = hex::encode(&serialized);

                                            let input_json = serde_json::json!({
                                                "txid": input_txid,
                                                "hex": tx_hex,
                                                "vout": input_tx.output.iter().enumerate().map(|(n, o)| serde_json::json!({
                                                    "value": o.value.to_btc(),
                                                    "n": n,
                                                })).collect::<Vec<_>>(),
                                            });

                                            // Propagate I/O errors from input write
                                            fs::write(
                                                &input_file,
                                                serde_json::to_string_pretty(&input_json)?,
                                            )?;
                                        }
                                        Err(e) => {
                                            warn!(
                                                "  ⚠️  Failed to fetch input {}: {}",
                                                input_txid, e
                                            );
                                            // Continue with other inputs even if one fails
                                        }
                                    }
                                }
                            }

                            // Only increment success after ALL steps complete successfully
                            success_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            println!("  ✓ {}", txid);

                            Ok(())
                        }
                        Err(e) => {
                            failed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            warn!("  ✗ {}: {}", txid, e);
                            Ok(())
                        }
                    }
                });

                tasks.push(task);
            }

            // Wait for all tasks to complete and handle errors
            for task in tasks {
                match task.await {
                    Ok(Ok(())) => {
                        // Task completed successfully
                    }
                    Ok(Err(e)) => {
                        // Task returned an error
                        failed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        error!("Task failed: {}", e);
                    }
                    Err(e) => {
                        // Task panicked or was cancelled
                        failed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        error!("Task join error: {}", e);
                    }
                }
            }

            let success = success_count.load(std::sync::atomic::Ordering::Relaxed);
            let failed = failed_count.load(std::sync::atomic::Ordering::Relaxed);

            println!("\nBatch complete: {} success, {} failed", success, failed);

            Ok(())
        }

        FetchCommands::ScanInputs {
            pattern,
            output_dir,
            rpc_url,
            rpc_username,
            rpc_password,
        } => {
            info!("Scanning fixtures for input transactions");

            // Load RPC configuration
            let app_config = AppConfig::load().unwrap_or_else(|_| {
                AppConfig::get_defaults().expect("Failed to create default config")
            });
            let mut rpc_config = app_config.bitcoin_rpc;

            if let Some(url) = rpc_url {
                rpc_config.url = url.clone();
            }
            if let Some(username) = rpc_username {
                rpc_config.username = username.clone();
            }
            if let Some(password) = rpc_password {
                rpc_config.password = password.clone();
            }

            // Find matching files
            let paths = glob::glob(pattern)
                .map_err(|e| AppError::Config(format!("Invalid glob pattern: {}", e)))?;

            let mut all_input_txids = HashSet::new();
            let mut files_scanned = 0;

            // Scan files for input TXIDs
            for path_result in paths {
                let path =
                    path_result.map_err(|e| AppError::Config(format!("Glob error: {}", e)))?;

                if !path.is_file() {
                    continue;
                }

                files_scanned += 1;

                let content = fs::read_to_string(&path)?;
                let json: Value = serde_json::from_str(&content).map_err(|e| {
                    AppError::Config(format!("Invalid JSON in {}: {}", path.display(), e))
                })?;

                // Extract input TXIDs
                if let Some(vin) = json.get("vin").and_then(|v| v.as_array()) {
                    for input in vin {
                        if let Some(txid) = input.get("txid").and_then(|t| t.as_str()) {
                            all_input_txids.insert(txid.to_string());
                        }
                    }
                }
            }

            println!(
                "Scanned {} files, found {} unique input transactions",
                files_scanned,
                all_input_txids.len()
            );

            if all_input_txids.is_empty() {
                println!("No input transactions to fetch");
                return Ok(());
            }

            // Determine output directory (use pattern's directory + /inputs)
            let output_path = if let Some(dir) = output_dir {
                dir.clone()
            } else {
                // Extract directory from pattern
                let pattern_path = PathBuf::from(&pattern);
                let parent = pattern_path.parent().unwrap_or(Path::new("."));
                parent.join("inputs")
            };

            fs::create_dir_all(&output_path)?;

            // Create RPC client
            let rpc_client = BitcoinRpcClient::new(rpc_config).await?;

            let mut fetched = 0;
            let mut skipped = 0;
            let mut failed = 0;

            // Fetch each input transaction
            for input_txid in all_input_txids {
                let output_file = output_path.join(format!("{}.json", input_txid));

                if output_file.exists() {
                    skipped += 1;
                    continue;
                }

                match rpc_client.get_transaction(&input_txid).await {
                    Ok(transaction) => {
                        let serialized = consensus::serialize(&transaction);
                        let tx_hex = hex::encode(&serialized);

                        let tx_json = serde_json::json!({
                            "txid": input_txid,
                            "hex": tx_hex,
                            "vout": transaction.output.iter().enumerate().map(|(n, o)| serde_json::json!({
                                "value": o.value.to_btc(),
                                "n": n,
                                "scriptPubKey": {
                                    "hex": hex::encode(o.script_pubkey.as_bytes()),
                                }
                            })).collect::<Vec<_>>(),
                        });

                        fs::write(&output_file, serde_json::to_string_pretty(&tx_json)?)?;
                        fetched += 1;
                        println!("  ✓ {}", input_txid);
                    }
                    Err(e) => {
                        failed += 1;
                        warn!("  ✗ {}: {}", input_txid, e);
                    }
                }
            }

            println!("\nScan complete:");
            println!("  - Fetched: {}", fetched);
            println!("  - Already existed: {}", skipped);
            println!("  - Failed: {}", failed);
            println!("  - Output directory: {}", output_path.display());

            Ok(())
        }
    }
}

async fn run_arc4(
    txid: String,
    show_raw: bool,
    format: String,
    rpc_url: Option<String>,
    rpc_username: Option<String>,
    rpc_password: Option<String>,
) -> AppResult<()> {
    info!("Starting ARC4 deobfuscation analysis for TXID: {}", txid);

    // Load configuration, allowing CLI overrides
    let config = AppConfig::load()
        .map_err(|e| AppError::Config(format!("Failed to load configuration: {}", e)))?;

    // Build RPC configuration with CLI overrides
    let mut rpc_config = config.bitcoin_rpc;
    if let Some(url) = rpc_url {
        rpc_config.url = url;
    }
    if let Some(username) = rpc_username {
        rpc_config.username = username;
    }
    if let Some(password) = rpc_password {
        rpc_config.password = password;
    }

    // Initialise RPC client
    let rpc_client = crate::rpc::BitcoinRpcClient::new(rpc_config)
        .await
        .map_err(|e| AppError::Config(format!("Failed to initialise RPC client: {}", e)))?;

    // Perform ARC4 deobfuscation
    let result = crate::decoder::arc4_tool::deobfuscate_transaction(&txid, &rpc_client)
        .await
        .map_err(|e| AppError::Config(format!("ARC4 deobfuscation failed: {}", e)))?;

    // Format and print output
    match format.as_str() {
        "json" => print_arc4_json(&result),
        "hex" => print_arc4_hex(&result),
        _ => print_arc4_text(&result, show_raw),
    }

    Ok(())
}

/// Print ARC4 result in text format
fn print_arc4_text(result: &crate::decoder::arc4_tool::Arc4Result, show_raw: bool) {
    println!("\n=== ARC4 Deobfuscation ===");
    println!("TXID: {}", result.txid);
    println!();
    println!("ARC4 Key (first input):");
    println!("  {}", result.input_txid);
    println!();
    println!("P2MS Outputs: {}", result.p2ms_output_count);
    println!();

    // Counterparty result
    if let Some(ref cp) = result.counterparty {
        println!("Counterparty:");
        println!("  ✓ Success");
        println!(
            "  Raw: {} bytes → Decrypted: {} bytes",
            cp.raw_data.len(),
            cp.decrypted.len()
        );
        println!();

        if show_raw {
            println!("  Raw data (hex):");
            print_hex_dump(&cp.raw_data, 2);
            println!();
        }

        println!("  Hex (first 64 bytes):");
        let preview_len = cp.decrypted.len().min(64);
        println!("  {}", hex::encode(&cp.decrypted[..preview_len]));
        println!();

        println!("  ASCII:");
        println!("  {}", to_ascii_preview(&cp.decrypted, 80));
        println!();
    } else {
        println!("Counterparty:");
        println!("  ✗ Not detected");
        println!();
    }

    // Bitcoin Stamps result
    if let Some(ref stamps) = result.stamps {
        println!("Bitcoin Stamps:");
        println!(
            "  ✓ Success ({:?})",
            match stamps.transport {
                crate::types::stamps::StampsTransport::Pure => "Pure",
                crate::types::stamps::StampsTransport::Counterparty => "Counterparty",
            }
        );
        println!(
            "  Raw: {} bytes → Decrypted: {} bytes",
            stamps.raw_data.len(),
            stamps.decrypted.len()
        );
        println!("  Signature at offset: {}", stamps.signature_offset);
        println!();

        if show_raw {
            println!("  Raw data (hex):");
            print_hex_dump(&stamps.raw_data, 2);
            println!();
        }

        println!("  ASCII:");
        println!("  {}", to_ascii_preview(&stamps.decrypted, 80));
        println!();
    } else {
        println!("Bitcoin Stamps:");
        println!("  ✗ Not detected");
        println!();
    }

    // Raw fallback result
    if let Some(ref raw) = result.raw_fallback {
        println!("Raw ARC4 Fallback:");
        println!("  ✓ Decrypted (unknown protocol)");
        println!(
            "  Raw: {} bytes → Decrypted: {} bytes",
            raw.raw_data.len(),
            raw.decrypted.len()
        );
        println!();

        if show_raw {
            println!("  Raw data (hex):");
            print_hex_dump(&raw.raw_data, 2);
            println!();
        }

        println!("  Hex (first 64 bytes):");
        let preview_len = raw.decrypted.len().min(64);
        println!("  {}", hex::encode(&raw.decrypted[..preview_len]));
        println!();

        println!("  ASCII:");
        println!("  {}", to_ascii_preview(&raw.decrypted, 80));
        println!();

        println!("  ⚠️  No known protocol signature detected.");
        println!("  💡 This may be a new or unknown protocol using ARC4 encryption.");
        println!("  💡 Look for patterns in the ASCII/hex output above.");
        println!();
    }
}

/// Print ARC4 result in JSON format
fn print_arc4_json(result: &crate::decoder::arc4_tool::Arc4Result) {
    let json = serde_json::json!({
        "txid": result.txid,
        "input_txid": result.input_txid,
        "p2ms_output_count": result.p2ms_output_count,
        "counterparty": result.counterparty.as_ref().map(|cp| {
            serde_json::json!({
                "raw_bytes": cp.raw_data.len(),
                "raw_data": hex::encode(&cp.raw_data),
                "decrypted_bytes": cp.decrypted.len(),
                "decrypted": hex::encode(&cp.decrypted),
            })
        }),
        "stamps": result.stamps.as_ref().map(|stamps| {
            serde_json::json!({
                "raw_bytes": stamps.raw_data.len(),
                "raw_data": hex::encode(&stamps.raw_data),
                "decrypted_bytes": stamps.decrypted.len(),
                "decrypted": hex::encode(&stamps.decrypted),
                "signature_offset": stamps.signature_offset,
                "transport": match stamps.transport {
                    crate::types::stamps::StampsTransport::Pure => "pure",
                    crate::types::stamps::StampsTransport::Counterparty => "counterparty",
                },
            })
        }),
        "raw_fallback": result.raw_fallback.as_ref().map(|raw| {
            serde_json::json!({
                "raw_bytes": raw.raw_data.len(),
                "raw_data": hex::encode(&raw.raw_data),
                "decrypted_bytes": raw.decrypted.len(),
                "decrypted": hex::encode(&raw.decrypted),
            })
        }),
    });

    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

/// Print ARC4 result in hex format (decrypted data only)
fn print_arc4_hex(result: &crate::decoder::arc4_tool::Arc4Result) {
    if let Some(ref cp) = result.counterparty {
        println!("{}", hex::encode(&cp.decrypted));
    } else if let Some(ref stamps) = result.stamps {
        println!("{}", hex::encode(&stamps.decrypted));
    } else if let Some(ref raw) = result.raw_fallback {
        println!("{}", hex::encode(&raw.decrypted));
    }
}

/// Convert bytes to ASCII preview with non-printable characters as dots
fn to_ascii_preview(data: &[u8], max_len: usize) -> String {
    let preview_len = data.len().min(max_len);
    let preview: String = data[..preview_len]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    if data.len() > max_len {
        format!("{}...", preview)
    } else {
        preview
    }
}

/// Print hex dump with indentation
fn print_hex_dump(data: &[u8], indent: usize) {
    let indent_str = " ".repeat(indent);
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        println!(
            "{}{:04x}: {:47}  {}",
            indent_str,
            offset,
            hex.join(" "),
            ascii
        );
    }
}
