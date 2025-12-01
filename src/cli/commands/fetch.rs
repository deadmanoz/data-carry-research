use crate::config::{output_paths, AppConfig};
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

/// Fetch transaction data from Bitcoin Core RPC
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

            println!("Fetched transaction: {}", txid);
            println!("  - VIN entries: {}", vin_count);
            println!("  - VOUT entries: {}", vout_count);
            println!("  - Saved to: {}", output_file.display());

            if vin_count == 0 {
                warn!("Transaction has no inputs (coinbase or unusual tx)");
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
                            println!("  {} fetched", input_txid);
                        }
                        Err(e) => {
                            warn!("  Failed to fetch {}: {}", input_txid, e);
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
                        println!("  {} (already exists)", txid);
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
                                            warn!("  Failed to fetch input {}: {}", input_txid, e);
                                            // Continue with other inputs even if one fails
                                        }
                                    }
                                }
                            }

                            // Only increment success after ALL steps complete successfully
                            success_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            println!("  {} fetched", txid);

                            Ok(())
                        }
                        Err(e) => {
                            failed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            warn!("  {}: {}", txid, e);
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
                        println!("  {} fetched", input_txid);
                    }
                    Err(e) => {
                        failed += 1;
                        warn!("  {}: {}", input_txid, e);
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
