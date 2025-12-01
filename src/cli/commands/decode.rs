use crate::config::{output_paths, AppConfig, BitcoinRpcConfig};
use crate::decoder::{BitcoinStampsData, DecodedData, ProtocolDecoder};
use crate::errors::{AppError, AppResult};
use clap::Args;
use std::path::PathBuf;
use tracing::{error, info};

/// Decode protocol data from transaction (Bitcoin Stamps, Counterparty, Omni, PPk, DataStorage, etc.)
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
        if self.no_output {
            info!(
                "Starting transaction decoding for TXID: {} (no-output mode)",
                self.txid
            );
        } else {
            info!("Starting transaction decoding for TXID: {}", self.txid);
            info!("Output directory: {}", self.output_dir.display());
        }

        // Load configuration, allowing CLI overrides
        let config = AppConfig::load()
            .map_err(|e| AppError::Config(format!("Failed to load configuration: {}", e)))?;

        // Build RPC configuration with CLI overrides
        let rpc_config = BitcoinRpcConfig {
            url: self.rpc_url.clone().unwrap_or(config.bitcoin_rpc.url),
            username: self
                .rpc_username
                .clone()
                .unwrap_or(config.bitcoin_rpc.username),
            password: self
                .rpc_password
                .clone()
                .unwrap_or(config.bitcoin_rpc.password),
            max_retries: config.bitcoin_rpc.max_retries,
            timeout_seconds: config.bitcoin_rpc.timeout_seconds,
            initial_backoff_ms: config.bitcoin_rpc.initial_backoff_ms,
            backoff_multiplier: config.bitcoin_rpc.backoff_multiplier,
            max_backoff_seconds: config.bitcoin_rpc.max_backoff_seconds,
            concurrent_requests: config.bitcoin_rpc.concurrent_requests,
        };

        // Initialise the decoder - use temp directory if no-output mode
        let actual_output_dir = if self.no_output {
            std::env::temp_dir().join("stamps_decoder_temp")
        } else {
            self.output_dir.clone()
        };

        let decoder = ProtocolDecoder::new(rpc_config, actual_output_dir)
            .await
            .map_err(|e| AppError::Config(format!("Failed to initialise decoder: {}", e)))?;

        info!("Decoder initialised successfully, attempting to decode transaction...");

        // Attempt to decode the transaction using verbose version if requested
        let decode_result = if self.verbose {
            decoder.decode_txid_verbose(&self.txid, true).await
        } else {
            decoder.decode_txid(&self.txid).await
        };

        match decode_result {
            Ok(Some(decoded_data)) => {
                if self.no_output {
                    print_compact_result(&self.txid, &decoded_data);
                } else {
                    print_verbose_result(&self.txid, &decoded_data);
                }
            }
            Ok(None) => {
                if self.no_output {
                    println!("TXID:{} TYPE:NONE", self.txid);
                } else {
                    info!("Transaction analysis complete:");
                    info!("   Transaction {} was processed", self.txid);
                    info!("   Result: No recognised protocol detected");
                    info!("   Checked: Bitcoin Stamps, Counterparty, Omni, DataStorage");
                }
            }
            Err(e) => {
                // Check if this is a "transaction not found" error
                let error_str = e.to_string();
                if error_str.contains("does not exist in the blockchain") {
                    if self.no_output {
                        println!("TXID:{} TYPE:ERROR ERROR:NOT_FOUND", self.txid);
                    } else {
                        info!("Transaction analysis complete:");
                        info!("   Transaction {} does not exist", self.txid);
                        info!("   This transaction was not found in the blockchain or mempool");
                        info!("   Please verify the transaction ID is correct");
                    }
                } else if self.no_output {
                    println!(
                        "TXID:{} TYPE:ERROR ERROR:{}",
                        self.txid,
                        error_str.replace(' ', "_")
                    );
                } else {
                    error!("Failed to decode transaction {}: {}", self.txid, e);
                    return Err(AppError::Config(format!("Decoding failed: {}", e)));
                }
            }
        }

        Ok(())
    }
}

/// Print compact result for no-output mode
fn print_compact_result(txid: &str, decoded_data: &DecodedData) {
    match decoded_data {
        DecodedData::BitcoinStamps { data } => match data {
            BitcoinStampsData::Image(decoded_image) => {
                println!(
                    "TXID:{} TYPE:IMAGE FORMAT:{:?} SIZE:{}",
                    txid, decoded_image.format, decoded_image.size_bytes
                );
            }
            BitcoinStampsData::Json(decoded_json) => {
                println!(
                    "TXID:{} TYPE:JSON PROTOCOL:{:?} SIZE:{}",
                    txid, decoded_json.json_type, decoded_json.size_bytes
                );
            }
            BitcoinStampsData::Html(decoded_html) => {
                println!("TXID:{} TYPE:HTML SIZE:{}", txid, decoded_html.size_bytes);
            }
            BitcoinStampsData::Compressed(decoded_compressed) => {
                println!(
                    "TXID:{} TYPE:COMPRESSED ALGORITHM:{} SIZE:{}",
                    txid, decoded_compressed.compression_type, decoded_compressed.size_bytes
                );
            }
            BitcoinStampsData::Data(decoded_data) => {
                println!("TXID:{} TYPE:DATA SIZE:{}", txid, decoded_data.size_bytes);
            }
            BitcoinStampsData::Document(decoded_doc) => {
                println!(
                    "TXID:{} TYPE:DOCUMENT FORMAT:{:?} SIZE:{}",
                    txid, decoded_doc.format, decoded_doc.size_bytes
                );
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
}

/// Print verbose result with file paths
fn print_verbose_result(txid: &str, decoded_data: &DecodedData) {
    match decoded_data {
        DecodedData::BitcoinStamps { data } => match data {
            BitcoinStampsData::Image(decoded_image) => {
                info!("Successfully decoded Bitcoin Stamps image!");
                info!("{}", decoded_image.summary());
            }
            BitcoinStampsData::Json(decoded_json) => {
                info!("Successfully decoded Bitcoin Stamps JSON data!");
                info!("{}", decoded_json.summary());
            }
            BitcoinStampsData::Html(decoded_html) => {
                info!("Successfully decoded Bitcoin Stamps HTML!");
                info!("{}", decoded_html.summary());
            }
            BitcoinStampsData::Compressed(decoded_compressed) => {
                info!("Successfully decoded Bitcoin Stamps compressed data!");
                info!("{}", decoded_compressed.summary());
            }
            BitcoinStampsData::Data(decoded_data) => {
                info!("Successfully decoded Bitcoin Stamps raw data!");
                info!("{}", decoded_data.summary());
            }
            BitcoinStampsData::Document(decoded_doc) => {
                info!("Successfully decoded Bitcoin Stamps document!");
                info!("{}", decoded_doc.summary());
            }
        },
        DecodedData::Counterparty { data } => {
            info!("Successfully decoded Counterparty data!");
            info!("Message Type: {:?}", data.message_type);
            info!("Size: {} bytes", data.raw_data.len());
            info!("File: {}", data.file_path.display());
        }
        DecodedData::Omni { data } => {
            info!("Successfully decoded Omni Layer data!");
            info!(
                "Message Type: {:?} (Type {})",
                data.message_type, data.message_type as u32
            );
            info!("Sender: {}", data.sender_address);
            info!("Packets: {}", data.packet_count);
            info!("Size: {} bytes", data.deobfuscated_payload.len());
            info!("File: {}", data.file_path.display());
        }
        DecodedData::Chancecoin { data } => {
            info!("Successfully decoded Chancecoin data!");
            info!("Message Type: {:?}", data.message_type);
            info!("Size: {} bytes", data.data.len());
            info!("File: {}", data.file_path.display());
        }
        DecodedData::PPk { data } => {
            info!("Successfully decoded PPk protocol data!");
            info!("Variant: {:?}", data.variant);
            info!("Content Type: {}", data.content_type);
            if let Some(ref odin) = data.odin_identifier {
                info!("ODIN: {}", odin.full_identifier);
                info!(
                    "   Block: {} (time: {})",
                    odin.block_height, odin.block_time
                );
                info!("   TX index: {}", odin.tx_index);
                info!("   DSS: {}", odin.dss);
            }
            if let Some(ref rt_json) = data.rt_json {
                info!(
                    "RT JSON fields: {}",
                    rt_json.as_object().map(|o| o.len()).unwrap_or(0)
                );
            }
            info!("File: {}", data.file_path.display());
        }
        DecodedData::DataStorage(data) => {
            info!("Successfully decoded DataStorage data!");
            info!("Pattern: {}", data.pattern);
            info!("Size: {} bytes", data.decoded_data.len());
            if let Some(metadata) = data.metadata.as_object() {
                if let Some(total_pubkeys) = metadata.get("total_pubkeys") {
                    info!("Total pubkeys: {}", total_pubkeys);
                }
            }
            // Note: DataStorage saves to multiple files in pattern-specific subdirectories
        }
        DecodedData::LikelyDataStorage(data) => {
            info!("Successfully classified as Likely Data Storage!");
            info!("Pattern Type: {}", data.pattern_type);
            info!("Details: {}", data.details);
            info!("Metadata file: {}", data.file_path.display());
        }
    }

    let _ = txid; // Suppress unused warning
}
