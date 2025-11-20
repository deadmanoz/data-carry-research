//! Generic Bitcoin transaction decoder for P2MS-based protocols
//!
//! This module provides a unified interface for decoding Bitcoin transaction data
//! from P2MS-based protocols including Bitcoin Stamps and Counterparty. The design
//! supports protocol detection with priority logic and extensible handler architecture.
//!
//! Key Features:
//! - RPC-based transaction detection (no database dependency)
//! - Unified protocol detection (Bitcoin Stamps, Counterparty)
//! - Protocol-specific validation and decoding
//! - Priority logic with transport metadata
//! - Clean separation of concerns for extensibility

#![allow(dead_code)]

use crate::config::BitcoinRpcConfig;
use crate::rpc::BitcoinRpcClient;
use std::path::PathBuf;
use tracing::{debug, info, warn};

use self::chancecoin::try_chancecoin;
use self::image_formats::{is_base64_data, ImageFormat};
use self::output::{JsonType, OutputManager};
use self::ppk::try_ppk;
use self::protocol_detection::{
    fetch_transaction, try_bitcoin_stamps, try_counterparty, try_likely_data_storage,
    try_likely_legitimate_p2ms, try_omni, DecodedProtocol,
};
use crate::types::stamps::validation::{
    detect_content_type_from_payload, find_stamp_signature,
};
use crate::types::stamps::{classify_json_data, StampsVariant};
use base64::Engine;

// Use the shared lenient base64 decoder from types::stamps::validation
// This ensures consistent decoding behaviour across Stage 3 classification and Stage 4 decoding
use crate::types::stamps::validation::BASE64_LENIENT;

pub mod arc4_tool;
pub mod chancecoin;
pub mod datastorage;
pub mod debug_display;
pub mod image_formats;
pub mod omni_parser;
pub mod output;
pub mod ppk;
pub mod protocol_detection;
pub mod protocol_detection_verbose;

/// Result type for decoder operations
pub type DecoderResult<T> = Result<T, DecoderError>;

/// Decoder-specific error types
#[derive(Debug, thiserror::Error)]
pub enum DecoderError {
    #[error("RPC error: {0}")]
    Rpc(#[from] crate::errors::RpcError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid transaction format for {0}")]
    InvalidTransaction(String),

    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid image format in transaction {0}")]
    InvalidImageFormat(String),

    #[error("Output error: {0}")]
    Output(#[from] crate::decoder::output::OutputError),
}

/// Unified result type for decoded protocol data
#[derive(Debug, Clone)]
pub enum DecodedData {
    BitcoinStamps { data: BitcoinStampsData },
    Counterparty { data: CounterpartyData },
    Omni { data: OmniData },
    Chancecoin { data: ChancecoinData },
    PPk { data: PPkData },
    DataStorage(DataStorageData),
}

/// Bitcoin Stamps protocol data types
#[derive(Debug, Clone)]
pub enum BitcoinStampsData {
    Image(DecodedImage),
    Json(DecodedJson),
    Html(DecodedHtml),
    Compressed(DecodedCompressed),
    Data(DecodedGenericData),
}

/// Counterparty protocol data
#[derive(Debug, Clone)]
pub struct CounterpartyData {
    pub txid: String,
    pub file_path: PathBuf,
    pub message_type: crate::types::counterparty::CounterpartyMessageType,
    pub raw_data: Vec<u8>,
}

/// Omni Layer protocol data
#[derive(Debug, Clone)]
pub struct OmniData {
    pub txid: String,
    pub file_path: PathBuf,
    pub message_type: crate::types::omni::OmniMessageType,
    pub sender_address: String,
    pub deobfuscated_payload: Vec<u8>,
    pub packet_count: u8,
}

/// Chancecoin protocol data
#[derive(Debug, Clone)]
pub struct ChancecoinData {
    pub txid: String,
    pub file_path: PathBuf,
    pub message_type: crate::types::chancecoin::ChancecoinMessageType,
    pub data: Vec<u8>,
}

/// PPk protocol data
#[derive(Debug, Clone)]
pub struct PPkData {
    pub txid: String,
    pub file_path: PathBuf,
    pub variant: crate::types::ProtocolVariant,
    pub rt_json: Option<serde_json::Value>,
    pub odin_identifier: Option<crate::types::ppk::OdinIdentifier>,
    pub content_type: String,
}

/// DataStorage protocol data
#[derive(Debug, Clone)]
pub struct DataStorageData {
    pub txid: String,
    pub pattern: String,
    pub decoded_data: Vec<u8>,
    pub metadata: serde_json::Value,
}

impl DecodedData {
    /// Get a human-readable summary of the decoded data
    pub fn summary(&self) -> String {
        match self {
            DecodedData::BitcoinStamps { data } => match data {
                BitcoinStampsData::Image(img) => img.summary(),
                BitcoinStampsData::Json(json) => json.summary(),
                BitcoinStampsData::Html(html) => html.summary(),
                BitcoinStampsData::Compressed(comp) => comp.summary(),
                BitcoinStampsData::Data(data) => data.summary(),
            },
            DecodedData::Counterparty { data } => {
                format!(
                    "Counterparty {:?} ({} bytes)",
                    data.message_type,
                    data.raw_data.len()
                )
            }
            DecodedData::Omni { data } => {
                format!(
                    "Omni Layer {:?} (Type {}, {} bytes, {} packets)",
                    data.message_type,
                    data.message_type as u32,
                    data.deobfuscated_payload.len(),
                    data.packet_count
                )
            }
            DecodedData::Chancecoin { data } => {
                format!(
                    "Chancecoin {} ({} bytes)",
                    data.message_type.description(),
                    data.data.len()
                )
            }
            DecodedData::PPk { data } => {
                let odin_suffix = if let Some(ref odin) = data.odin_identifier {
                    format!(" - ODIN: {}", odin.full_identifier)
                } else {
                    String::new()
                };
                format!(
                    "PPk {:?} ({}){}",
                    data.variant,
                    data.content_type,
                    odin_suffix
                )
            }
            DecodedData::DataStorage(data) => {
                format!(
                    "DataStorage {} ({} bytes)",
                    data.pattern,
                    data.decoded_data.len()
                )
            }
        }
    }

    /// Get the transaction ID
    pub fn txid(&self) -> &str {
        match self {
            DecodedData::BitcoinStamps { data, .. } => match data {
                BitcoinStampsData::Image(img) => &img.txid,
                BitcoinStampsData::Json(json) => &json.txid,
                BitcoinStampsData::Html(html) => &html.txid,
                BitcoinStampsData::Compressed(comp) => &comp.txid,
                BitcoinStampsData::Data(data) => &data.txid,
            },
            DecodedData::Counterparty { data } => &data.txid,
            DecodedData::Omni { data } => &data.txid,
            DecodedData::Chancecoin { data } => &data.txid,
            DecodedData::PPk { data } => &data.txid,
            DecodedData::DataStorage(data) => &data.txid,
        }
    }

    /// Get the file path (returns None for DataStorage since it *could* save multiple files)
    pub fn file_path(&self) -> Option<&PathBuf> {
        match self {
            DecodedData::BitcoinStamps { data, .. } => match data {
                BitcoinStampsData::Image(img) => Some(&img.file_path),
                BitcoinStampsData::Json(json) => Some(&json.file_path),
                BitcoinStampsData::Html(html) => Some(&html.file_path),
                BitcoinStampsData::Compressed(comp) => Some(&comp.file_path),
                BitcoinStampsData::Data(data) => Some(&data.file_path),
            },
            DecodedData::Counterparty { data } => Some(&data.file_path),
            DecodedData::Omni { data } => Some(&data.file_path),
            DecodedData::Chancecoin { data } => Some(&data.file_path),
            DecodedData::PPk { data } => Some(&data.file_path),
            DecodedData::DataStorage(_) => None, // DataStorage saves to multiple files
        }
    }

    /// Get the size in bytes
    pub fn size_bytes(&self) -> usize {
        match self {
            DecodedData::BitcoinStamps { data, .. } => match data {
                BitcoinStampsData::Image(img) => img.size_bytes,
                BitcoinStampsData::Json(json) => json.size_bytes,
                BitcoinStampsData::Html(html) => html.size_bytes,
                BitcoinStampsData::Compressed(comp) => comp.size_bytes,
                BitcoinStampsData::Data(data) => data.size_bytes,
            },
            DecodedData::Omni { data } => data.deobfuscated_payload.len(),
            DecodedData::Counterparty { data } => data.raw_data.len(),
            DecodedData::Chancecoin { data } => data.data.len(),
            DecodedData::PPk { data } => {
                data.rt_json.as_ref().map(|j| j.to_string().len()).unwrap_or(0)
                    + data.odin_identifier.as_ref().map(|o| o.full_identifier.len()).unwrap_or(0)
            }
            DecodedData::DataStorage(data) => data.decoded_data.len(),
        }
    }

    /// Check if this is a PPk protocol decode
    pub fn is_ppk(&self) -> bool {
        matches!(self, DecodedData::PPk { .. })
    }

    /// Get PPk data if this is a PPk decode
    pub fn ppk_data(&self) -> Option<&PPkData> {
        match self {
            DecodedData::PPk { data } => Some(data),
            _ => None,
        }
    }
}

/// Information about a successfully decoded image
#[derive(Debug, Clone)]
pub struct DecodedImage {
    pub txid: String,
    pub format: ImageFormat,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>, // Actual decoded image bytes
}

/// Information about successfully decoded JSON data
#[derive(Debug, Clone)]
pub struct DecodedJson {
    pub txid: String,
    pub json_type: JsonType,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub parsed_data: serde_json::Value,
    pub bytes: Vec<u8>, // Actual raw JSON bytes
}

#[derive(Debug, Clone)]
pub struct DecodedHtml {
    pub txid: String,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecodedCompressed {
    pub txid: String,
    pub compression_type: String,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecodedGenericData {
    pub txid: String,
    pub content_type: String,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>,
}

impl DecodedImage {
    /// Get a human-readable summary of the decoded image
    pub fn summary(&self) -> String {
        format!(
            "Transaction {}: {} image ({} bytes) -> {}",
            &self.txid[..16], // Show first 16 chars of txid
            self.format.extension().to_uppercase(),
            self.size_bytes,
            self.file_path.display()
        )
    }
}

impl DecodedJson {
    /// Get a human-readable summary of the decoded JSON data
    pub fn summary(&self) -> String {
        format!(
            "Transaction {}: {} ({} bytes) -> {}",
            &self.txid[..16], // Show first 16 chars of txid
            self.json_type.description(),
            self.size_bytes,
            self.file_path.display()
        )
    }
}

impl DecodedHtml {
    pub fn summary(&self) -> String {
        format!(
            "Transaction {}: HTML ({} bytes) -> {}",
            &self.txid[..16],
            self.size_bytes,
            self.file_path.display()
        )
    }
}

impl DecodedCompressed {
    pub fn summary(&self) -> String {
        format!(
            "Transaction {}: {} compressed payload ({} bytes) -> {}",
            &self.txid[..16],
            self.compression_type,
            self.size_bytes,
            self.file_path.display()
        )
    }
}

impl DecodedGenericData {
    pub fn summary(&self) -> String {
        format!(
            "Transaction {}: {} data ({} bytes) -> {}",
            &self.txid[..16],
            self.content_type,
            self.size_bytes,
            self.file_path.display()
        )
    }
}

/// Generic decoder for Bitcoin transaction data with protocol detection
pub struct ProtocolDecoder {
    rpc_client: BitcoinRpcClient,
    output_manager: OutputManager,
}

impl ProtocolDecoder {
    /// Create a new decoder with RPC client and output management
    pub async fn new(rpc_config: BitcoinRpcConfig, output_dir: PathBuf) -> DecoderResult<Self> {
        info!("Initialising multi-protocol decoder (Stamps, Counterparty, Omni, DataStorage)");

        let rpc_client = BitcoinRpcClient::new(rpc_config).await?;
        let output_manager = OutputManager::new(output_dir)
            .map_err(|e| DecoderError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        info!("Multi-protocol decoder initialised successfully");

        Ok(Self {
            rpc_client,
            output_manager,
        })
    }

    /// Decode data from a specific transaction ID
    ///
    /// This is the main entry point for the decoder. It uses a simple linear flow:
    /// 1. Fetch transaction data via RPC
    /// 2. Try protocols in priority order (matches Stage 3):
    ///    - Omni (exclusive Exodus address)
    ///    - Chancecoin (signature-based)
    ///    - Bitcoin Stamps (BEFORE Counterparty - can be embedded)
    ///    - Counterparty (after Stamps)
    ///    - DataStorage (generic patterns)
    ///    - LikelyDataStorage (suspicious patterns - marker addresses, repeated pubkeys)
    ///    - LikelyLegitimateMultisig (pubkey validation)
    /// 3. Return None if no protocol detected
    ///
    /// Returns `Ok(None)` for non-protocol transactions.
    /// Returns `Ok(Some(DecodedData))` for successfully decoded data.
    pub async fn decode_txid(&self, txid: &str) -> DecoderResult<Option<DecodedData>> {
        self.decode_txid_verbose(txid, false).await
    }

    /// Decode a transaction with optional verbose output
    pub async fn decode_txid_verbose(
        &self,
        txid: &str,
        verbose: bool,
    ) -> DecoderResult<Option<DecodedData>> {
        info!("Attempting to decode transaction: {}", txid);

        // Step 1: Fetch transaction data
        let tx_data = match fetch_transaction(&self.rpc_client, txid).await? {
            Some(data) => data,
            None => {
                info!("Transaction {} not found", txid);
                return Ok(None);
            }
        };

        // Step 2: Check if transaction has P2MS outputs (required for this decoder)
        // Note: This decoder only handles P2MS encoding
        let p2ms_count = tx_data.p2ms_outputs().len();
        if p2ms_count == 0 {
            info!(
                "Transaction {} has no P2MS outputs - cannot decode with P2MS-based decoder",
                txid
            );
            info!("Note: P2MS-based transactions only are supported by this decoder");
            return Ok(None);
        }

        info!(
            "Transaction {} has {} P2MS output(s), attempting protocol detection",
            txid, p2ms_count
        );

        // Step 3: Try protocols in priority order (matches Stage 3 classification order)

        // Priority 1: Omni Layer (exclusive transport via Exodus address)
        if let Some(decoded_protocol) = try_omni(&tx_data, &self.rpc_client).await {
            info!("✅ Detected Omni Layer in {}", txid);
            return self.decode_omni(decoded_protocol).await;
        }

        // Priority 2: Chancecoin (exclusive transport - signature check)
        if let Some(decoded_protocol) = try_chancecoin(&tx_data) {
            info!("✅ Detected Chancecoin in {}", txid);
            return self.decode_chancecoin(decoded_protocol).await;
        }

        // Priority 3: Bitcoin Stamps (MUST be before Counterparty - can be embedded IN Counterparty)
        if let Some(decoded_protocol) = try_bitcoin_stamps(&tx_data) {
            info!("✅ Detected Bitcoin Stamps in {}", txid);
            return self.decode_bitcoin_stamps(decoded_protocol).await;
        }

        // Priority 4: Counterparty (after Stamps to avoid misclassifying Stamps-over-Counterparty)
        // Note: try_counterparty can return BitcoinStamps if it finds a stamp signature in Counterparty data
        let decoded_protocol = if verbose {
            protocol_detection_verbose::try_counterparty_verbose(&tx_data, true)
        } else {
            try_counterparty(&tx_data)
        };

        if let Some(decoded_protocol) = decoded_protocol {
            match &decoded_protocol {
                DecodedProtocol::BitcoinStamps { debug_info, .. } => {
                    info!(
                        "✅ Detected Bitcoin Stamps (Counterparty-embedded) in {}",
                        txid
                    );
                    // Display verbose debug info if available
                    if verbose {
                        if let Some(ref debug_info) = debug_info {
                            debug_info.display_verbose();
                        }
                    }
                    return self.decode_bitcoin_stamps(decoded_protocol).await;
                }
                DecodedProtocol::Counterparty { debug_info, .. } => {
                    info!("✅ Detected Counterparty (P2MS-encoded) in {}", txid);
                    // Display verbose debug info if available
                    if verbose {
                        if let Some(ref debug_info) = debug_info {
                            debug_info.display_verbose();
                        }
                    }
                    return self.decode_counterparty(decoded_protocol).await;
                }
                _ => {}
            }
        }

        // Priority 5: PPk (marker pubkey-based protocol detection)
        if let Some(decoded_protocol) = try_ppk(&tx_data, &self.rpc_client).await {
            info!("✅ Detected PPk protocol in {}", txid);
            return self.decode_ppk(decoded_protocol).await;
        }

        // Priority 6: DataStorage (generic data embedding patterns)
        if let Some(decoded_protocol) =
            datastorage::try_datastorage(&tx_data, self.output_manager.output_dir())
        {
            info!("✅ Detected DataStorage pattern in {}", txid);
            return self.decode_datastorage(decoded_protocol).await;
        }

        // Priority 7: LikelyDataStorage (valid EC points but suspicious patterns)
        if let Some(decoded_protocol) = try_likely_data_storage(&tx_data) {
            info!("✅ Detected Likely Data Storage pattern in {}", txid);
            return self.decode_likely_data_storage(decoded_protocol).await;
        }

        // Priority 8: LikelyLegitimateMultisig (pubkey validation - all valid EC points)
        if let Some(decoded_protocol) = try_likely_legitimate_p2ms(&tx_data) {
            info!("✅ Detected Likely Legitimate Multisig in {}", txid);
            return self.decode_likely_legitimate_p2ms(decoded_protocol).await;
        }

        info!(
            "Transaction {} has P2MS outputs but no recognised protocol signature",
            txid
        );
        Ok(None)
    }

    /// Decode Bitcoin Stamps protocol data
    async fn decode_bitcoin_stamps(
        &self,
        protocol: DecodedProtocol,
    ) -> DecoderResult<Option<DecodedData>> {
        let (txid, decrypted_data) = match protocol {
            DecodedProtocol::BitcoinStamps {
                txid,
                decrypted_data,
                debug_info: _,
            } => (txid, decrypted_data),
            _ => {
                return Err(DecoderError::InvalidTransaction(
                    "Expected Bitcoin Stamps protocol".to_string(),
                ))
            }
        };

        info!("Decoding Bitcoin Stamps data for transaction: {}", txid);

        // Extract the data after stamp signature
        // Format can be either:
        // 1. [2-byte length prefix] + signature + data (pure stamps with length)
        // 2. signature + data (Counterparty-embedded or simple stamps)
        let (stamps_offset, sig_variant) =
            find_stamp_signature(&decrypted_data).ok_or_else(|| {
                DecoderError::InvalidTransaction(format!(
                    "No Bitcoin Stamps signature found in transaction {}",
                    txid
                ))
            })?;

        info!(
            "Found {:?} signature at offset {} (length: {} bytes)",
            sig_variant,
            stamps_offset,
            sig_variant.len()
        );

        let sig_len = sig_variant.len();
        let data_start = stamps_offset + sig_len;

        // Length prefix ONLY for pure Bitcoin Stamps (stamp at offset 2)
        // Counterparty-embedded has stamp at other offsets (like 28) with NO length prefix
        let raw_data = if stamps_offset == 2 {
            // Pure Bitcoin Stamps: [2-byte length] + "stamp(s):" + data
            let length_bytes = [decrypted_data[0], decrypted_data[1]];
            let total_length = ((length_bytes[0] as usize) << 8) | (length_bytes[1] as usize);

            if total_length >= sig_len && total_length <= decrypted_data.len() {
                let data_length = total_length - sig_len;
                info!(
                    "Pure stamps (offset 2) with length prefix: {} bytes",
                    data_length
                );
                &decrypted_data[data_start..(data_start + data_length)]
            } else {
                info!("Invalid length, using all remaining data");
                &decrypted_data[data_start..]
            }
        } else {
            // Counterparty-embedded or other: NO length prefix
            info!(
                "Counterparty-embedded (offset {}), using all remaining data",
                stamps_offset
            );
            &decrypted_data[data_start..]
        };

        // Detect if this is a Counterparty-embedded stamp
        // stamps_offset == 2: Pure Bitcoin Stamps (2-byte length prefix before STAMP)
        // stamps_offset != 2: Counterparty-embedded (STAMP after CNTRPRTY prefix + message type)
        //   Typical offset: 28 bytes (8-byte CNTRPRTY + 4-byte message type + ~16 bytes message data)
        let is_counterparty_embedded = stamps_offset != 2;

        debug!("Raw data after 'stamp:' prefix: {} bytes", raw_data.len());

        // For Counterparty-embedded stamps, apply special processing:
        // 1. Convert the full payload from Latin-1 (description field encoding) to UTF-8
        // 2. Filter to only base64 characters, ignoring any interspersed control bytes
        // 3. Tidy padding so the decoder sees a contiguous base64 string
        let cleaned_string: Option<String> = if is_counterparty_embedded {
            // Step 1: Convert Latin-1 (ISO-8859-1) to UTF-8 string
            // Counterparty description field uses Latin-1 encoding
            // This matches Electrum's decodeURIComponent(escape(descr))
            let latin1_string: String = raw_data.iter().map(|&b| b as char).collect();

            // Step 2: Filter to only base64 characters
            let mut data_str: String = latin1_string
                .chars()
                .filter(|&c| {
                    // Keep ONLY valid base64 characters: A-Za-z0-9+/=
                    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
                })
                .collect();

            debug!(
                "Cleaned Counterparty-embedded data: {} -> {} chars",
                raw_data.len(),
                data_str.len()
            );

            if data_str.is_empty() {
                None
            } else {
                // Per Electrum-Counterparty: Base64 may have junk data after it
                // Also, if multiple P2MS outputs were concatenated, there may be intermediate '=' padding
                // Find the last '=' and truncate there
                if let Some(last_equals) = data_str.rfind('=') {
                    data_str.truncate(last_equals + 1);

                    // Remove any intermediate '=' characters (from concatenated base64 segments)
                    // Keep only the final 1-2 '=' characters for padding
                    let original_len = data_str.len();
                    let cleaned: String = data_str
                        .chars()
                        .enumerate()
                        .filter(|(i, c)| *c != '=' || *i >= original_len - 2)
                        .map(|(_, c)| c)
                        .collect();
                    data_str = cleaned;
                }

                debug!("Final base64: {} chars", data_str.len());
                Some(data_str)
            }
        } else {
            // Pure stamps (stamp at offset 2): no cleanup needed
            None
        };

        let cleaned_data: &[u8] = if let Some(ref s) = cleaned_string {
            debug!(
                "Cleaned data for Counterparty-embedded stamp: {} bytes",
                s.len()
            );
            s.as_bytes()
        } else {
            raw_data
        };

        // Shared payload handler keeps Stage 3 and Stage 4 aligned
        let handle_payload = |payload: Vec<u8>| -> DecoderResult<Option<DecodedData>> {
            let (variant, content_type, image_format) =
                detect_content_type_from_payload(&payload);

            match (variant, content_type, image_format, payload) {
                (Some(StampsVariant::Compressed), Some(ct), _, bytes) => {
                    info!("Detected compressed Bitcoin Stamps payload ({})", ct);
                    let output_path = self
                        .output_manager
                        .write_compressed(&txid, &bytes, ct)
                        .map_err(|e| {
                            DecoderError::Io(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                e,
                            ))
                        })?;

                    let decoded_data = DecodedData::BitcoinStamps {
                        data: BitcoinStampsData::Compressed(DecodedCompressed {
                            txid: txid.clone(),
                            compression_type: ct.to_string(),
                            file_path: output_path,
                            size_bytes: bytes.len(),
                            bytes,
                        }),
                    };

                    info!(
                        "Successfully decoded compressed Bitcoin Stamps: {}",
                        decoded_data.summary()
                    );
                    Ok(Some(decoded_data))
                }
                (Some(StampsVariant::Classic), Some(_), Some(fmt), bytes) => {
                    info!(
                        "Detected image payload for transaction {} (format: {:?})",
                        txid, fmt
                    );
                    let output_path = self
                        .output_manager
                        .write_image(&txid, &bytes, fmt.clone())
                        .map_err(|e| {
                            DecoderError::Io(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                e,
                            ))
                        })?;

                    let decoded_data = DecodedData::BitcoinStamps {
                        data: BitcoinStampsData::Image(DecodedImage {
                            txid: txid.clone(),
                            format: fmt,
                            file_path: output_path,
                            size_bytes: bytes.len(),
                            bytes,
                        }),
                    };

                    info!(
                        "Successfully decoded Bitcoin Stamps image: {}",
                        decoded_data.summary()
                    );
                    Ok(Some(decoded_data))
                }
                (Some(StampsVariant::SRC20) | Some(StampsVariant::SRC721) | Some(StampsVariant::SRC101), Some(_), _, bytes) => {
                    match serde_json::from_slice::<serde_json::Value>(&bytes) {
                        Ok(parsed_json) => {
                            let json_type = classify_json_data(&bytes);
                            let output_path = self
                                .output_manager
                                .write_json(&txid, &bytes, json_type.clone())
                                .map_err(|e| {
                                    DecoderError::Io(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        e,
                                    ))
                                })?;

                            let decoded_data = DecodedData::BitcoinStamps {
                                data: BitcoinStampsData::Json(DecodedJson {
                                    txid: txid.clone(),
                                    json_type,
                                    file_path: output_path,
                                    size_bytes: bytes.len(),
                                    parsed_data: parsed_json,
                                    bytes,
                                }),
                            };

                            info!(
                                "Successfully decoded Bitcoin Stamps JSON: {}",
                                decoded_data.summary()
                            );
                            Ok(Some(decoded_data))
                        }
                        Err(e) => {
                            warn!(
                                "Helper marked {} as JSON but parsing failed: {} - writing as binary",
                                txid, e
                            );
                            let output_path = self
                                .output_manager
                                .write_data(
                                    &txid,
                                    &bytes,
                                    Some("application/octet-stream"),
                                )
                                .map_err(|e| {
                                    DecoderError::Io(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        e,
                                    ))
                                })?;

                            let decoded_data = DecodedData::BitcoinStamps {
                                data: BitcoinStampsData::Data(DecodedGenericData {
                                    txid: txid.clone(),
                                    content_type: "application/octet-stream".to_string(),
                                    file_path: output_path,
                                    size_bytes: bytes.len(),
                                    bytes,
                                }),
                            };

                            info!(
                                "Saved malformed JSON payload as binary data for {}",
                                txid
                            );
                            Ok(Some(decoded_data))
                        }
                    }
                }
                (Some(StampsVariant::HTML), Some(_), _, bytes) => {
                    info!("Detected HTML Bitcoin Stamps payload");
                    let output_path = self
                        .output_manager
                        .write_html(&txid, &bytes)
                        .map_err(|e| {
                            DecoderError::Io(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                e,
                            ))
                        })?;

                    let decoded_data = DecodedData::BitcoinStamps {
                        data: BitcoinStampsData::Html(DecodedHtml {
                            txid: txid.clone(),
                            file_path: output_path,
                            size_bytes: bytes.len(),
                            bytes,
                        }),
                    };

                    info!(
                        "Successfully decoded HTML Bitcoin Stamps: {}",
                        decoded_data.summary()
                    );
                    Ok(Some(decoded_data))
                }
                (Some(StampsVariant::Data), Some(ct), _, bytes) => {
                    info!(
                        "Detected data payload for transaction {} ({} bytes, type: {})",
                        txid,
                        bytes.len(),
                        ct
                    );
                    let output_path = self
                        .output_manager
                        .write_data(&txid, &bytes, Some(ct))
                        .map_err(|e| {
                            DecoderError::Io(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                e,
                            ))
                        })?;

                    let decoded_data = DecodedData::BitcoinStamps {
                        data: BitcoinStampsData::Data(DecodedGenericData {
                            txid: txid.clone(),
                            content_type: ct.to_string(),
                            file_path: output_path,
                            size_bytes: bytes.len(),
                            bytes,
                        }),
                    };

                    info!(
                        "Successfully decoded data Bitcoin Stamps: {}",
                        decoded_data.summary()
                    );
                    Ok(Some(decoded_data))
                }
                (Some(StampsVariant::Unknown) | None, _, _, bytes) => Err(
                    DecoderError::InvalidTransaction(format!(
                        "Transaction {} contains empty or unrecognizable data after decoding ({} bytes)",
                        txid,
                        bytes.len()
                    )),
                ),
                (detected_variant, detected_content_type, detected_image_format, _) => {
                    warn!(
                        "Invariant violation in content detection for {}: variant={:?}, content_type={:?}, image_format={:?}",
                        txid, detected_variant, detected_content_type, detected_image_format
                    );
                    Err(DecoderError::InvalidTransaction(format!(
                        "Transaction {} produced inconsistent content detection results",
                        txid
                    )))
                }
            }
        };

        // Try base64 decoding first when heuristics indicate, otherwise use raw payload
        let is_base64 = is_base64_data(cleaned_data);
        debug!(
            "Is base64 (heuristic): {}, force_base64: {}, cleaned_data length: {}",
            is_base64,
            is_counterparty_embedded,
            cleaned_data.len()
        );

        if is_base64 || is_counterparty_embedded {
            match BASE64_LENIENT.decode(cleaned_data) {
                Ok(decoded_bytes) => {
                    debug!("Base64 decode successful: {} bytes", decoded_bytes.len());
                    return handle_payload(decoded_bytes);
                }
                Err(e) => {
                    debug!(
                        "Base64 decode failed for transaction {} ({} bytes): {}",
                        txid,
                        cleaned_data.len(),
                        e
                    );
                }
            }
        }

        handle_payload(cleaned_data.to_vec())
    }

    /// Decode Counterparty protocol data
    async fn decode_counterparty(
        &self,
        protocol: DecodedProtocol,
    ) -> DecoderResult<Option<DecodedData>> {
        let (txid, decrypted_data) = match protocol {
            DecodedProtocol::Counterparty {
                txid,
                decrypted_data,
                debug_info: _,
            } => (txid, decrypted_data),
            _ => {
                return Err(DecoderError::InvalidTransaction(
                    "Expected Counterparty protocol".to_string(),
                ))
            }
        };

        info!("Processing Counterparty data for transaction: {}", txid);

        // Find the Counterparty signature offset
        let counterparty_offset = protocol_detection::has_counterparty_signature(&decrypted_data)
            .ok_or_else(|| {
            DecoderError::InvalidTransaction(format!(
                "No Counterparty signature found in transaction {}",
                txid
            ))
        })?;

        // Extract the Counterparty message data (skip the CNTRPRTY prefix)
        let message_start =
            counterparty_offset + crate::types::counterparty::COUNTERPARTY_PREFIX.len();
        if message_start >= decrypted_data.len() {
            return Err(DecoderError::InvalidTransaction(format!(
                "Invalid Counterparty data in transaction {}",
                txid
            )));
        }

        let message_data = &decrypted_data[message_start..];

        // The message_data is already the payload after CNTRPRTY prefix
        // Counterparty has two message type formats:
        // - Modern: 4-byte big-endian integer (try first)
        // - Legacy: 1-byte integer (fallback)
        info!(
            "Raw message data length: {}, hex: {}",
            message_data.len(),
            hex::encode(&message_data[..std::cmp::min(20, message_data.len())])
        );

        let (message_type, payload) = if message_data.is_empty() {
            return Err(DecoderError::InvalidTransaction(format!(
                "Counterparty message too short in transaction {}",
                txid
            )));
        } else if message_data.len() >= 4 {
            // Try 4-byte message type first (modern format)
            let message_type_u32 = u32::from_be_bytes([
                message_data[0],
                message_data[1],
                message_data[2],
                message_data[3],
            ]);

            if let Some(mt) =
                crate::types::counterparty::CounterpartyMessageType::from_u32(message_type_u32)
            {
                info!("Parsed 4-byte message type ID: {}", message_type_u32);
                (mt, message_data[4..].to_vec())
            } else {
                // Not a valid 4-byte type, try 1-byte fallback
                let message_type_u8 = message_data[0] as u32;
                if let Some(mt) =
                    crate::types::counterparty::CounterpartyMessageType::from_u32(message_type_u8)
                {
                    info!("Parsed 1-byte message type ID: {}", message_type_u8);
                    (mt, message_data[1..].to_vec())
                } else {
                    info!(
                        "Unknown Counterparty message type (4-byte: {}, 1-byte: {}) in {}",
                        message_type_u32, message_type_u8, txid
                    );
                    return Err(DecoderError::InvalidTransaction(format!(
                        "Unknown Counterparty message type in transaction {}",
                        txid
                    )));
                }
            }
        } else {
            // Less than 4 bytes, can only try 1-byte format
            let message_type_u8 = message_data[0] as u32;
            if let Some(mt) =
                crate::types::counterparty::CounterpartyMessageType::from_u32(message_type_u8)
            {
                info!("Parsed 1-byte message type ID: {}", message_type_u8);
                (mt, message_data[1..].to_vec())
            } else {
                info!(
                    "Unknown Counterparty message type {} in {}",
                    message_type_u8, txid
                );
                return Err(DecoderError::InvalidTransaction(format!(
                    "Unknown Counterparty message type in transaction {}",
                    txid
                )));
            }
        };

        info!(
            "Successfully parsed message type: {:?}, payload length: {}",
            message_type,
            payload.len()
        );

        // Parse the payload into structured data using our new parsing infrastructure
        let parsed_message = match message_type.parse_payload(&payload) {
            Ok(parsed) => Some(serde_json::to_value(parsed).map_err(|e| {
                DecoderError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            })?),
            Err(parse_err) => {
                info!(
                    "Failed to parse Counterparty payload for {}: {}",
                    txid, parse_err
                );
                None
            }
        };

        // Write the structured JSON data instead of raw binary
        let output_path = self
            .output_manager
            .write_counterparty_json(&txid, &message_type, &payload, &parsed_message)
            .map_err(|e| DecoderError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        let counterparty_data = CounterpartyData {
            txid: txid.clone(),
            file_path: output_path,
            message_type,
            raw_data: message_data.to_vec(),
        };

        let decoded_data = DecodedData::Counterparty {
            data: counterparty_data,
        };

        info!(
            "Successfully decoded Counterparty: {}",
            decoded_data.summary()
        );
        Ok(Some(decoded_data))
    }

    /// Decode Omni Layer protocol data (STUB - not yet implemented)
    async fn decode_omni(&self, protocol: DecodedProtocol) -> DecoderResult<Option<DecodedData>> {
        let (txid, decrypted_data, sender_address, packet_count) = match protocol {
            DecodedProtocol::Omni {
                txid,
                decrypted_data,
                sender_address,
                packet_count,
                debug_info: _,
            } => (txid, decrypted_data, sender_address, packet_count),
            _ => {
                return Err(DecoderError::InvalidTransaction(
                    "Expected Omni protocol".to_string(),
                ))
            }
        };

        info!("Decoding Omni Layer data for transaction: {}", txid);

        // Parse Omni message header (version + message type)
        if decrypted_data.len() < 4 {
            return Err(DecoderError::InvalidTransaction(format!(
                "Omni data too short: {} bytes",
                decrypted_data.len()
            )));
        }

        let _version = u16::from_be_bytes([decrypted_data[0], decrypted_data[1]]);
        let message_type_u16 = u16::from_be_bytes([decrypted_data[2], decrypted_data[3]]);

        // Convert to OmniMessageType
        let message_type = crate::types::omni::OmniMessageType::from_u32(message_type_u16 as u32)
            .ok_or_else(|| {
            DecoderError::InvalidTransaction(format!(
                "Unknown Omni message type: {}",
                message_type_u16
            ))
        })?;

        info!(
            "Omni message type: {:?} ({})",
            message_type, message_type_u16
        );

        // Parse the message payload according to its type
        let parsed_data = match omni_parser::parse_omni_payload(&message_type, &decrypted_data) {
            Ok(parsed) => {
                info!("Successfully parsed Omni message payload");
                Some(parsed)
            }
            Err(e) => {
                debug!("Failed to parse Omni message payload: {}", e);
                None
            }
        };

        // Write Omni JSON output with parsed data
        let output_path = self
            .output_manager
            .write_omni_json(
                &txid,
                &message_type,
                &sender_address,
                &decrypted_data,
                packet_count,
                parsed_data,
            )
            .map_err(|e| DecoderError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        let omni_data = OmniData {
            txid: txid.clone(),
            file_path: output_path,
            message_type,
            sender_address,
            deobfuscated_payload: decrypted_data,
            packet_count,
        };

        let decoded_data = DecodedData::Omni { data: omni_data };

        info!(
            "Successfully decoded Omni Layer: {}",
            decoded_data.summary()
        );

        Ok(Some(decoded_data))
    }

    /// Decode Chancecoin protocol data
    async fn decode_chancecoin(
        &self,
        protocol: DecodedProtocol,
    ) -> DecoderResult<Option<DecodedData>> {
        let (txid, message) = match protocol {
            DecodedProtocol::Chancecoin {
                txid,
                message,
                debug_info: _,
            } => (txid, message),
            _ => {
                return Err(DecoderError::InvalidTransaction(
                    "Expected Chancecoin protocol".to_string(),
                ))
            }
        };

        info!("Decoding Chancecoin data for transaction: {}", txid);
        info!("Message type: {}", message.message_type.description());
        info!("Data length: {} bytes", message.data.len());

        // Create output file for Chancecoin data
        let output_path = self
            .output_manager
            .create_chancecoin_output(&txid, &message)?;

        info!("Wrote Chancecoin data to: {:?}", output_path);

        let chancecoin_data = ChancecoinData {
            txid: txid.clone(),
            file_path: output_path,
            message_type: message.message_type.clone(),
            data: message.data.clone(),
        };

        let decoded_data = DecodedData::Chancecoin {
            data: chancecoin_data,
        };

        info!(
            "Successfully decoded Chancecoin: {}",
            decoded_data.summary()
        );

        Ok(Some(decoded_data))
    }

    /// Decode PPk protocol data
    async fn decode_ppk(
        &self,
        protocol: DecodedProtocol,
    ) -> DecoderResult<Option<DecodedData>> {
        let (txid, variant, rt_json, raw_opreturn_bytes, parsed_data, content_type, odin_identifier) = match protocol {
            DecodedProtocol::PPk {
                txid,
                variant,
                rt_json,
                raw_opreturn_bytes,
                parsed_data,
                content_type,
                odin_identifier,
                debug_info: _,
            } => (txid, variant, rt_json, raw_opreturn_bytes, parsed_data, content_type, odin_identifier),
            _ => {
                return Err(DecoderError::InvalidTransaction(
                    "Expected PPk protocol".to_string(),
                ))
            }
        };

        info!("Decoding PPk data for transaction: {}", txid);
        info!("Variant: {:?}", variant);
        info!("Content type: {}", content_type);
        if let Some(ref odin) = odin_identifier {
            info!("ODIN: {}", odin.full_identifier);
        }

        // Create output file for PPk data
        let output_path = self.output_manager.create_ppk_output(
            &txid,
            &variant,
            rt_json.as_ref(),
            raw_opreturn_bytes.as_ref(),
            parsed_data.as_ref(),
            &content_type,
            odin_identifier.as_ref(),
        )?;

        info!("Wrote PPk data to: {:?}", output_path);

        let ppk_data = PPkData {
            txid: txid.clone(),
            file_path: output_path,
            variant,
            rt_json,
            odin_identifier,
            content_type,
        };

        let decoded_data = DecodedData::PPk {
            data: ppk_data,
        };

        info!(
            "Successfully decoded PPk: {}",
            decoded_data.summary()
        );

        Ok(Some(decoded_data))
    }

    /// Decode DataStorage protocol data
    async fn decode_datastorage(
        &self,
        protocol: DecodedProtocol,
    ) -> DecoderResult<Option<DecodedData>> {
        let (txid, pattern, decoded_data, metadata) = match protocol {
            DecodedProtocol::DataStorage {
                txid,
                pattern,
                decoded_data,
                metadata,
                debug_info: _,
            } => (txid, pattern, decoded_data, metadata),
            _ => {
                return Err(DecoderError::InvalidTransaction(
                    "Expected DataStorage protocol".to_string(),
                ))
            }
        };

        info!("Processing DataStorage data for transaction: {}", txid);
        info!("Pattern: {}", pattern);
        info!("Decoded size: {} bytes", decoded_data.len());

        // The data is already decoded and saved by try_datastorage
        // Just create the DecodedData response
        let datastorage_data = DataStorageData {
            txid: txid.clone(),
            pattern: pattern.clone(),
            decoded_data: decoded_data.clone(),
            metadata,
        };

        Ok(Some(DecodedData::DataStorage(datastorage_data)))
    }

    /// Handle likely legitimate multisig classification
    async fn decode_likely_data_storage(
        &self,
        protocol: DecodedProtocol,
    ) -> DecoderResult<Option<DecodedData>> {
        let (txid, pattern_type, details) = match protocol {
            DecodedProtocol::LikelyDataStorage {
                txid,
                pattern_type,
                details,
                debug_info: _,
            } => (txid, pattern_type, details),
            _ => {
                return Err(DecoderError::InvalidTransaction(
                    "Expected LikelyDataStorage protocol".to_string(),
                ))
            }
        };

        info!(
            "Transaction {} classified as Likely Data Storage ({}): {}",
            txid, pattern_type, details
        );

        // For likely data storage, we don't decode/extract any specific data
        // Just return None to indicate "transaction processed, no data to save"
        Ok(None)
    }

    async fn decode_likely_legitimate_p2ms(
        &self,
        protocol: DecodedProtocol,
    ) -> DecoderResult<Option<DecodedData>> {
        let (txid, validation_summary, has_duplicates) = match protocol {
            DecodedProtocol::LikelyLegitimateMultisig {
                txid,
                validation_summary,
                has_duplicates,
                debug_info: _,
            } => (txid, validation_summary, has_duplicates),
            _ => {
                return Err(DecoderError::InvalidTransaction(
                    "Expected LikelyLegitimateMultisig protocol".to_string(),
                ))
            }
        };

        info!(
            "Transaction {} classified as Likely Legitimate Multisig: {}",
            txid, validation_summary
        );
        if has_duplicates {
            info!("Note: Duplicate keys detected (likely wallet error)");
        }

        // For legitimate multisig, we don't decode/save any data
        // Just return None to indicate "transaction processed, no data to save"
        Ok(None)
    }
}
