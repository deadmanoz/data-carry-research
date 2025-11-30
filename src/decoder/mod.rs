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
use self::output::{JsonType, OutputManager};
use self::ppk::try_ppk;
use self::protocol_detection::{
    fetch_transaction, try_bitcoin_stamps, try_counterparty, try_likely_data_storage,
    try_likely_legitimate_p2ms, try_omni, DecodedProtocol,
};
use crate::shared::is_base64_data;
use crate::types::content_detection::{detect_image_format, DocumentFormat, ImageFormat};
use crate::types::stamps::validation::{
    detect_content_type_from_payload, extract_stamps_payload, find_stamp_signature,
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
    LikelyDataStorage(LikelyDataStorageData),
}

/// Bitcoin Stamps protocol data types
#[derive(Debug, Clone)]
pub enum BitcoinStampsData {
    Image(DecodedImage),
    Document(DecodedDocument),
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

/// LikelyDataStorage protocol data
#[derive(Debug, Clone)]
pub struct LikelyDataStorageData {
    pub txid: String,
    pub pattern_type: String, // "InvalidECPoint", "HighOutputCount", "DustAmount"
    pub details: String,
    pub file_path: PathBuf,
}

impl DecodedData {
    /// Get a human-readable summary of the decoded data
    pub fn summary(&self) -> String {
        match self {
            DecodedData::BitcoinStamps { data } => match data {
                BitcoinStampsData::Image(img) => img.summary(),
                BitcoinStampsData::Document(doc) => doc.summary(),
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
                    data.variant, data.content_type, odin_suffix
                )
            }
            DecodedData::DataStorage(data) => {
                format!(
                    "DataStorage {} ({} bytes)",
                    data.pattern,
                    data.decoded_data.len()
                )
            }
            DecodedData::LikelyDataStorage(data) => {
                format!("LikelyDataStorage {} - {}", data.pattern_type, data.details)
            }
        }
    }

    /// Get the transaction ID
    pub fn txid(&self) -> &str {
        match self {
            DecodedData::BitcoinStamps { data, .. } => match data {
                BitcoinStampsData::Image(img) => &img.txid,
                BitcoinStampsData::Document(doc) => &doc.txid,
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
            DecodedData::LikelyDataStorage(data) => &data.txid,
        }
    }

    /// Get the file path (returns None for DataStorage since it *could* save multiple files)
    pub fn file_path(&self) -> Option<&PathBuf> {
        match self {
            DecodedData::BitcoinStamps { data, .. } => match data {
                BitcoinStampsData::Image(img) => Some(&img.file_path),
                BitcoinStampsData::Document(doc) => Some(&doc.file_path),
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
            DecodedData::LikelyDataStorage(data) => Some(&data.file_path),
        }
    }

    /// Get the size in bytes
    pub fn size_bytes(&self) -> usize {
        match self {
            DecodedData::BitcoinStamps { data, .. } => match data {
                BitcoinStampsData::Image(img) => img.size_bytes,
                BitcoinStampsData::Document(doc) => doc.size_bytes,
                BitcoinStampsData::Json(json) => json.size_bytes,
                BitcoinStampsData::Html(html) => html.size_bytes,
                BitcoinStampsData::Compressed(comp) => comp.size_bytes,
                BitcoinStampsData::Data(data) => data.size_bytes,
            },
            DecodedData::Omni { data } => data.deobfuscated_payload.len(),
            DecodedData::Counterparty { data } => data.raw_data.len(),
            DecodedData::Chancecoin { data } => data.data.len(),
            DecodedData::PPk { data } => {
                data.rt_json
                    .as_ref()
                    .map(|j| j.to_string().len())
                    .unwrap_or(0)
                    + data
                        .odin_identifier
                        .as_ref()
                        .map(|o| o.full_identifier.len())
                        .unwrap_or(0)
            }
            DecodedData::DataStorage(data) => data.decoded_data.len(),
            DecodedData::LikelyDataStorage(_) => 0, // Metadata-only classification, no data bytes
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

/// Information about a successfully decoded document (PDF, etc.)
#[derive(Debug, Clone)]
pub struct DecodedDocument {
    pub txid: String,
    pub format: DocumentFormat,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>,
}

impl DecodedDocument {
    /// Get a human-readable summary of the decoded document
    pub fn summary(&self) -> String {
        let format_name = match self.format {
            DocumentFormat::Pdf => "PDF",
        };
        format!(
            "Transaction {}: {} document ({} bytes) -> {}",
            &self.txid[..16.min(self.txid.len())],
            format_name,
            self.size_bytes,
            self.file_path.display()
        )
    }
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
            .map_err(|e| DecoderError::Io(std::io::Error::other(e)))?;

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
    ///    - LikelyDataStorage (suspicious patterns - invalid EC points, high output count, dust amounts)
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

        // Use the shared extraction function (same as Stage 3)
        // This handles Pure vs Counterparty-embedded stamps with proper Latin-1 conversion
        let cleaned_data = extract_stamps_payload(&decrypted_data).ok_or_else(|| {
            DecoderError::InvalidTransaction(format!(
                "No Bitcoin Stamps signature found in transaction {}",
                txid
            ))
        })?;

        // Log signature info for debugging
        if let Some((stamps_offset, sig_variant)) = find_stamp_signature(&decrypted_data) {
            let transport_type = if stamps_offset == 2 {
                "Pure Bitcoin Stamps"
            } else {
                "Counterparty-embedded"
            };
            info!(
                "Found {:?} signature at offset {} ({}) - {} bytes payload",
                sig_variant,
                stamps_offset,
                transport_type,
                cleaned_data.len()
            );
        }

        // Reference for handle_payload closure
        let cleaned_data_ref = cleaned_data.as_slice();

        // Shared payload handler keeps Stage 3 and Stage 4 aligned
        let handle_payload = |payload: Vec<u8>| -> DecoderResult<Option<DecodedData>> {
            let (variant, content_type, image_format) = detect_content_type_from_payload(&payload);

            match (variant, content_type, image_format, payload) {
                (Some(StampsVariant::Compressed), Some(ct), _, bytes) => {
                    info!("Detected compressed Bitcoin Stamps payload ({})", ct);
                    let output_path = self
                        .output_manager
                        .write_compressed(&txid, &bytes, ct)
                        .map_err(|e| {
                            DecoderError::Io(std::io::Error::other(
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
                // Handle PDF documents separately (semantically correct - PDF is a document, not an image)
                (Some(StampsVariant::Classic), Some("application/pdf"), _, bytes) => {
                    info!(
                        "Detected PDF document payload for transaction {}",
                        txid
                    );
                    let output_path = self
                        .output_manager
                        .write_document(&txid, &bytes, DocumentFormat::Pdf)
                        .map_err(|e| {
                            DecoderError::Io(std::io::Error::other(
                                e,
                            ))
                        })?;

                    let decoded_data = DecodedData::BitcoinStamps {
                        data: BitcoinStampsData::Document(DecodedDocument {
                            txid: txid.clone(),
                            format: DocumentFormat::Pdf,
                            file_path: output_path,
                            size_bytes: bytes.len(),
                            bytes,
                        }),
                    };

                    info!(
                        "Successfully decoded Bitcoin Stamps document: {}",
                        decoded_data.summary()
                    );
                    Ok(Some(decoded_data))
                }
                // Handle image formats using content_detection::detect_image_format
                (Some(StampsVariant::Classic), Some(_), _, bytes) => {
                    // Re-detect using canonical content_detection::ImageFormat
                    let fmt = match detect_image_format(&bytes) {
                        Some(f) => f,
                        None => {
                            warn!(
                                "Could not detect image format for transaction {} - falling back to generic data",
                                txid
                            );
                            // Fall through to generic data handling
                            let output_path = self
                                .output_manager
                                .write_data(&txid, &bytes, Some("application/octet-stream"))
                                .map_err(|e| {
                                    DecoderError::Io(std::io::Error::other(
                                        e,
                                    ))
                                })?;

                            return Ok(Some(DecodedData::BitcoinStamps {
                                data: BitcoinStampsData::Data(DecodedGenericData {
                                    txid: txid.clone(),
                                    content_type: "application/octet-stream".to_string(),
                                    file_path: output_path,
                                    size_bytes: bytes.len(),
                                    bytes,
                                }),
                            }));
                        }
                    };

                    info!(
                        "Detected image payload for transaction {} (format: {:?})",
                        txid, fmt
                    );
                    let output_path = self
                        .output_manager
                        .write_image(&txid, &bytes, fmt)
                        .map_err(|e| {
                            DecoderError::Io(std::io::Error::other(
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
                                    DecoderError::Io(std::io::Error::other(
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
                                    DecoderError::Io(std::io::Error::other(
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
                            DecoderError::Io(std::io::Error::other(
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
                            DecoderError::Io(std::io::Error::other(
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

        // Try base64 decoding - Bitcoin Stamps payloads are typically base64 encoded
        // The shared extract_stamps_payload already cleaned the data for us
        let is_base64 = is_base64_data(cleaned_data_ref);
        debug!(
            "Is base64 (heuristic): {}, cleaned_data length: {}",
            is_base64,
            cleaned_data_ref.len()
        );

        // Always try base64 decode first since extract_stamps_payload already cleaned the data
        match BASE64_LENIENT.decode(cleaned_data_ref) {
            Ok(decoded_bytes) => {
                debug!("Base64 decode successful: {} bytes", decoded_bytes.len());
                return handle_payload(decoded_bytes);
            }
            Err(e) => {
                debug!(
                    "Base64 decode failed for transaction {} ({} bytes): {}",
                    txid,
                    cleaned_data_ref.len(),
                    e
                );
            }
        }

        // Fallback to raw payload if base64 decode fails
        handle_payload(cleaned_data)
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
                DecoderError::Io(std::io::Error::other(e))
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
            .map_err(|e| DecoderError::Io(std::io::Error::other(e)))?;

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
            .map_err(|e| DecoderError::Io(std::io::Error::other(e)))?;

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
    async fn decode_ppk(&self, protocol: DecodedProtocol) -> DecoderResult<Option<DecodedData>> {
        let (
            txid,
            variant,
            rt_json,
            raw_opreturn_bytes,
            parsed_data,
            content_type,
            odin_identifier,
        ) = match protocol {
            DecodedProtocol::PPk {
                txid,
                variant,
                rt_json,
                raw_opreturn_bytes,
                parsed_data,
                content_type,
                odin_identifier,
                debug_info: _,
            } => (
                txid,
                variant,
                rt_json,
                raw_opreturn_bytes,
                parsed_data,
                content_type,
                odin_identifier,
            ),
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

        let decoded_data = DecodedData::PPk { data: ppk_data };

        info!("Successfully decoded PPk: {}", decoded_data.summary());

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

        // Create metadata JSON (no data extraction - heuristic classification only)
        let metadata = serde_json::json!({
            "txid": txid,
            "pattern_type": pattern_type,
            "details": details,
            "classification": "LikelyDataStorage",
            "note": "Heuristic classification - no protocol data extracted"
        });

        // Save to output_data/decoded/likely_data_storage/<pattern_type>/<txid>.json
        let output_path = self
            .output_manager
            .output_dir()
            .join("likely_data_storage")
            .join(&pattern_type)
            .join(format!("{}.json", txid));

        // Create directory structure
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write metadata JSON
        let json_str = serde_json::to_string_pretty(&metadata)
            .map_err(std::io::Error::other)?;
        std::fs::write(&output_path, json_str)?;

        info!(
            "Saved LikelyDataStorage metadata to {}",
            output_path.display()
        );

        // Return LikelyDataStorage variant (metadata saved as side effect)
        Ok(Some(DecodedData::LikelyDataStorage(
            LikelyDataStorageData {
                txid,
                pattern_type,
                details,
                file_path: output_path,
            },
        )))
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
