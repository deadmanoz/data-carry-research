//! Decoded protocol data types
//!
//! Unified types for decoded data from Bitcoin P2MS-based protocols.

use super::decoded_outputs::{
    DecodedCompressed, DecodedDocument, DecodedGenericData, DecodedHtml, DecodedImage, DecodedJson,
};
use std::path::PathBuf;

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
