//! Decoded output type structs for Bitcoin protocol data
//!
//! These structs represent successfully decoded data from various
//! Bitcoin protocols (Stamps, Counterparty, Omni, etc.)

use super::output::JsonType;
use crate::types::content_detection::{DocumentFormat, ImageFormat};
use std::path::PathBuf;

/// Information about a successfully decoded image
#[derive(Debug, Clone)]
pub struct DecodedImage {
    pub txid: String,
    pub format: ImageFormat,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>, // Actual decoded image bytes
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

impl DecodedJson {
    /// Get a human-readable summary of the decoded JSON data
    pub fn summary(&self) -> String {
        format!(
            "Transaction {}: {} ({} bytes) -> {}",
            &self.txid[..16], // Show first 16 chars of txid
            self.json_type.display_name(),
            self.size_bytes,
            self.file_path.display()
        )
    }
}

/// Information about successfully decoded HTML data
#[derive(Debug, Clone)]
pub struct DecodedHtml {
    pub txid: String,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>,
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

/// Information about successfully decoded compressed data
#[derive(Debug, Clone)]
pub struct DecodedCompressed {
    pub txid: String,
    pub compression_type: String,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>,
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

/// Information about successfully decoded generic data
#[derive(Debug, Clone)]
pub struct DecodedGenericData {
    pub txid: String,
    pub content_type: String,
    pub file_path: PathBuf,
    pub size_bytes: usize,
    pub bytes: Vec<u8>,
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
