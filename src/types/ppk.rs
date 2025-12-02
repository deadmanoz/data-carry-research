//! PPk Protocol Type Definitions
//!
//! PPk (PPkPub) is an abandoned blockchain infrastructure protocol from Beijing University
//! of Posts and Telecommunications (2015-2019) that attempted to create a decentralised
//! naming and identity system built on Bitcoin.
//!
//! **NOTE**: Detection logic has been moved to `crate::decoder::ppk`.
//! This module contains only type definitions.

use crate::types::ProtocolVariant;

/// PPk protocol detection result
#[derive(Debug, Clone)]
pub struct PPkDetectionResult {
    /// Protocol variant (from existing ProtocolVariant enum)
    pub variant: ProtocolVariant,
    /// Parsed RT JSON (for RT variants only)
    pub rt_json: Option<serde_json::Value>,
    /// Full OP_RETURN bytes (COMPLETE data, not trimmed)
    pub raw_opreturn_bytes: Option<Vec<u8>>,
    /// Extracted/parsed data (JSON string, registration number, message text)
    pub parsed_data: Option<Vec<u8>>,
    /// Content type for this variant
    pub content_type: &'static str,
}

/// ODIN identifier for PPk resources
/// Format: ppk:[BLOCK_HEIGHT].[TRANSACTION_INDEX]/[DSS]
#[derive(Debug, Clone)]
pub struct OdinIdentifier {
    pub block_height: u64,
    pub tx_index: usize,
    pub dss: String,
    pub full_identifier: String,
    pub block_time: u64,
}

impl OdinIdentifier {
    pub fn new(block_height: u64, tx_index: usize, dss: String, block_time: u64) -> Self {
        let full_identifier = format!("ppk:{}.{}/{}", block_height, tx_index, dss);
        Self {
            block_height,
            tx_index,
            dss,
            full_identifier,
            block_time,
        }
    }
}
