//! DataStorage Protocol Decoder
//!
//! This module provides detection and decoding capabilities for various data storage
//! patterns found in Bitcoin P2MS outputs. It can identify and extract:
//! - Plain text and structured text (JSON, XML, scripts)
//! - Compressed data (gzip, zlib, bzip2)
//! - Encoded data (base64, hex)
//! - Binary files with magic numbers
//! - Proof-of-burn and structured burn patterns

use crate::config::output_paths;
use crate::decoder::protocol_detection::{DecodedProtocol, TransactionData};
use crate::shared::datastorage_helpers::{
    detect_binary_signature, extract_key_data, is_burn_pattern,
};
use crate::types::TransactionOutput;
use bzip2::read::BzDecoder;
use flate2::read::{GzDecoder, ZlibDecoder};
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Types of data patterns that can be detected and decoded
#[derive(Debug, Clone, PartialEq)]
pub enum DataPattern {
    // Text-based patterns
    PlainText,
    JsonData,
    XmlData,
    PythonScript,
    JavaScriptCode,
    ShellScript,

    // Binary patterns
    CompressedGzip,
    CompressedZlib,
    CompressedBzip2,
    Base64Encoded,
    HexEncoded,
    BinaryFile(String), // With detected file type

    // Burn patterns
    ProofOfBurn,
    StructuredBurn(String), // With pattern description

    // Unknown but valid data
    UnknownData,
}

impl DataPattern {
    pub fn file_extension(&self) -> &str {
        match self {
            DataPattern::PlainText => "txt",
            DataPattern::JsonData => "json",
            DataPattern::XmlData => "xml",
            DataPattern::PythonScript => "py",
            DataPattern::JavaScriptCode => "js",
            DataPattern::ShellScript => "sh",
            DataPattern::CompressedGzip => "gz",
            DataPattern::CompressedZlib => "zlib",
            DataPattern::CompressedBzip2 => "bz2",
            DataPattern::Base64Encoded => "b64",
            DataPattern::HexEncoded => "hex",
            DataPattern::BinaryFile(file_type) => match file_type.as_str() {
                "PDF" => "pdf",
                "PNG" => "png",
                "JPEG" => "jpg",
                "GIF" => "gif",
                "ZIP" => "zip",
                "RAR" => "rar",
                "7Z" => "7z",
                _ => "bin",
            },
            DataPattern::ProofOfBurn => "burn",
            DataPattern::StructuredBurn(_) => "burn",
            DataPattern::UnknownData => "dat",
        }
    }

    pub fn description(&self) -> String {
        match self {
            DataPattern::PlainText => "Plain text data".to_string(),
            DataPattern::JsonData => "JSON structured data".to_string(),
            DataPattern::XmlData => "XML structured data".to_string(),
            DataPattern::PythonScript => "Python script".to_string(),
            DataPattern::JavaScriptCode => "JavaScript code".to_string(),
            DataPattern::ShellScript => "Shell script".to_string(),
            DataPattern::CompressedGzip => "Gzip compressed data".to_string(),
            DataPattern::CompressedZlib => "Zlib compressed data".to_string(),
            DataPattern::CompressedBzip2 => "Bzip2 compressed data".to_string(),
            DataPattern::Base64Encoded => "Base64 encoded data".to_string(),
            DataPattern::HexEncoded => "Hex encoded data".to_string(),
            DataPattern::BinaryFile(t) => format!("Binary file ({})", t),
            DataPattern::ProofOfBurn => "Proof-of-burn pattern".to_string(),
            DataPattern::StructuredBurn(p) => format!("Structured burn: {}", p),
            DataPattern::UnknownData => "Unknown data format".to_string(),
        }
    }
}

/// Decoded data storage result
#[derive(Debug)]
pub struct DecodedDataStorage {
    pub txid: String,
    pub pattern: DataPattern,
    pub raw_data: Vec<u8>,
    pub decoded_data: Vec<u8>,
    pub metadata: DataStorageMetadata,
}

/// Metadata about decoded data
#[derive(Debug)]
pub struct DataStorageMetadata {
    pub total_pubkeys: usize,
    pub data_segments: usize,
    pub raw_size: usize,
    pub decoded_size: usize,
    pub multi_output: bool,
    pub burn_patterns: Vec<String>,
}

/// DataStorage decoder implementation
pub struct DataStorageDecoder {
    output_dir: PathBuf,
}

impl DataStorageDecoder {
    /// Maximum distance into the payload we'll scan for compression signatures.
    /// Real transactions sometimes prepend a small prefix (few bytes), but larger offsets risk
    /// false positives when scanning arbitrary binary data.
    const MAX_COMPRESSION_SIGNATURE_OFFSET: usize = 32;

    fn find_gzip_header(data: &[u8]) -> Option<usize> {
        if data.len() < 2 {
            return None;
        }

        data.windows(2)
            .position(|w| w[0] == 0x1f && w[1] == 0x8b)
            .and_then(|pos| {
                if pos <= Self::MAX_COMPRESSION_SIGNATURE_OFFSET {
                    Some(pos)
                } else {
                    None
                }
            })
    }

    fn find_zlib_header(data: &[u8]) -> Option<usize> {
        if data.len() < 2 {
            return None;
        }

        data.windows(2)
            .position(|w| {
                let cmf = w[0];
                let flg = w[1];
                if cmf == 0x78 {
                    let cmf_flg = (cmf as u16) * 256 + (flg as u16);
                    cmf_flg % 31 == 0
                } else {
                    false
                }
            })
            .and_then(|pos| {
                if pos <= Self::MAX_COMPRESSION_SIGNATURE_OFFSET {
                    Some(pos)
                } else {
                    None
                }
            })
    }

    fn find_bzip2_header(data: &[u8]) -> Option<usize> {
        if data.len() < 4 {
            return None;
        }

        data.windows(4)
            .position(|w| {
                w[0] == 0x42 && w[1] == 0x5a && w[2] == 0x68 && (0x31..=0x39).contains(&w[3])
            })
            .and_then(|pos| {
                if pos <= Self::MAX_COMPRESSION_SIGNATURE_OFFSET {
                    Some(pos)
                } else {
                    None
                }
            })
    }

    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }

    /// Main decode function - tries to detect and decode DataStorage patterns
    pub fn decode(&self, tx_data: &TransactionData) -> Option<DecodedDataStorage> {
        debug!("Attempting DataStorage decode for {}", tx_data.txid);

        let p2ms_outputs = tx_data.p2ms_outputs();
        if p2ms_outputs.is_empty() {
            return None;
        }

        // Extract all data from pubkeys
        let (raw_data, mut metadata) = self.extract_all_data(&p2ms_outputs);

        if raw_data.is_empty() {
            debug!("No data extracted from pubkeys");
            return None;
        }

        debug!(
            "Extracted {} bytes from {} pubkeys",
            raw_data.len(),
            metadata.total_pubkeys
        );

        // Display visual interpretations for inspection
        self.display_data_interpretations(&raw_data);

        // Detect the data pattern
        let pattern = self.detect_pattern(&raw_data);
        debug!("Detected pattern: {:?}", pattern);

        // Only proceed if we found a meaningful pattern
        // Reject UnknownData and pure burn patterns
        match &pattern {
            DataPattern::UnknownData => {
                debug!("Unknown data pattern - not meaningful, skipping");
                return None;
            }
            DataPattern::ProofOfBurn | DataPattern::StructuredBurn(_) => {
                debug!("Only burn patterns found - not meaningful data storage");
                return None;
            }
            _ => {
                // We have a meaningful pattern, proceed with decoding
            }
        }

        // Additional validation: Check if the data has enough entropy/structure
        if !self.is_meaningful_data(&raw_data, &pattern) {
            debug!("Data does not appear meaningful - likely random bytes");
            return None;
        }

        // Decode based on pattern
        let mut decoded_data = self.decode_by_pattern(&raw_data, &pattern);

        if let DataPattern::BinaryFile(file_type) = &pattern {
            if file_type.eq_ignore_ascii_case("PDF") {
                decoded_data = Self::normalise_pdf(decoded_data);
            }
        }

        metadata.decoded_size = decoded_data.len();

        // Final check: After decoding, verify we have something useful
        if decoded_data.is_empty() {
            debug!("Decoding produced no data - skipping");
            return None;
        }

        info!(
            "✅ DataStorage decoded in {}: {} ({} bytes -> {} bytes)",
            tx_data.txid,
            pattern.description(),
            raw_data.len(),
            decoded_data.len()
        );

        Some(DecodedDataStorage {
            txid: tx_data.txid.clone(),
            pattern,
            raw_data: raw_data.clone(),
            decoded_data,
            metadata,
        })
    }

    /// Extract data from all pubkeys in P2MS outputs
    ///
    /// CRITICAL: For binary files (PDF, images, archives), we MUST concatenate
    /// ALL outputs first, then detect patterns. Breaking early on first pattern
    /// detection results in incomplete/corrupted files.
    fn extract_all_data(&self, outputs: &[TransactionOutput]) -> (Vec<u8>, DataStorageMetadata) {
        let mut all_data = Vec::new();
        let mut total_pubkeys = 0;
        let mut burn_patterns = Vec::new();

        // Extract and concatenate ALL data from ALL outputs
        // Don't break early - binary files need complete data
        for output in outputs {
            if let Some(info) = output.multisig_info() {
                for pubkey_hex in &info.pubkeys {
                    total_pubkeys += 1;

                    if let Some(data) = extract_key_data(pubkey_hex) {
                        debug!(
                            "Extracted {} bytes from pubkey: {}",
                            data.len(),
                            &pubkey_hex[..16]
                        );

                        // Check for burn patterns
                        if is_burn_pattern(&data, Some(pubkey_hex)) {
                            burn_patterns.push(format!(
                                "Burn in vout {}: {}",
                                output.vout,
                                &pubkey_hex[..16]
                            ));
                            continue;
                        }

                        // Append data exactly as embedded; stripping bytes causes corruption for
                        // multi-output binaries like the Bitcoin whitepaper.
                        all_data.extend_from_slice(&data);
                    }
                }
            }
        }

        debug!(
            "Extracted total {} bytes from {} pubkeys across {} outputs",
            all_data.len(),
            total_pubkeys,
            outputs.len()
        );

        let metadata = DataStorageMetadata {
            total_pubkeys,
            data_segments: outputs.len(),
            raw_size: all_data.len(),
            decoded_size: all_data.len(), // Will be updated after decoding
            multi_output: outputs.len() > 1,
            burn_patterns,
        };

        (all_data, metadata)
    }

    /// Display various interpretations of the data for visual inspection
    fn display_data_interpretations(&self, data: &[u8]) {
        info!("🔍 DataStorage Visual Inspection ({} bytes):", data.len());
        info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // Hex representation (first 256 bytes)
        let hex_limit = std::cmp::min(256, data.len());
        let hex_str: String = data[..hex_limit]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .chunks(32)
            .map(|chunk| chunk.join(" "))
            .collect::<Vec<_>>()
            .join("\n    ");
        info!("📋 Hex (first {} bytes):\n    {}", hex_limit, hex_str);

        // UTF-8 interpretation (attempt to decode, show valid parts)
        info!("\n📝 UTF-8 Interpretation:");
        match std::str::from_utf8(data) {
            Ok(text) => {
                let preview = if text.len() > 500 {
                    format!("{}... [truncated]", &text[..500])
                } else {
                    text.to_string()
                };
                info!("    ✅ Valid UTF-8: {}", preview);
            }
            Err(_) => {
                // Try lossy UTF-8 conversion
                let text = String::from_utf8_lossy(data);
                let preview = if text.len() > 500 {
                    // Find a valid character boundary near position 500
                    let mut truncate_at = 500.min(text.len());
                    while truncate_at > 0 && !text.is_char_boundary(truncate_at) {
                        truncate_at -= 1;
                    }
                    format!("{}... [truncated]", &text[..truncate_at])
                } else {
                    text.to_string()
                };
                info!("    ⚠️  Lossy UTF-8 (� = invalid bytes): {}", preview);
            }
        }

        // Latin-1 (ISO-8859-1) interpretation
        info!("\n📜 Latin-1 (ISO-8859-1) Interpretation:");
        let latin1: String = data
            .iter()
            .take(500)
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' || b >= 0xA0 {
                    b as char // Printable ASCII or Latin-1 extended
                } else {
                    '·' // Non-printable placeholder
                }
            })
            .collect();
        info!(
            "    {}{}",
            latin1,
            if data.len() > 500 {
                "... [truncated]"
            } else {
                ""
            }
        );

        // ASCII interpretation (printable chars only)
        info!("\n🔤 ASCII Interpretation (printable only):");
        let ascii: String = data
            .iter()
            .take(500)
            .map(|&b| {
                if (0x20..=0x7E).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        info!(
            "    {}{}",
            ascii,
            if data.len() > 500 {
                "... [truncated]"
            } else {
                ""
            }
        );

        // Character frequency analysis
        let mut char_counts = std::collections::HashMap::new();
        for &byte in data {
            *char_counts.entry(byte).or_insert(0) += 1;
        }
        let mut sorted_chars: Vec<_> = char_counts.iter().collect();
        sorted_chars.sort_by(|a, b| b.1.cmp(a.1));

        info!("\n📊 Top 10 Most Frequent Bytes:");
        for (byte, count) in sorted_chars.iter().take(10) {
            let char_repr = if **byte >= 0x20 && **byte <= 0x7E {
                format!("'{}'", **byte as char)
            } else {
                "   ".to_string()
            };
            info!(
                "    0x{:02x} {} : {} occurrences ({:.1}%)",
                byte,
                char_repr,
                count,
                (**count as f64 / data.len() as f64) * 100.0
            );
        }

        info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    /// Normalise extracted PDF payloads by trimming protocol padding before the `%PDF`
    /// header and any trailing padding after the `%%EOF` marker. Some on-chain encodings
    /// inject random bytes to satisfy pubkey formatting, so we strip those to recover the
    /// canonical PDF byte sequence.
    fn normalise_pdf(mut data: Vec<u8>) -> Vec<u8> {
        const PDF_MAGIC: &[u8] = b"%PDF";
        const PDF_EOF: &[u8] = b"%%EOF";

        if let Some(start) = data.windows(PDF_MAGIC.len()).position(|w| w == PDF_MAGIC) {
            if start > 0 {
                debug!("Trimming {} leading byte(s) before PDF magic header", start);
                data = data[start..].to_vec();
            }
        } else {
            debug!("PDF magic header not found during normalisation");
        }

        if let Some(eof_pos) = data.windows(PDF_EOF.len()).rposition(|w| w == PDF_EOF) {
            let mut end = eof_pos + PDF_EOF.len();
            while end < data.len() && matches!(data[end], b'\r' | b'\n') {
                end += 1;
            }
            let mut trimmed = data[..end].to_vec();
            let mut removed_nulls = 0usize;
            while trimmed.last().copied() == Some(0x00) {
                trimmed.pop();
                removed_nulls += 1;
            }
            if removed_nulls > 0 {
                debug!(
                    "Removed {} trailing padding byte(s) after PDF EOF marker",
                    removed_nulls
                );
            }
            data = trimmed;
        } else {
            debug!("PDF EOF marker not found during normalisation");
        }

        data
    }

    /// Check if data appears to be meaningful (not just random bytes)
    fn is_meaningful_data(&self, data: &[u8], pattern: &DataPattern) -> bool {
        // For known patterns, trust the detection
        match pattern {
            DataPattern::JsonData
            | DataPattern::XmlData
            | DataPattern::PythonScript
            | DataPattern::JavaScriptCode
            | DataPattern::ShellScript
            | DataPattern::CompressedGzip
            | DataPattern::CompressedZlib
            | DataPattern::CompressedBzip2
            | DataPattern::BinaryFile(_) => {
                // These patterns have already been validated
                return true;
            }
            _ => {}
        }

        // For PlainText, Base64, Hex - do additional validation
        // Check for minimum entropy/structure

        // 1. Check if data is too repetitive (low entropy)
        if self.is_highly_repetitive(data) {
            return false;
        }

        // 2. For text data, check if it has reasonable content
        if matches!(pattern, DataPattern::PlainText) {
            if let Ok(text) = std::str::from_utf8(data) {
                // Must have some meaningful content, not just whitespace
                let non_whitespace = text.chars().filter(|c| !c.is_whitespace()).count();
                if non_whitespace < 10 {
                    return false;
                }

                // Should have reasonable character distribution
                let printable = text.chars().filter(|c| c.is_ascii_graphic()).count();
                if printable < text.len() / 2 {
                    return false;
                }
            }
        }

        // 3. For encoded data, try to decode and check result
        match pattern {
            DataPattern::Base64Encoded => {
                // Try to decode and see if result is meaningful
                if let Some(decoded) = self.decode_base64(data) {
                    // Check if decoded data has structure
                    return !self.is_highly_repetitive(&decoded);
                }
                return false;
            }
            DataPattern::HexEncoded => {
                if let Some(decoded) = self.decode_hex_string(data) {
                    return !self.is_highly_repetitive(&decoded);
                }
                return false;
            }
            _ => {}
        }

        true
    }

    /// Check if data is highly repetitive (low entropy)
    fn is_highly_repetitive(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return true;
        }

        // Count unique bytes
        let mut unique_bytes = HashSet::new();
        for &byte in data.iter().take(256) {
            unique_bytes.insert(byte);
        }

        // If less than 10% unique bytes, it's too repetitive
        let uniqueness_ratio = unique_bytes.len() as f32 / data.len().min(256) as f32;
        if uniqueness_ratio < 0.1 {
            return true;
        }

        // Check for repeating patterns
        // If first 32 bytes repeat throughout, it's repetitive
        if data.len() >= 64 {
            let pattern = &data[..32];
            let mut matches = 0;
            for chunk in data[32..].chunks(32) {
                if chunk.len() == 32 && chunk == pattern {
                    matches += 1;
                }
            }
            // If more than 50% of chunks match the first pattern, it's repetitive
            if matches > (data.len() / 64) {
                return true;
            }
        }

        false
    }

    /// Detect the pattern of the extracted data
    pub fn detect_pattern(&self, data: &[u8]) -> DataPattern {
        // Debug logging to understand what data we're analysing
        debug!("detect_pattern: Analysing {} bytes", data.len());
        if !data.is_empty() && data.len() <= 200 {
            let hex_str = hex::encode(data);
            debug!("detect_pattern: Full data (hex): {}", hex_str);
        }

        // Also try to show ASCII preview
        let ascii: String = data
            .iter()
            .map(|&b| {
                if (0x20..=0x7E).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        debug!("detect_pattern: ASCII preview: {}", ascii);
        // Check for compressed data first (binary signatures)
        if let Some(pattern) = self.detect_compression(data) {
            return pattern;
        }

        // Check for text-based patterns
        if let Ok(text) = std::str::from_utf8(data) {
            // Check for specific text patterns
            if self.is_json(text) {
                return DataPattern::JsonData;
            }

            if self.is_python_script(text) {
                return DataPattern::PythonScript;
            }

            if self.is_javascript(text) {
                return DataPattern::JavaScriptCode;
            }

            if self.is_shell_script(text) {
                return DataPattern::ShellScript;
            }

            if self.is_xml(text) {
                return DataPattern::XmlData;
            }

            // Check if it's mostly printable ASCII
            if self.is_valid_text(text) {
                return DataPattern::PlainText;
            }
        }

        // Check for encoded data
        if self.looks_like_base64(data) {
            return DataPattern::Base64Encoded;
        }

        if self.looks_like_hex_string(data) {
            return DataPattern::HexEncoded;
        }

        // Check for binary file signatures
        if let Some(file_type) = detect_binary_signature(data) {
            return DataPattern::BinaryFile(file_type.to_string());
        }

        DataPattern::UnknownData
    }

    /// Detect compression type from magic bytes
    fn detect_compression(&self, data: &[u8]) -> Option<DataPattern> {
        if data.len() < 2 {
            return None;
        }

        // Gzip magic: 0x1f 0x8b -- allow small prefix but avoid false positives deep in payloads
        if Self::find_gzip_header(data).is_some() {
            return Some(DataPattern::CompressedGzip);
        }

        // Zlib: 0x78 followed by FLG byte
        // Common combinations:
        //   0x78 0x9c - default compression
        //   0x78 0x5e - moderate compression (CRITICAL for Linpyro/WikiLeaks!)
        //   0x78 0x01 - no compression
        //   0x78 0xda - best compression
        // Verify FLG byte checksum: (CMF * 256 + FLG) must be divisible by 31
        if Self::find_zlib_header(data).is_some() {
            return Some(DataPattern::CompressedZlib);
        }

        // Bzip2 magic: "BZh" (0x42 0x5a 0x68) + block size 1-9
        if Self::find_bzip2_header(data).is_some() {
            return Some(DataPattern::CompressedBzip2);
        }

        None
    }

    /// Check if text is valid JSON
    fn is_json(&self, text: &str) -> bool {
        // Quick check for JSON-like structure
        let trimmed = text.trim();
        if (trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        {
            // Try to parse as JSON
            serde_json::from_str::<JsonValue>(text).is_ok()
        } else {
            false
        }
    }

    /// Check if text looks like Python code
    fn is_python_script(&self, text: &str) -> bool {
        let python_keywords = [
            "import ",
            "from ",
            "def ",
            "class ",
            "if __name__",
            "return ",
            "yield ",
            "lambda ",
            "async def",
            "await ",
            "try:",
            "except:",
            "finally:",
            "with ",
            "raise ",
        ];

        let mut keyword_count = 0;
        for keyword in &python_keywords {
            if text.contains(keyword) {
                keyword_count += 1;
            }
        }

        // Also check for Python-specific patterns
        keyword_count >= 2
            || (text.contains("#!/usr/bin/env python")
                || text.contains("#!/usr/bin/python")
                || text.contains("# -*- coding:"))
    }

    /// Check if text looks like JavaScript
    fn is_javascript(&self, text: &str) -> bool {
        let js_keywords = [
            "function ",
            "const ",
            "let ",
            "var ",
            "return ",
            "async ",
            "await ",
            "class ",
            "extends ",
            "import ",
            "export ",
            "require(",
            "console.",
            "window.",
            "document.",
            "=> ",
            "===",
            "!==",
            "typeof ",
        ];

        let mut keyword_count = 0;
        for keyword in &js_keywords {
            if text.contains(keyword) {
                keyword_count += 1;
            }
        }

        keyword_count >= 2
    }

    /// Check if text looks like a shell script
    fn is_shell_script(&self, text: &str) -> bool {
        text.starts_with("#!/bin/bash")
            || text.starts_with("#!/bin/sh")
            || text.starts_with("#!/usr/bin/env bash")
            || (text.contains("echo ") && text.contains("if ["))
            || (text.contains("for ") && text.contains("do\n"))
    }

    /// Check if text is XML
    fn is_xml(&self, text: &str) -> bool {
        let trimmed = text.trim();
        (trimmed.starts_with("<?xml") || trimmed.starts_with("<"))
            && trimmed.contains('>')
            && text.contains("</")
    }

    /// Check if text is mostly valid/printable and contains actual words
    fn is_valid_text(&self, text: &str) -> bool {
        // First check basic printability
        let printable_count = text
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count();

        if printable_count < text.len() * 3 / 4 {
            return false; // Less than 75% printable
        }

        // Check if it's just hex characters (not meaningful text)
        let is_all_hex = text
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c.is_whitespace() || c == 'x' || c == '0');

        if is_all_hex && text.len() > 20 {
            // Likely just hex data, not meaningful text
            return false;
        }

        // Look for actual word-like patterns
        // Must contain at least some letters and word boundaries
        let has_letters = text.chars().filter(|c| c.is_alphabetic()).count() >= 5;

        // Check for common English words or patterns
        let text_lower = text.to_lowercase();
        let has_common_words = [
            "the", "and", "for", "are", "but", "not", "you", "with", "have", "this", "from",
            "they", "will", "would", "there", "their", "what", "about", "which", "when", "make",
            "can", "time", "just", "know", "take", "person", "year", "good", "some", "could",
            "them", "than", "other", "then", "now", "look", "only", "come", "over", "also", "back",
            "after", "use", "two", "how", "work", "well", "way", "even", "new", "want", "because",
            "any", "these", "give", "most", "http", "www", "com", "org", "bitcoin", "data", "file",
        ]
        .iter()
        .any(|word| text_lower.contains(word));

        // Must have letters AND (common words OR be very short)
        has_letters && (has_common_words || text.len() < 50)
    }

    /// Check if data looks like base64
    fn looks_like_base64(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        // Check if all bytes are valid base64 characters
        data.iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    }

    /// Check if data looks like a hex string
    fn looks_like_hex_string(&self, data: &[u8]) -> bool {
        if data.len() < 2 || data.len() % 2 != 0 {
            return false;
        }

        data.iter().all(|&b| b.is_ascii_hexdigit())
    }

    /// Decode data based on detected pattern
    pub fn decode_by_pattern(&self, data: &[u8], pattern: &DataPattern) -> Vec<u8> {
        let decoded = match pattern {
            DataPattern::CompressedGzip => {
                self.decompress_gzip(data).unwrap_or_else(|| data.to_vec())
            }
            DataPattern::CompressedZlib => {
                self.decompress_zlib(data).unwrap_or_else(|| data.to_vec())
            }
            DataPattern::CompressedBzip2 => {
                self.decompress_bzip2(data).unwrap_or_else(|| data.to_vec())
            }
            DataPattern::Base64Encoded => self.decode_base64(data).unwrap_or_else(|| data.to_vec()),
            DataPattern::HexEncoded => self
                .decode_hex_string(data)
                .unwrap_or_else(|| data.to_vec()),
            _ => data.to_vec(), // For text and binary patterns, return as-is
        };

        // After decompression, check for nested archives
        if matches!(
            pattern,
            DataPattern::CompressedGzip
                | DataPattern::CompressedZlib
                | DataPattern::CompressedBzip2
        ) {
            if let Some(nested_type) = self.detect_nested_pattern(&decoded) {
                info!(
                    "Detected nested archive: {} inside {:?}",
                    nested_type, pattern
                );
                // Note: Nested type logged for analysis, but not saved separately yet
                // Future enhancement: Update metadata to track nested archive types
            }
        }

        decoded
    }

    /// Detect nested archive formats after decompression
    ///
    /// After decompressing gzip/zlib/bzip2, check if the result is another archive format.
    /// This handles common nested patterns like:
    /// - .tar.gz (gzipped tar)
    /// - .tar.bz2 (bzip2'd tar)
    /// - .7z.gz (gzipped 7z)
    fn detect_nested_pattern(&self, decompressed: &[u8]) -> Option<String> {
        // Check for TAR (ustar magic at offset 257)
        if decompressed.len() >= 263 {
            let tar_magic = &decompressed[257..262];
            if tar_magic == b"ustar" && (decompressed[262] == 0x00 || decompressed[262] == b' ') {
                return Some("TAR".to_string());
            }
        }

        // Check for 7-Zip
        if decompressed.len() >= 6
            && decompressed.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
        {
            return Some("7Z".to_string());
        }

        // Check for ZIP
        if decompressed.starts_with(&[0x50, 0x4b, 0x03, 0x04]) {
            return Some("ZIP".to_string());
        }

        None
    }

    /// Decompress gzip data
    fn decompress_gzip(&self, data: &[u8]) -> Option<Vec<u8>> {
        let start = Self::find_gzip_header(data)?;
        if start > 0 {
            debug!(
                "Trimming {} leading byte(s) before gzip header for decompression",
                start
            );
        }
        let slice = &data[start..];
        let mut decoder = GzDecoder::new(slice);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).ok()?;
        Some(decompressed)
    }

    /// Decompress zlib data
    fn decompress_zlib(&self, data: &[u8]) -> Option<Vec<u8>> {
        let start = Self::find_zlib_header(data)?;
        if start > 0 {
            debug!(
                "Trimming {} leading byte(s) before zlib header for decompression",
                start
            );
        }
        let slice = &data[start..];
        let mut decoder = ZlibDecoder::new(slice);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).ok()?;
        Some(decompressed)
    }

    /// Decompress bzip2 data
    fn decompress_bzip2(&self, data: &[u8]) -> Option<Vec<u8>> {
        let start = Self::find_bzip2_header(data)?;
        if start > 0 {
            debug!(
                "Trimming {} leading byte(s) before bzip2 header for decompression",
                start
            );
        }
        let slice = &data[start..];
        let mut decoder = BzDecoder::new(slice);
        let mut decompressed = Vec::new();
        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => {
                debug!(
                    "Successfully decompressed {} bytes of bzip2 data",
                    decompressed.len()
                );
                Some(decompressed)
            }
            Err(e) => {
                warn!("Failed to decompress bzip2 data: {}", e);
                None
            }
        }
    }

    /// Decode base64 data
    fn decode_base64(&self, data: &[u8]) -> Option<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.decode(data).ok()
    }

    /// Decode hex string
    fn decode_hex_string(&self, data: &[u8]) -> Option<Vec<u8>> {
        let text = std::str::from_utf8(data).ok()?;
        hex::decode(text).ok()
    }

    /// Save decoded data to appropriate output directory
    pub fn save_decoded_data(&self, decoded: &DecodedDataStorage) -> std::io::Result<PathBuf> {
        // Determine subdirectory based on pattern
        let subdir = match &decoded.pattern {
            DataPattern::JsonData => "json",
            DataPattern::PythonScript => "scripts",
            DataPattern::JavaScriptCode => "scripts",
            DataPattern::ShellScript => "scripts",
            DataPattern::PlainText => "text",
            DataPattern::XmlData => "xml",
            DataPattern::CompressedGzip
            | DataPattern::CompressedZlib
            | DataPattern::CompressedBzip2 => "compressed",
            DataPattern::BinaryFile(_) => "binary",
            DataPattern::ProofOfBurn | DataPattern::StructuredBurn(_) => "burns",
            _ => "other",
        };

        let output_dir = self
            .output_dir
            .join(output_paths::PROTOCOL_DATASTORAGE)
            .join(subdir);
        std::fs::create_dir_all(&output_dir)?;

        let filename = format!("{}.{}", decoded.txid, decoded.pattern.file_extension());
        let output_path = output_dir.join(filename);

        std::fs::write(&output_path, &decoded.decoded_data)?;

        // Also save metadata
        let metadata_path = output_dir.join(format!("{}.metadata.json", decoded.txid));
        let metadata_json = serde_json::json!({
            "txid": decoded.txid,
            "pattern": format!("{:?}", decoded.pattern),
            "description": decoded.pattern.description(),
            "total_pubkeys": decoded.metadata.total_pubkeys,
            "data_segments": decoded.metadata.data_segments,
            "raw_size": decoded.metadata.raw_size,
            "decoded_size": decoded.metadata.decoded_size,
            "multi_output": decoded.metadata.multi_output,
            "burn_patterns": decoded.metadata.burn_patterns,
        });

        std::fs::write(metadata_path, serde_json::to_string_pretty(&metadata_json)?)?;

        info!("Saved decoded DataStorage to: {}", output_path.display());
        Ok(output_path)
    }
}

/// Try to decode a transaction as DataStorage
pub fn try_datastorage(tx_data: &TransactionData, output_dir: &Path) -> Option<DecodedProtocol> {
    debug!("Attempting DataStorage decoding for txid: {}", tx_data.txid);
    let decoder = DataStorageDecoder::new(output_dir.to_path_buf());

    if let Some(decoded) = decoder.decode(tx_data) {
        debug!("DataStorage decoding successful for txid: {}", tx_data.txid);
        // Save the decoded data
        if let Err(e) = decoder.save_decoded_data(&decoded) {
            warn!("Failed to save decoded data: {}", e);
        }

        return Some(DecodedProtocol::DataStorage {
            txid: decoded.txid,
            pattern: format!("{:?}", decoded.pattern),
            decoded_data: decoded.decoded_data,
            metadata: serde_json::json!({
                "pattern": decoded.pattern.description(),
                "raw_size": decoded.metadata.raw_size,
                "decoded_size": decoded.metadata.decoded_size,
                "total_pubkeys": decoded.metadata.total_pubkeys,
            }),
            debug_info: None,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test bzip2 decompression with valid compressed data
    #[test]
    fn test_bzip2_decompression_valid() {
        use crate::config::output_paths;
        let decoder = DataStorageDecoder::new(output_paths::decoded_base());

        // Create valid bzip2 compressed data: "Hello World"
        // This is actual bzip2-compressed data created with: echo -n "Hello World" | bzip2 | xxd -p
        let compressed = hex::decode(
            "425a6839314159265359065c89da0000009780400000400080060490002000310c082031a916c41d41e2ee48a70a1200cb913b40"
        ).unwrap();

        let result = decoder.decompress_bzip2(&compressed);
        assert!(result.is_some(), "Bzip2 decompression should succeed");

        let decompressed = result.unwrap();
        assert_eq!(std::str::from_utf8(&decompressed).unwrap(), "Hello World");
    }

    /// Test bzip2 decompression with invalid/corrupt data
    #[test]
    fn test_bzip2_decompression_invalid() {
        use crate::config::output_paths;
        let decoder = DataStorageDecoder::new(output_paths::decoded_base());

        // Invalid bzip2 data (just random bytes)
        let invalid_data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

        let result = decoder.decompress_bzip2(&invalid_data);
        assert!(result.is_none(), "Invalid data should return None");
    }

    /// Test bzip2 decompression with empty input
    #[test]
    fn test_bzip2_decompression_empty() {
        use crate::config::output_paths;
        let decoder = DataStorageDecoder::new(output_paths::decoded_base());

        let empty_data = vec![];
        let result = decoder.decompress_bzip2(&empty_data);
        assert!(result.is_none(), "Empty data should return None");
    }

    /// Test bzip2 decompression with truncated data
    #[test]
    fn test_bzip2_decompression_truncated() {
        use crate::config::output_paths;
        let decoder = DataStorageDecoder::new(output_paths::decoded_base());

        // Truncated bzip2 header (incomplete)
        let truncated = vec![0x42, 0x5a, 0x68]; // "BZh" magic but incomplete

        let result = decoder.decompress_bzip2(&truncated);
        assert!(result.is_none(), "Truncated data should return None");
    }

    /// Test bzip2 pattern detection
    #[test]
    fn test_bzip2_pattern_detection() {
        use crate::config::output_paths;
        let decoder = DataStorageDecoder::new(output_paths::decoded_base());

        // Valid bzip2 magic number
        let bzip2_data = vec![0x42, 0x5a, 0x68, 0x39]; // "BZh9"
        let pattern = decoder.detect_pattern(&bzip2_data);
        assert_eq!(pattern, DataPattern::CompressedBzip2);
    }

    /// Test that bzip2 magic number is correctly identified
    #[test]
    fn test_bzip2_magic_number() {
        use crate::config::output_paths;
        let decoder = DataStorageDecoder::new(output_paths::decoded_base());

        // Bzip2 starts with "BZ" (0x42 0x5a)
        let valid_bzip2 = vec![0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59];
        let pattern = decoder.detect_pattern(&valid_bzip2);
        assert_eq!(
            pattern,
            DataPattern::CompressedBzip2,
            "Valid bzip2 magic should be detected"
        );

        // Not bzip2
        let not_bzip2 = vec![0x42, 0x00, 0x68, 0x39];
        let pattern = decoder.detect_pattern(&not_bzip2);
        assert_ne!(
            pattern,
            DataPattern::CompressedBzip2,
            "Invalid magic should not be detected as bzip2"
        );
    }
}
