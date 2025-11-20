use crate::database::Database;
use crate::types::content_detection::ContentType;
use crate::types::{
    ClassificationResult, EnrichedTransaction, ProtocolType, ProtocolVariant, Stage3Config,
};
use std::time::{SystemTime, UNIX_EPOCH};

use super::filter_p2ms_for_classification;
use super::spendability::SpendabilityAnalyser;
use super::{ProtocolSpecificClassifier, SignatureDetector};

/// DataStorage classifier - detects various data embedding patterns in P2MS outputs
pub struct DataStorageClassifier {
    _config: Stage3Config, // For future use if needed
}

impl DataStorageClassifier {
    pub fn new(config: &Stage3Config) -> Self {
        Self {
            _config: config.clone(),
        }
    }

    /// Extract data from public key slots for DataStorage pattern detection
    ///
    /// Unlike protocol-specific classifiers, DataStorage accepts ANY data in pubkey slots
    /// since we're looking for generic data embedding patterns, not valid EC points.
    ///
    /// This handles:
    /// - Standard 33-byte compressed pubkeys (with or without valid prefix)
    /// - Standard 65-byte uncompressed pubkeys (with or without 0x04 prefix)
    /// - Raw 32-byte data chunks (no prefix)
    /// - Non-standard length data (e.g., PDF chunks, custom encoding)
    fn extract_key_data(pubkey_hex: &str) -> Option<Vec<u8>> {
        let pubkey_bytes = hex::decode(pubkey_hex).ok()?;

        match pubkey_bytes.len() {
            33 => {
                // 33-byte chunks: could be compressed pubkey OR raw data
                // Extract all 33 bytes for analysis (don't filter by prefix)
                Some(pubkey_bytes.to_vec())
            }
            65 => {
                // 65-byte chunks: could be uncompressed pubkey OR raw data
                // Extract all 65 bytes for analysis (don't filter by prefix)
                Some(pubkey_bytes.to_vec())
            }
            32 => {
                // 32-byte chunks (sometimes used without prefix)
                Some(pubkey_bytes.to_vec())
            }
            _ if pubkey_bytes.len() >= 10 => {
                // Accept any reasonable-length data (>=10 bytes)
                // This handles non-standard push sizes (e.g., PDF chunks)
                Some(pubkey_bytes.to_vec())
            }
            _ => None, // Too short to be meaningful data
        }
    }

    /// Check if data is a proof-of-burn pattern (all 0xFF bytes)
    ///
    /// Handles both:
    /// - Pure 32-byte 0xFF data (old extraction method)
    /// - 33-byte compressed key with prefix (0x02/0x03) + 32 bytes of 0xFF
    /// - 65-byte uncompressed key with prefix (0x04) + 64 bytes of 0xFF
    fn is_proof_of_burn(data: &[u8]) -> bool {
        match data.len() {
            32 => {
                // Pure 32-byte 0xFF pattern
                data.iter().all(|&b| b == 0xFF)
            }
            33 => {
                // Compressed pubkey: prefix (0x02 or 0x03) + 32 bytes of 0xFF
                (data[0] == 0x02 || data[0] == 0x03) && data[1..].iter().all(|&b| b == 0xFF)
            }
            65 => {
                // Uncompressed pubkey: prefix (0x04) + 64 bytes of 0xFF
                data[0] == 0x04 && data[1..].iter().all(|&b| b == 0xFF)
            }
            _ => false,
        }
    }

    /// Check if data contains valid UTF-8/ASCII text
    fn is_valid_text_data(data: &[u8]) -> bool {
        // Use lossy UTF-8 conversion to handle mixed binary/text data
        // Invalid UTF-8 bytes are replaced with � but valid ASCII is preserved
        let text = String::from_utf8_lossy(data);

        // Count characters (not bytes!) for proper ratio calculation
        // BUG FIX: text.len() returns BYTE count, not character count!
        // Replacement characters (�) are 3 bytes each in UTF-8, which inflates the denominator.
        // Must use chars().count() to get actual character count.
        let char_count = text.chars().count();

        // Must contain at least some printable ASCII characters
        let printable_count = text
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count();

        // At least 50% of characters should be printable ASCII and minimum length
        printable_count >= char_count / 2 && char_count >= 4
    }

    /// Check if data contains file metadata patterns
    fn contains_file_metadata(data: &[u8]) -> bool {
        // Use lossy UTF-8 conversion to handle mixed binary/text data
        // This allows detection of URLs/filenames even when surrounded by binary data
        let text = String::from_utf8_lossy(data);
        let text_lower = text.to_lowercase();

        // Look for file extensions or metadata patterns
        text_lower.contains(".7z")
            || text_lower.contains(".zip")
            || text_lower.contains(".rar")
            || text_lower.contains(".tar")
            || text_lower.contains(".gz")
            || text_lower.contains("backup")
            || text_lower.contains("download")
            || text_lower.contains("file")
            || text_lower.contains("wikileaks")
            || text_lower.contains("magnet:")
            || text_lower.contains("http://")
            || text_lower.contains("https://")
    }

    /// Detect binary file signatures in raw data
    ///
    /// Checks for magic bytes of common file formats embedded in P2MS outputs.
    /// Returns the file type if a signature is found.
    fn detect_binary_signature(data: &[u8]) -> Option<&'static str> {
        if data.len() < 4 {
            return None;
        }

        // PDF: %PDF (0x25 0x50 0x44 0x46)
        // Search in windows since PDF header might not be at start of chunk
        if SignatureDetector::has_at_any_offset(data, b"%PDF") {
            return Some("PDF");
        }

        // PNG: ‰PNG (0x89 0x50 0x4E 0x47)
        if data.len() >= 8 && SignatureDetector::has_prefix(data, &[0x89, 0x50, 0x4E, 0x47]) {
            return Some("PNG");
        }

        // JPEG: 0xFF 0xD8 0xFF
        if SignatureDetector::has_prefix(data, &[0xFF, 0xD8, 0xFF]) {
            return Some("JPEG");
        }

        // GIF: GIF8 (GIF87a or GIF89a)
        if SignatureDetector::has_prefix(data, b"GIF8") {
            return Some("GIF");
        }

        // ZIP/JAR/DOCX: PK (0x50 0x4B)
        if SignatureDetector::has_prefix(data, &[0x50, 0x4B]) {
            return Some("ZIP");
        }

        // RAR: Rar! (0x52 0x61 0x72 0x21)
        if SignatureDetector::has_prefix(data, b"Rar!") {
            return Some("RAR");
        }

        // 7-Zip: 7z (0x37 0x7A 0xBC 0xAF)
        if data.len() >= 6 && SignatureDetector::has_prefix(data, &[0x37, 0x7A, 0xBC, 0xAF]) {
            return Some("7Z");
        }

        // GZIP: 0x1f 0x8b 0x08 (most common)
        // Note: Third byte is compression method (0x08 = DEFLATE)
        // Search in windows since GZIP header might not be at start of chunk
        if SignatureDetector::has_at_any_offset(data, &[0x1f, 0x8b, 0x08]) {
            return Some("GZIP");
        }

        // BZIP2: BZh[1-9] (0x42 0x5a 0x68 followed by block size 1-9)
        // Note: Fourth byte indicates block size (100KB-900KB)
        if data.len() >= 4
            && data[0] == 0x42
            && data[1] == 0x5a
            && data[2] == 0x68
            && (0x31..=0x39).contains(&data[3])
        // '1'-'9' in ASCII
        {
            return Some("BZIP2");
        }

        // ZLIB: 0x78 followed by FLG byte
        // Common combinations:
        //   0x78 0x9c - default compression
        //   0x78 0x5e - moderate compression
        //   0x78 0x01 - no compression
        //   0x78 0xda - best compression
        // Verify FLG byte checksum: (CMF * 256 + FLG) must be divisible by 31
        // NOTE: Check offset 0 (standard), offset 5-6, and offset 7-8 (empirical patterns).
        // GZIP is detected first (which searches entire buffer), so this won't conflict.
        // Evidence: 10 Unknown outputs have ZLIB at offset 5, 10 at offset 7, all successfully decode.
        // Conservative approach: Only check known offsets to avoid false positives on text data.
        if data.len() >= 2 {
            // Check offset 0 (standard position)
            if data[0] == 0x78 {
                let cmf_flg = (data[0] as u16) * 256 + (data[1] as u16);
                if cmf_flg % 31 == 0 {
                    return Some("ZLIB");
                }
            }
        }

        // Check offset 5 (empirical pattern from Unknown outputs)
        if data.len() >= 7 && data[5] == 0x78 {
            let cmf_flg = (data[5] as u16) * 256 + (data[6] as u16);
            if cmf_flg % 31 == 0 {
                return Some("ZLIB");
            }
        }

        // Check offset 7 (empirical pattern from Unknown outputs)
        if data.len() >= 9 && data[7] == 0x78 {
            let cmf_flg = (data[7] as u16) * 256 + (data[8] as u16);
            if cmf_flg % 31 == 0 {
                return Some("ZLIB");
            }
        }

        // TAR: ustar magic at offset 257
        // POSIX standard: "ustar\0" or "ustar  " (with spaces)
        // Check both variants to avoid false positives
        if data.len() >= 263 && SignatureDetector::has_at_offset(data, 257, 262, b"ustar") {
            // Verify next byte is either NUL or space to distinguish from random data
            if data[262] == 0x00 || data[262] == b' ' {
                return Some("TAR");
            }
        }

        None
    }

    // Note: CHANCECO pattern detection removed - handled by dedicated
    // Chancecoin classifier which runs at higher priority

    /// Analyse all extracted data and return the most specific classification
    fn classify_data_patterns(&self, all_data: &[Vec<u8>]) -> Option<(ProtocolVariant, String)> {
        let mut found_binary_file = false;
        let mut file_type = None;
        let mut found_burn = false;
        let mut found_file_metadata = false;
        let mut found_text_data = false;
        let mut has_non_null_data = false;

        // First, check individual pubkey chunks for signatures that appear early (< 65 bytes)
        // This catches PDF, PNG, JPEG, GIF, ZIP, RAR, 7Z, GZIP, BZIP2, ZLIB
        for data in all_data {
            // Check if this data chunk has any non-zero bytes
            if data.iter().any(|&b| b != 0x00) {
                has_non_null_data = true;
            }

            // Check patterns - most specific first, then allow multiple flags for priority later
            // Binary file signatures are most specific (definitive file types)
            if let Some(sig) = Self::detect_binary_signature(data) {
                found_binary_file = true;
                file_type = Some(sig);
            } else if Self::is_proof_of_burn(data) {
                found_burn = true;
            } else {
                // Allow both text and file metadata flags to be set for the same data
                // Priority order is determined in the return statement below
                if Self::is_valid_text_data(data) {
                    found_text_data = true;
                }
                if Self::contains_file_metadata(data) {
                    found_file_metadata = true;
                }
            }
            // Note: CHANCECO pattern check removed - handled by Chancecoin classifier at higher priority
        }

        // Second, check concatenated data for formats requiring larger offsets (TAR at offset 257)
        // Only concatenate if we haven't found a signature yet (performance optimisation)
        if !found_binary_file && all_data.len() > 1 {
            let concatenated: Vec<u8> = all_data
                .iter()
                .flat_map(|chunk| chunk.iter())
                .copied()
                .collect();

            // Check for TAR archive (requires offset 257, so needs concatenated data)
            if let Some(sig) = Self::detect_binary_signature(&concatenated) {
                found_binary_file = true;
                file_type = Some(sig);
            }
        }

        // Return most specific pattern found (ordered by specificity)
        if found_binary_file {
            Some((
                ProtocolVariant::DataStorageEmbeddedData,
                format!("{} file embedded across P2MS outputs", file_type.unwrap()),
            ))
        } else if found_burn {
            Some((
                ProtocolVariant::DataStorageProofOfBurn,
                "Proof-of-burn pattern detected (0xFFFF keys)".to_string(),
            ))
        } else if found_file_metadata && found_text_data {
            // Both flags set - distinguish PRIMARY file metadata from INCIDENTAL references
            // Use length heuristic: short data = primary metadata, long data = incidental
            let total_length: usize = all_data.iter().map(|d| d.len()).sum();

            if total_length < 200 {
                // Short data (<200 bytes) - file metadata is likely PRIMARY content (bare URLs, filenames)
                Some((
                    ProtocolVariant::DataStorageFileMetadata,
                    "File metadata embedded in public keys".to_string(),
                ))
            } else {
                // Substantial data (≥200 bytes) - file metadata is likely INCIDENTAL (URLs mentioned in code/docs)
                Some((
                    ProtocolVariant::DataStorageEmbeddedData,
                    "Text data embedded in public key coordinates".to_string(),
                ))
            }
        } else if found_file_metadata {
            // Only file metadata, no substantial text content
            Some((
                ProtocolVariant::DataStorageFileMetadata,
                "File metadata embedded in public keys".to_string(),
            ))
        } else if found_text_data {
            // Only text data, no file metadata
            Some((
                ProtocolVariant::DataStorageEmbeddedData,
                "Text data embedded in public key coordinates".to_string(),
            ))
        } else if !has_non_null_data {
            // All data is null/zero bytes (empty padding)
            Some((
                ProtocolVariant::DataStorageNullData,
                "Null/zero byte data (empty padding)".to_string(),
            ))
        } else {
            // No definitive data storage patterns found - fallthrough to other classifiers
            // Invalid EC points alone are ambiguous (could be bugs/errors), so let LikelyDataStorage handle them
            None
        }
    }
}

impl ProtocolSpecificClassifier for DataStorageClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        _database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // No height restrictions - active at all heights

        // Filter to P2MS outputs ONLY
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);

        // Extract data from all public keys in one pass
        let mut extracted_data = Vec::new();

        for output in &p2ms_outputs {
            if let Some(info) = output.multisig_info() {
                for pubkey in &info.pubkeys {
                    if let Some(data) = Self::extract_key_data(pubkey) {
                        extracted_data.push(data);
                    }
                }
            }
        }

        // If no data could be extracted, not a data storage transaction
        if extracted_data.is_empty() {
            return None;
        }

        // Analyse extracted data for patterns
        if let Some((variant, method)) = self.classify_data_patterns(&extracted_data) {
            // Concatenate all data chunks for content type detection
            let concatenated: Vec<u8> = extracted_data
                .iter()
                .flat_map(|chunk| chunk.iter())
                .copied()
                .collect();

            // Detect content type from concatenated data
            let content_type =
                ContentType::detect(&concatenated).map(|ct| ct.mime_type().to_string());

            let additional_metadata = format!(
                "Data segments analysed: {}, Total P2MS outputs: {}",
                extracted_data.len(),
                p2ms_outputs.len()
            );

            // Insert per-output classifications with PER-OUTPUT spendability analysis
            let mut output_classifications = Vec::new();
            for output in p2ms_outputs.iter() {
                // CRITICAL: Analyse spendability for THIS specific output
                let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

                let mut details = crate::types::OutputClassificationDetails::new(
                    Vec::new(),
                    true,
                    true,
                    method.clone(),
                    spendability_result,
                )
                .with_metadata(additional_metadata.clone());

                if let Some(ct) = &content_type {
                    details = details.with_content_type(ct.clone());
                }

                output_classifications.push(crate::types::OutputClassificationData::new(
                    output.vout,
                    ProtocolType::DataStorage,
                    Some(variant.clone()),
                    details,
                ));
            }

            let tx_classification = ClassificationResult {
                txid: tx.txid.clone(),
                protocol: ProtocolType::DataStorage,
                variant: Some(variant),
                classification_details: crate::types::ClassificationDetails {
                    burn_patterns_detected: Vec::new(),
                    height_check_passed: true,
                    protocol_signature_found: true,
                    classification_method: method,
                    additional_metadata: Some(additional_metadata),
                    content_type,
                },
                classification_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            return Some((tx_classification, output_classifications));
        }

        // No recognizable data storage patterns found
        None
    }
}
