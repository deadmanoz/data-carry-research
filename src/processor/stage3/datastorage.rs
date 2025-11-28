use crate::database::Database;
use crate::shared::datastorage_helpers::{
    detect_binary_signature, extract_key_data, is_burn_pattern,
};
use crate::types::content_detection::ContentType;
use crate::types::{
    ClassificationResult, EnrichedTransaction, ProtocolType, ProtocolVariant, Stage3Config,
};
use std::time::{SystemTime, UNIX_EPOCH};

use super::filter_p2ms_for_classification;
use super::spendability::SpendabilityAnalyser;
use super::ProtocolSpecificClassifier;

/// Known historical artifact: The Bitcoin Whitepaper PDF (height 230,009)
const BITCOIN_WHITEPAPER_TXID: &str = "54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713";

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

    /// Check for known historical artifacts by TXID
    fn check_known_artifacts(txid: &str) -> Option<(ProtocolVariant, &'static str, &'static str)> {
        if txid == BITCOIN_WHITEPAPER_TXID {
            return Some((
                ProtocolVariant::DataStorageBitcoinWhitepaper,
                "application/pdf",
                "Bitcoin Whitepaper PDF (Satoshi Nakamoto, 2008)",
            ));
        }
        None
    }

    /// Build classification for a known historical artifact
    fn build_artifact_classification(
        tx: &EnrichedTransaction,
        variant: ProtocolVariant,
        content_type: &str,
        description: &str,
    ) -> (ClassificationResult, Vec<crate::types::OutputClassificationData>) {
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);

        let additional_metadata = format!(
            "{} | Height: {} | P2MS outputs: {}",
            description, tx.height, p2ms_outputs.len()
        );

        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let details = crate::types::OutputClassificationDetails::new(
                Vec::new(),
                true,
                true,
                "Known historical artifact (TXID match)".to_string(),
                spendability_result,
            )
            .with_metadata(additional_metadata.clone())
            .with_content_type(content_type);

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
                classification_method: "Known historical artifact (TXID match)".to_string(),
                additional_metadata: Some(additional_metadata),
                content_type: Some(content_type.to_string()),
            },
            classification_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        (tx_classification, output_classifications)
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
            if let Some(sig) = detect_binary_signature(data) {
                found_binary_file = true;
                file_type = Some(sig);
            } else if is_burn_pattern(data, None) {
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
            if let Some(sig) = detect_binary_signature(&concatenated) {
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
        // Check for known historical artifacts FIRST (short-circuit before generic detection)
        if let Some((variant, content_type, description)) = Self::check_known_artifacts(&tx.txid) {
            return Some(Self::build_artifact_classification(
                tx,
                variant,
                content_type,
                description,
            ));
        }

        // No height restrictions - active at all heights

        // Filter to P2MS outputs ONLY
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);

        // Extract data from all public keys in one pass
        let mut extracted_data = Vec::new();

        for output in &p2ms_outputs {
            if let Some(info) = output.multisig_info() {
                for pubkey in &info.pubkeys {
                    if let Some(data) = extract_key_data(pubkey) {
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
