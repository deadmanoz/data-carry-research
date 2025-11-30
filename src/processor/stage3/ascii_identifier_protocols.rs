use crate::database::Database;
use crate::types::{ClassificationResult, EnrichedTransaction, ProtocolType, ProtocolVariant};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

use super::filter_p2ms_for_classification;
use super::spendability::SpendabilityAnalyser;
use super::ProtocolSpecificClassifier;
use crate::shared::{MultisigPatternMatcher, SignatureDetector};

// Protocol signatures
const TB0001_SIGNATURE: &[u8] = b"TB0001"; // hex: 544230303031
const TEST01_SIGNATURE: &[u8] = b"TEST01"; // hex: 544553543031
const METROXMN_SIGNATURE: &[u8] = b"METROXMN"; // hex: 4d4554524f584d4e

// Known ASCII identifier signatures (allowlist approach)
// Only these signatures will trigger AsciiIdentifierOther classification
const KNOWN_ASCII_IDENTIFIERS: &[&[u8]] = &[
    b"NEWBCOIN", // hex: 4e455742434f494e
    b"PRVCY",    // hex: 5052564359 (may have version byte suffix)
];

/// ASCII Identifier Protocols classifier
///
/// Handles protocols that embed ASCII-readable identifiers in P2MS data:
/// - TB0001: Unknown protocol from May 2015 (~185 transactions, historical range 357178-369584)
/// - TEST01: Test/experimental protocol from May 2015 (~91 transactions, historical range 354150-356917)
/// - Metronotes (METROXMN): March 2015 cryptocurrency project (~100 transactions, historical range 346000-357000)
///
///   Historical ranges documented for reference only - detection based on signature, not height.
pub struct AsciiIdentifierProtocolsClassifier;

impl AsciiIdentifierProtocolsClassifier {
    /// Check if transaction contains TB0001 protocol signature
    /// Returns vout if detected
    fn detect_tb0001(&self, tx: &EnrichedTransaction) -> Option<u32> {
        // TB0001 uses 1-of-2 or 1-of-3 multisig patterns
        // Signature can appear in EITHER first or second pubkey (bytes 1-7)
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
        for output in &p2ms_outputs {
            // Check 1-of-3 pattern (check both first and second pubkey)
            if MultisigPatternMatcher::matches(output, 1, 3) {
                if let Some(info) = output.multisig_info() {
                    if info.pubkeys.len() >= 2 {
                        // Check first pubkey
                        if let Ok(pubkey_bytes) = hex::decode(&info.pubkeys[0]) {
                            if SignatureDetector::has_at_offset(
                                &pubkey_bytes,
                                1,
                                7,
                                TB0001_SIGNATURE,
                            ) {
                                debug!(
                                    "✅ TB0001 signature found in 1-of-3 tx {} (first pubkey)",
                                    tx.txid
                                );
                                return Some(output.vout);
                            }
                        }
                        // Check second pubkey
                        if let Ok(pubkey_bytes) = hex::decode(&info.pubkeys[1]) {
                            if SignatureDetector::has_at_offset(
                                &pubkey_bytes,
                                1,
                                7,
                                TB0001_SIGNATURE,
                            ) {
                                debug!(
                                    "✅ TB0001 signature found in 1-of-3 tx {} (second pubkey)",
                                    tx.txid
                                );
                                return Some(output.vout);
                            }
                        }
                    }
                }
            }

            // Check 1-of-2 pattern (check both first and second pubkey)
            if MultisigPatternMatcher::matches(output, 1, 2) {
                if let Some(info) = output.multisig_info() {
                    if info.pubkeys.len() >= 2 {
                        // Check first pubkey
                        if let Ok(pubkey_bytes) = hex::decode(&info.pubkeys[0]) {
                            if SignatureDetector::has_at_offset(
                                &pubkey_bytes,
                                1,
                                7,
                                TB0001_SIGNATURE,
                            ) {
                                debug!(
                                    "✅ TB0001 signature found in 1-of-2 tx {} (first pubkey)",
                                    tx.txid
                                );
                                return Some(output.vout);
                            }
                        }
                        // Check second pubkey
                        if let Ok(pubkey_bytes) = hex::decode(&info.pubkeys[1]) {
                            if SignatureDetector::has_at_offset(
                                &pubkey_bytes,
                                1,
                                7,
                                TB0001_SIGNATURE,
                            ) {
                                debug!(
                                    "✅ TB0001 signature found in 1-of-2 tx {} (second pubkey)",
                                    tx.txid
                                );
                                return Some(output.vout);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if transaction contains TEST01 protocol signature
    /// Returns vout if detected
    /// NOTE: TEST01 places signature in FIRST pubkey, unlike TB0001 (second pubkey)
    fn detect_test01(&self, tx: &EnrichedTransaction) -> Option<u32> {
        // TEST01 uses 1-of-2 or 1-of-3 multisig patterns
        // Signature appears in the FIRST pubkey (bytes 1-7)
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
        for output in &p2ms_outputs {
            // Check 1-of-2 pattern (most common for TEST01)
            if MultisigPatternMatcher::matches(output, 1, 2) {
                if let Some(info) = output.multisig_info() {
                    if !info.pubkeys.is_empty() {
                        if let Ok(pubkey_bytes) = hex::decode(&info.pubkeys[0]) {
                            if SignatureDetector::has_at_offset(
                                &pubkey_bytes,
                                1,
                                7,
                                TEST01_SIGNATURE,
                            ) {
                                debug!("✅ TEST01 signature found in 1-of-2 tx {}", tx.txid);
                                return Some(output.vout);
                            }
                        }
                    }
                }
            }

            // Check 1-of-3 pattern
            if MultisigPatternMatcher::matches(output, 1, 3) {
                if let Some(info) = output.multisig_info() {
                    if !info.pubkeys.is_empty() {
                        if let Ok(pubkey_bytes) = hex::decode(&info.pubkeys[0]) {
                            if SignatureDetector::has_at_offset(
                                &pubkey_bytes,
                                1,
                                7,
                                TEST01_SIGNATURE,
                            ) {
                                debug!("✅ TEST01 signature found in 1-of-3 tx {}", tx.txid);
                                return Some(output.vout);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if transaction contains METROXMN/Metronotes protocol signature
    /// Returns vout if detected
    fn detect_metronotes(&self, tx: &EnrichedTransaction) -> Option<u32> {
        // METROXMN uses 1-of-2 multisig pattern
        // Asset name "METROXMN" is embedded directly in the second pubkey
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
        for output in &p2ms_outputs {
            if let Some(info) = output.multisig_info() {
                if info.required_sigs == 1 && info.total_pubkeys == 2 && info.pubkeys.len() >= 2 {
                    if let Ok(pubkey_bytes) = hex::decode(&info.pubkeys[1]) {
                        // Check if METROXMN signature appears anywhere in the pubkey
                        if SignatureDetector::has_at_any_offset(&pubkey_bytes, METROXMN_SIGNATURE) {
                            debug!("✅ METROXMN signature found in tx {}", tx.txid);
                            return Some(output.vout);
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if transaction contains known ASCII identifier signatures (NEWBCOIN, PRVCY)
    /// Returns vout if detected
    fn detect_ascii_identifier_other(&self, tx: &EnrichedTransaction) -> Option<u32> {
        // Check for known ASCII identifier signatures in P2MS outputs
        // Uses allowlist approach - only detects explicitly listed signatures
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);

        for output in &p2ms_outputs {
            if let Some(info) = output.multisig_info() {
                // Check 1-of-2 and 1-of-3 multisig patterns
                if info.required_sigs == 1 && (info.total_pubkeys == 2 || info.total_pubkeys == 3) {
                    // Scan all pubkeys for known signatures
                    for pubkey_hex in &info.pubkeys {
                        if let Ok(pubkey_bytes) = hex::decode(pubkey_hex) {
                            // Search within first 20 bytes of each pubkey (after prefix byte)
                            for &known_sig in KNOWN_ASCII_IDENTIFIERS {
                                if Self::contains_signature(&pubkey_bytes[1..], known_sig, 20) {
                                    debug!(
                                        "✅ ASCII identifier signature {:?} found in tx {}",
                                        String::from_utf8_lossy(known_sig),
                                        tx.txid
                                    );
                                    return Some(output.vout);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Helper: Check if signature appears within max_offset bytes of data
    fn contains_signature(data: &[u8], signature: &[u8], max_offset: usize) -> bool {
        let search_limit = data.len().min(max_offset);
        for offset in 0..search_limit {
            if offset + signature.len() <= data.len()
                && &data[offset..offset + signature.len()] == signature
            {
                return true;
            }
        }
        false
    }

    /// Create a classification result for a detected variant (transaction-level, no spendability)
    fn create_classification_result(
        &self,
        tx: &EnrichedTransaction,
        variant: ProtocolVariant,
    ) -> ClassificationResult {
        ClassificationResult {
            txid: tx.txid.clone(),
            protocol: ProtocolType::AsciiIdentifierProtocols,
            variant: Some(variant.clone()),
            classification_details: crate::types::ClassificationDetails {
                burn_patterns_detected: Vec::new(),
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: format!(
                    "AsciiIdentifierProtocols P2MS with variant {:?}",
                    variant
                ),
                additional_metadata: Some(format!(r#"{{"height": {}}}"#, tx.height)),
                content_type: Some("application/octet-stream".to_string()),
            },
            classification_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

impl ProtocolSpecificClassifier for AsciiIdentifierProtocolsClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        _database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        debug!(
            "AsciiIdentifierProtocols classifier processing tx: {} at height {}",
            tx.txid, tx.height
        );

        // Try TB0001 detection first (more transactions)
        if let Some(_vout) = self.detect_tb0001(tx) {
            let variant = ProtocolVariant::AsciiIdentifierTB0001;
            let mut output_classifications = Vec::new();

            // Insert per-output classifications with PER-OUTPUT spendability analysis
            let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
            for output in p2ms_outputs {
                // CRITICAL: Analyse spendability for THIS specific output
                let spendability_result = SpendabilityAnalyser::analyse_counterparty_output(output);

                let details = crate::types::OutputClassificationDetails::new(
                    Vec::new(),
                    true,
                    true,
                    format!("AsciiIdentifierProtocols P2MS with variant {:?}", variant),
                    spendability_result,
                )
                .with_metadata(format!("Height: {}", tx.height))
                .with_content_type("application/octet-stream");

                output_classifications.push(crate::types::OutputClassificationData::new(
                    output.vout,
                    ProtocolType::AsciiIdentifierProtocols,
                    Some(variant.clone()),
                    details,
                ));
            }

            let tx_classification = self.create_classification_result(tx, variant);
            return Some((tx_classification, output_classifications));
        }

        // Try TEST01 detection
        if let Some(_vout) = self.detect_test01(tx) {
            let variant = ProtocolVariant::AsciiIdentifierTEST01;
            let mut output_classifications = Vec::new();

            // Insert per-output classifications with PER-OUTPUT spendability analysis
            let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
            for output in p2ms_outputs {
                let spendability_result = SpendabilityAnalyser::analyse_counterparty_output(output);

                let details = crate::types::OutputClassificationDetails::new(
                    Vec::new(),
                    true,
                    true,
                    format!("AsciiIdentifierProtocols P2MS with variant {:?}", variant),
                    spendability_result,
                )
                .with_metadata(format!("Height: {}", tx.height))
                .with_content_type("application/octet-stream");

                output_classifications.push(crate::types::OutputClassificationData::new(
                    output.vout,
                    ProtocolType::AsciiIdentifierProtocols,
                    Some(variant.clone()),
                    details,
                ));
            }

            let tx_classification = self.create_classification_result(tx, variant);
            return Some((tx_classification, output_classifications));
        }

        // Try Metronotes detection
        if let Some(_vout) = self.detect_metronotes(tx) {
            let variant = ProtocolVariant::AsciiIdentifierMetronotes;
            let mut output_classifications = Vec::new();

            // Insert per-output classifications with PER-OUTPUT spendability analysis
            let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
            for output in p2ms_outputs {
                let spendability_result = SpendabilityAnalyser::analyse_counterparty_output(output);

                let details = crate::types::OutputClassificationDetails::new(
                    Vec::new(),
                    true,
                    true,
                    format!("AsciiIdentifierProtocols P2MS with variant {:?}", variant),
                    spendability_result,
                )
                .with_metadata(format!("Height: {}", tx.height))
                .with_content_type("application/octet-stream");

                output_classifications.push(crate::types::OutputClassificationData::new(
                    output.vout,
                    ProtocolType::AsciiIdentifierProtocols,
                    Some(variant.clone()),
                    details,
                ));
            }

            let tx_classification = self.create_classification_result(tx, variant);
            return Some((tx_classification, output_classifications));
        }

        // Try ASCII identifier other detection (NEWBCOIN, PRVCY)
        if let Some(_vout) = self.detect_ascii_identifier_other(tx) {
            let variant = ProtocolVariant::AsciiIdentifierOther;
            let mut output_classifications = Vec::new();

            // Insert per-output classifications with PER-OUTPUT spendability analysis
            // CRITICAL: Use analyse_generic_output (not analyse_counterparty_output)
            // because NEWBCOIN/PRVCY have mixed EC points (1 valid + 1 invalid data pubkey)
            let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
            for output in p2ms_outputs {
                let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

                let details = crate::types::OutputClassificationDetails::new(
                    Vec::new(),
                    true,
                    true,
                    format!("AsciiIdentifierProtocols P2MS with variant {:?}", variant),
                    spendability_result,
                )
                .with_metadata(format!("Height: {}", tx.height))
                .with_content_type("application/octet-stream");

                output_classifications.push(crate::types::OutputClassificationData::new(
                    output.vout,
                    ProtocolType::AsciiIdentifierProtocols,
                    Some(variant.clone()),
                    details,
                ));
            }

            let tx_classification = self.create_classification_result(tx, variant);
            return Some((tx_classification, output_classifications));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tb0001_signature() {
        // Verify the TB0001 signature is correct
        assert_eq!(TB0001_SIGNATURE, b"TB0001");
        assert_eq!(hex::encode(TB0001_SIGNATURE), "544230303031");
    }

    #[test]
    fn test_metroxmn_signature() {
        // Verify the METROXMN signature is correct
        assert_eq!(METROXMN_SIGNATURE, b"METROXMN");
        assert_eq!(hex::encode(METROXMN_SIGNATURE), "4d4554524f584d4e");
    }
}
