use crate::types::burn_patterns::{classify_burn_pattern, BurnPattern};

#[cfg(test)]
use crate::types::burn_patterns::BurnPatternType;
use crate::types::TransactionOutput;
use tracing::debug;

/// Burn pattern detector for identifying protocol-specific burn keys in P2MS outputs
pub struct BurnPatternDetector;

impl BurnPatternDetector {
    /// Detect burn patterns across all P2MS outputs in a transaction
    pub fn detect_burn_patterns(outputs: &[TransactionOutput]) -> Vec<BurnPattern> {
        let mut patterns = Vec::new();

        for output in outputs {
            patterns.extend(Self::analyse_p2ms_for_burns(output));
        }

        debug!(
            "Detected {} burn patterns across {} P2MS outputs",
            patterns.len(),
            outputs.len()
        );
        patterns
    }

    /// Analyse a single P2MS output for burn patterns
    fn analyse_p2ms_for_burns(output: &TransactionOutput) -> Vec<BurnPattern> {
        let mut patterns = Vec::new();

        // Try to get multisig info from metadata
        if let Some(multisig_info) = output.multisig_info() {
            for (index, pubkey) in multisig_info.pubkeys.iter().enumerate() {
                if let Some(pattern_type) = classify_burn_pattern(pubkey) {
                    patterns.push(BurnPattern {
                        pattern_type,
                        vout: output.vout,
                        pubkey_index: index as u8,
                        pattern_data: pubkey.clone(),
                    });
                }
            }
        }
        // Also check nonstandard scripts with MultisigAnomaly
        else if let Some(nonstandard_info) = output.nonstandard_info() {
            if let crate::types::script_metadata::NonstandardClassification::MultisigAnomaly(
                ref anomaly,
            ) = nonstandard_info.classification
            {
                for segment in &anomaly.segments {
                    match segment {
                        crate::types::script_metadata::MultisigSegment::Pubkey {
                            hex,
                            index,
                            ..
                        } => {
                            if let Some(pattern_type) = classify_burn_pattern(hex) {
                                patterns.push(BurnPattern {
                                    pattern_type,
                                    vout: output.vout,
                                    pubkey_index: *index as u8,
                                    pattern_data: hex.clone(),
                                });
                            }
                        }
                        crate::types::script_metadata::MultisigSegment::DataChunk { .. } => {
                            // Data chunks can't be burn patterns
                        }
                    }
                }
            }
        }

        patterns
    }
}

#[cfg(test)]
impl BurnPatternDetector {
    /// Count total burn patterns by type for statistics (test-only)
    pub fn count_patterns_by_type(
        patterns: &[BurnPattern],
    ) -> std::collections::HashMap<BurnPatternType, usize> {
        let mut counts = std::collections::HashMap::new();

        for pattern in patterns {
            *counts.entry(pattern.pattern_type.clone()).or_insert(0) += 1;
        }

        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_p2ms_output(pubkeys: Vec<String>) -> TransactionOutput {
        use crate::types::script_metadata::MultisigInfo;

        let multisig_info = MultisigInfo {
            pubkeys: pubkeys.clone(),
            required_sigs: 1,
            total_pubkeys: pubkeys.len() as u32,
        };

        TransactionOutput {
            txid: "test_txid".to_string(),
            vout: 0,
            height: 100000,
            amount: 1000,
            script_hex: "test_script".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(multisig_info).unwrap(),
            address: None,
        }
    }

    #[test]
    fn test_stamps_22_pattern_detection() {
        let burn_key =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();
        let output = create_test_p2ms_output(vec![burn_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 1);
        assert!(matches!(
            patterns[0].pattern_type,
            BurnPatternType::Stamps22Pattern
        ));
    }

    #[test]
    fn test_stamps_33_pattern_detection() {
        let burn_key =
            "033333333333333333333333333333333333333333333333333333333333333333".to_string();
        let output = create_test_p2ms_output(vec![burn_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 1);
        assert!(matches!(
            patterns[0].pattern_type,
            BurnPatternType::Stamps33Pattern
        ));
    }

    #[test]
    fn test_stamps_0202_pattern_detection() {
        let burn_key =
            "020202020202020202020202020202020202020202020202020202020202020202".to_string();
        let output = create_test_p2ms_output(vec![burn_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 1);
        assert!(matches!(
            patterns[0].pattern_type,
            BurnPatternType::Stamps0202Pattern
        ));
    }

    #[test]
    fn test_stamps_0303_pattern_detection() {
        let burn_key =
            "030303030303030303030303030303030303030303030303030303030303030303".to_string();
        let output = create_test_p2ms_output(vec![burn_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 1);
        assert!(matches!(
            patterns[0].pattern_type,
            BurnPatternType::Stamps0303Pattern
        ));
    }

    #[test]
    fn test_proof_of_burn_pattern_detection() {
        // Test DataStorage proof-of-burn pattern
        let proof_of_burn_key =
            "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        let output = create_test_p2ms_output(vec![proof_of_burn_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 1);
        assert!(matches!(
            patterns[0].pattern_type,
            BurnPatternType::ProofOfBurn
        ));
    }

    #[test]
    fn test_unknown_suspicious_pattern_detection() {
        // Create a key with many zeros (suspicious but not matching known patterns)
        let suspicious_key =
            "020000000000000000000000000000000000000000000000000000000000000000".to_string();
        let output = create_test_p2ms_output(vec![suspicious_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 1);
        assert!(matches!(
            patterns[0].pattern_type,
            BurnPatternType::UnknownBurn
        ));
    }

    #[test]
    fn test_counterparty_message_not_detected_as_burn() {
        let counterparty_key = format!("1{}", "0".repeat(65));
        let output = create_test_p2ms_output(vec![counterparty_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert!(patterns.is_empty());
    }

    #[test]
    fn test_all_ones_detected_as_unknown_burn() {
        let repeating_key = format!("02{}", "1".repeat(64));
        let output = create_test_p2ms_output(vec![repeating_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 1);
        assert!(matches!(
            patterns[0].pattern_type,
            BurnPatternType::UnknownBurn
        ));
    }

    #[test]
    fn test_normal_pubkey_not_detected() {
        // Normal-looking pubkey should not be detected as burn
        let normal_key =
            "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2".to_string();
        let output = create_test_p2ms_output(vec![normal_key]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 0);
    }

    #[test]
    fn test_multiple_patterns_in_transaction() {
        let burn_key_1 =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();
        let burn_key_2 =
            "033333333333333333333333333333333333333333333333333333333333333333".to_string();
        let normal_key =
            "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2".to_string();

        let output = create_test_p2ms_output(vec![burn_key_1, normal_key, burn_key_2]);

        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        assert_eq!(patterns.len(), 2);
        // Should detect both burn patterns but not the normal key
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, BurnPatternType::Stamps22Pattern)));
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, BurnPatternType::Stamps33Pattern)));
    }

    #[test]
    fn test_pattern_counting() {
        let burn_key_1 =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();
        let burn_key_2 =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string(); // Same pattern
        let burn_key_3 =
            "033333333333333333333333333333333333333333333333333333333333333333".to_string();

        let output = create_test_p2ms_output(vec![burn_key_1, burn_key_2, burn_key_3]);
        let patterns = BurnPatternDetector::detect_burn_patterns(&[output]);

        let counts = BurnPatternDetector::count_patterns_by_type(&patterns);

        assert_eq!(counts.get(&BurnPatternType::Stamps22Pattern), Some(&2));
        assert_eq!(counts.get(&BurnPatternType::Stamps33Pattern), Some(&1));
    }
}
