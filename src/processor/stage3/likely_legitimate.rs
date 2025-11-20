//! Likely Legitimate Multisig Classifier
//!
//! Classifies P2MS outputs as likely legitimate multisig transactions based on public key validation.
//!
//! ## Classification Logic
//!
//! A P2MS output is classified as "Likely Legitimate Multisig" if:
//! - ALL public keys are valid EC points on the secp256k1 curve
//! - Even if duplicate keys are present (likely wallet/user error)
//!
//! If ANY public key is invalid (not on curve), the transaction remains "Unknown"
//! as it's definitely data-carrying (impossible in real cryptography).

use crate::analysis::aggregate_validation_for_outputs;
use crate::database::traits::Stage1Operations;
use crate::database::Database;
use crate::processor::stage3::{ProtocolSpecificClassifier, SpendabilityAnalyser};
use crate::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, ProtocolType,
    ProtocolVariant, Stage3Config,
};
use serde_json::json;
use tracing::debug;

/// Classifier for likely legitimate multisig transactions
pub struct LikelyLegitimateClassifier {
    #[allow(dead_code)]
    config: Stage3Config,
}

impl LikelyLegitimateClassifier {
    /// Create a new likely legitimate classifier
    pub fn new(config: &Stage3Config) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

impl ProtocolSpecificClassifier for LikelyLegitimateClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Get P2MS outputs for this transaction
        let p2ms_outputs = match database.get_p2ms_outputs_for_transaction(&tx.txid) {
            Ok(outputs) => outputs,
            Err(e) => {
                debug!("Failed to get P2MS outputs for {}: {}", tx.txid, e);
                return None;
            }
        };

        if p2ms_outputs.is_empty() {
            return None;
        }

        // Validate all public keys using shared aggregation helper
        let validation = match aggregate_validation_for_outputs(&p2ms_outputs) {
            Some(v) => v,
            None => {
                debug!(
                    "Transaction {} has no extractable pubkeys for validation",
                    tx.txid
                );
                return None;
            }
        };

        // Only classify as LikelyLegitimateMultisig if ALL pubkeys are valid
        if !validation.all_valid_ec_points {
            debug!(
                "Transaction {} has invalid EC points - not legitimate multisig",
                tx.txid
            );
            return None; // Falls through to Unknown
        }

        // Guard against all-null outputs (should be caught by DataStorage, but safety check)
        let real_key_count = validation.valid_keys;
        if real_key_count == 0 {
            debug!(
                "Transaction {} has only null keys - not legitimate multisig",
                tx.txid
            );
            return None; // Falls through to Unknown or DataStorage
        }

        // All pubkeys valid - classify as LikelyLegitimateMultisig
        // Determine variant based on key composition
        let variant = if validation.null_key_count > 0 {
            ProtocolVariant::LegitimateMultisigWithNullKey
        } else if validation.has_duplicate_keys {
            ProtocolVariant::LegitimateMultisigDupeKeys
        } else {
            ProtocolVariant::LegitimateMultisig
        };

        debug!(
            "Transaction {} classified as LikelyLegitimateMultisig ({}): {}",
            tx.txid,
            match variant {
                ProtocolVariant::LegitimateMultisigWithNullKey => "WithNullKey",
                ProtocolVariant::LegitimateMultisigDupeKeys => "DupeKeys",
                _ => "Standard",
            },
            validation.summary()
        );

        // Build per-output classifications: mark each output as LikelyLegitimateMultisig
        // Each output gets its own spendability analysis for accurate key counts
        let mut output_classifications = Vec::new();
        for output in &p2ms_outputs {
            let spendability_result = SpendabilityAnalyser::analyse_legitimate_output(output);

            let details = crate::types::OutputClassificationDetails::new(
                Vec::new(), // No burn patterns for legitimate multisig
                true,       // Height check passed (always active)
                false,      // No protocol signature (EC validation is the signal)
                format!(
                    "Legitimate multisig: all {} pubkeys are valid EC points",
                    output.multisig_info().map(|i| i.total_pubkeys).unwrap_or(0)
                ),
                spendability_result,
            );

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::LikelyLegitimateMultisig,
                Some(variant.clone()),
                details,
            ));
        }

        let tx_classification = ClassificationResult {
            txid: tx.txid.clone(),
            protocol: ProtocolType::LikelyLegitimateMultisig,
            variant: Some(variant),
            classification_details: ClassificationDetails {
                burn_patterns_detected: vec![],
                height_check_passed: true,
                protocol_signature_found: false, // No signature needed - EC validation is the signal
                classification_method: "Public key EC point validation".to_string(),
                additional_metadata: Some(
                    json!({
                        "pubkey_validation": {
                            "all_valid": validation.all_valid_ec_points,
                            "has_duplicates": validation.has_duplicate_keys,
                            "total_keys": validation.total_keys,
                            "valid_keys": validation.valid_keys,
                            "summary": validation.summary(),
                            "confidence": if validation.has_duplicate_keys {
                                "Medium" // Duplicate keys lower confidence slightly
                            } else {
                                "High"
                            }
                        }
                    })
                    .to_string(),
                ),
                content_type: None,
            },
            classification_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        Some((tx_classification, output_classifications))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Stage3Config, TransactionOutput};

    #[test]
    fn test_likely_legitimate_classifier_creation() {
        let config = Stage3Config::default();
        let _classifier = LikelyLegitimateClassifier::new(&config);
        // Classifier created successfully
    }

    #[test]
    fn test_valid_pubkeys_classification() {
        // Valid uncompressed public key
        let valid_pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5";

        let output = TransactionOutput {
            txid: "test123".to_string(),
            vout: 0,
            amount: 1000,
            height: 100000,
            script_hex: "".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: json!({
                "pubkeys": [valid_pubkey, valid_pubkey],
                "required_sigs": 2,
                "total_pubkeys": 2
            }),
            address: None,
        };

        let config = Stage3Config::default();
        let _classifier = LikelyLegitimateClassifier::new(&config);

        let validation = aggregate_validation_for_outputs(&[output]);
        assert!(validation.is_some());

        let v = validation.unwrap();
        assert!(v.all_valid_ec_points);
        assert!(v.has_duplicate_keys); // Same key used twice
    }

    #[test]
    fn test_invalid_pubkey_returns_none() {
        // Invalid EC point
        let invalid_pubkey = format!("03{}", "00".repeat(32));

        let output = TransactionOutput {
            txid: "test456".to_string(),
            vout: 0,
            amount: 1000,
            height: 100000,
            script_hex: "".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: json!({
                "pubkeys": [invalid_pubkey],
                "required_sigs": 1,
                "total_pubkeys": 1
            }),
            address: None,
        };

        let config = Stage3Config::default();
        let _classifier = LikelyLegitimateClassifier::new(&config);

        let validation = aggregate_validation_for_outputs(&[output]);
        assert!(validation.is_some());

        let v = validation.unwrap();
        assert!(!v.all_valid_ec_points); // Should detect invalid point
    }

    #[test]
    fn test_null_padded_multisig_spendable() {
        // Valid EC point + null key with M=1 (spendable)
        let valid_pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5";
        let null_pubkey_compressed = "00".repeat(33); // 33 bytes of 0x00 as hex

        let output = TransactionOutput {
            txid: "null_padded_test".to_string(),
            vout: 0,
            amount: 1000,
            height: 100000,
            script_hex: "".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: json!({
                "pubkeys": [valid_pubkey, null_pubkey_compressed],
                "required_sigs": 1,
                "total_pubkeys": 2
            }),
            address: None,
        };

        let config = Stage3Config::default();
        let _classifier = LikelyLegitimateClassifier::new(&config);

        let validation = aggregate_validation_for_outputs(&[output.clone()]);
        assert!(validation.is_some());

        let v = validation.unwrap();
        assert!(v.all_valid_ec_points); // All keys are valid or null
        assert_eq!(v.null_key_count, 1); // One null key detected
        assert_eq!(v.valid_keys, 1); // Only real EC points (null not counted)

        // Check spendability
        use crate::processor::stage3::SpendabilityAnalyser;
        let spendability = SpendabilityAnalyser::analyse_legitimate_output(&output);
        assert!(spendability.is_spendable); // M=1, real_keys=1, spendable
        assert_eq!(spendability.real_pubkey_count, 1);
    }

    #[test]
    fn test_null_padded_multisig_unspendable() {
        // Valid EC point + null key with M=2 (unspendable - insufficient real keys)
        let valid_pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5";
        let null_pubkey_compressed = "00".repeat(33); // 33 bytes of 0x00 as hex

        let output = TransactionOutput {
            txid: "null_unspendable_test".to_string(),
            vout: 0,
            amount: 1000,
            height: 100000,
            script_hex: "".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: json!({
                "pubkeys": [valid_pubkey, null_pubkey_compressed],
                "required_sigs": 2,
                "total_pubkeys": 2
            }),
            address: None,
        };

        let config = Stage3Config::default();
        let _classifier = LikelyLegitimateClassifier::new(&config);

        let validation = aggregate_validation_for_outputs(&[output.clone()]);
        assert!(validation.is_some());

        let v = validation.unwrap();
        assert!(v.all_valid_ec_points);
        assert_eq!(v.null_key_count, 1);

        // Check spendability - should be unspendable
        use crate::processor::stage3::SpendabilityAnalyser;
        use crate::types::spendability::SpendabilityReason;
        let spendability = SpendabilityAnalyser::analyse_legitimate_output(&output);
        assert!(!spendability.is_spendable); // M=2, real_keys=1, unspendable
        assert_eq!(
            spendability.reason,
            SpendabilityReason::InsufficientRealKeys
        );
        assert_eq!(spendability.real_pubkey_count, 1);
    }

    #[test]
    fn test_multiple_null_keys() {
        // 1 valid + 2 null keys with M=1 (spendable)
        let valid_pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5";
        let null_pubkey_1 = "00".repeat(33); // 33 bytes of 0x00 as hex
        let null_pubkey_2 = "00".repeat(65); // 65 bytes of 0x00 as hex

        let output = TransactionOutput {
            txid: "multi_null_test".to_string(),
            vout: 0,
            amount: 1000,
            height: 100000,
            script_hex: "".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: json!({
                "pubkeys": [valid_pubkey, null_pubkey_1, null_pubkey_2],
                "required_sigs": 1,
                "total_pubkeys": 3
            }),
            address: None,
        };

        let config = Stage3Config::default();
        let _classifier = LikelyLegitimateClassifier::new(&config);

        let validation = aggregate_validation_for_outputs(&[output.clone()]);
        assert!(validation.is_some());

        let v = validation.unwrap();
        assert!(v.all_valid_ec_points);
        assert_eq!(v.null_key_count, 2); // Two null keys detected
        assert_eq!(v.valid_keys, 1); // Only real EC points (nulls not counted)

        // Check spendability
        use crate::processor::stage3::SpendabilityAnalyser;
        let spendability = SpendabilityAnalyser::analyse_legitimate_output(&output);
        assert!(spendability.is_spendable); // M=1, real_keys=1, spendable
        assert_eq!(spendability.real_pubkey_count, 1);
    }

    #[test]
    fn test_null_key_summary() {
        use crate::analysis::pubkey_validator::validate_pubkeys;

        let valid_pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5".to_string();
        let null_pubkey = "00".repeat(33); // 33 bytes of 0x00 as hex

        let result = validate_pubkeys(&[valid_pubkey, null_pubkey]);

        assert!(result.all_valid_ec_points);
        assert_eq!(result.null_key_count, 1);
        assert_eq!(result.valid_keys, 1); // Only real EC points
        assert!(result.summary().contains("null keys"));
        assert!(result.summary().contains("null-padded multisig"));
    }
}
