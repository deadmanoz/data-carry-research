//! LikelyDataStorage protocol classifier
//!
//! Identifies P2MS outputs that are likely storing data based on patterns:
//! 1. Invalid EC points - pubkeys that fail secp256k1 curve validation
//! 2. High output count - 5+ P2MS outputs with valid EC points
//! 3. Dust amounts - all P2MS outputs <= 1000 satoshis (cost minimization)
//!
//! These patterns suggest data storage protocols, though not with the certainty
//! of protocol-specific signatures. Classification order ensures these are only
//! checked after all specific protocol detectors have run.

use crate::database::Database;
use crate::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, OutputClassificationDetails,
    ProtocolType, ProtocolVariant, TransactionOutput,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, trace};

use super::filter_p2ms_for_classification;
use super::spendability::SpendabilityAnalyser;

/// LikelyDataStorage protocol classifier
pub struct LikelyDataStorageClassifier;

impl Default for LikelyDataStorageClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl LikelyDataStorageClassifier {
    /// Create a new LikelyDataStorage classifier instance
    pub fn new() -> Self {
        Self
    }

    /// Check if a transaction shows likely data storage patterns
    pub fn classify(
        &self,
        tx: &EnrichedTransaction,
        db: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        trace!(
            "Checking transaction {} for LikelyDataStorage patterns",
            tx.txid
        );

        // Filter to P2MS outputs ONLY (collect owned values for helper functions)
        let p2ms_outputs: Vec<_> = filter_p2ms_for_classification(&tx.outputs)
            .into_iter()
            .cloned()
            .collect();

        // Need at least one P2MS output to classify
        if p2ms_outputs.is_empty() {
            return None;
        }

        // Check 1: Invalid EC points (strong data embedding indicator)
        // Even a SINGLE invalid EC point suggests data storage, as legitimate wallets
        // would never generate keys that aren't on the secp256k1 curve.
        // Uses full EC validation (not just prefix checking).
        if let Some(invalid_info) = self.check_invalid_ec_points(&p2ms_outputs) {
            debug!(
                "Transaction {} has invalid EC points: {}",
                tx.txid, invalid_info
            );

            // Build per-output classifications with spendability analysis
            let output_classifications = self.build_output_classifications(
                &p2ms_outputs,
                ProtocolVariant::InvalidECPoint,
                &invalid_info,
            );

            let tx_classification =
                self.create_classification(&tx.txid, ProtocolVariant::InvalidECPoint, invalid_info);

            return Some((tx_classification, output_classifications));
        }

        // Check 2: High output count (5+ P2MS outputs)
        // But only if ALL pubkeys are valid EC points (otherwise would be Unknown)
        if p2ms_outputs.len() >= 5 {
            // Check that all outputs have valid EC points (no obvious data embedding)
            let all_valid_ec = self.check_all_valid_ec_points(&p2ms_outputs, db);
            if all_valid_ec {
                let method = format!("{} P2MS outputs with valid EC points", p2ms_outputs.len());

                debug!(
                    "Transaction {} has {} P2MS outputs with valid EC points",
                    tx.txid,
                    p2ms_outputs.len()
                );

                // Build per-output classifications with spendability analysis
                let output_classifications = self.build_output_classifications(
                    &p2ms_outputs,
                    ProtocolVariant::HighOutputCount,
                    &method,
                );

                let tx_classification =
                    self.create_classification(&tx.txid, ProtocolVariant::HighOutputCount, method);

                return Some((tx_classification, output_classifications));
            }
        }

        // Check 3: Dust-level amounts (<= 1000 sats) with valid EC points
        // This catches data-carrying protocols that use minimal amounts to reduce costs
        if let Some(dust_info) = self.check_dust_amounts(&p2ms_outputs, db) {
            debug!(
                "Transaction {} has dust-level P2MS outputs: {}",
                tx.txid, dust_info
            );

            // Build per-output classifications with spendability analysis
            let output_classifications = self.build_output_classifications(
                &p2ms_outputs,
                ProtocolVariant::DustAmount,
                &dust_info,
            );

            let tx_classification =
                self.create_classification(&tx.txid, ProtocolVariant::DustAmount, dust_info);

            return Some((tx_classification, output_classifications));
        }

        None
    }

    /// Build per-output classifications with spendability analysis
    fn build_output_classifications(
        &self,
        outputs: &[TransactionOutput],
        variant: ProtocolVariant,
        method: &str,
    ) -> Vec<crate::types::OutputClassificationData> {
        // Build per-output classifications with PER-OUTPUT spendability analysis
        let mut output_classifications = Vec::new();
        for output in outputs {
            // CRITICAL: Analyse spendability for THIS specific output
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let details = OutputClassificationDetails::new(
                Vec::new(),
                true,
                false, // protocol_signature_found = false for LikelyDataStorage
                method.to_string(),
                spendability_result,
            );

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::LikelyDataStorage,
                Some(variant.clone()),
                details,
            ));
        }
        output_classifications
    }

    /// Check if any pubkeys are invalid EC points (data embedding indicator)
    ///
    /// Returns Some(description) if ANY pubkey fails EC point validation.
    /// Uses full secp256k1 curve validation via shared aggregation helper.
    ///
    /// Even a single invalid EC point strongly suggests data storage, as legitimate
    /// multisig wallets would never generate keys that aren't on the curve.
    ///
    /// This catches:
    /// - Invalid prefixes (0xb6, 0x01, 0xe1 instead of 0x02/0x03/0x04)
    /// - Valid prefixes but coordinates not on secp256k1 curve
    /// - Malformed keys of wrong length
    fn check_invalid_ec_points(&self, outputs: &[TransactionOutput]) -> Option<String> {
        use crate::analysis::aggregate_validation_for_outputs;

        let validation = aggregate_validation_for_outputs(outputs)?;

        // Trigger if ANY key is invalid (≥1 invalid EC point)
        if !validation.all_valid_ec_points {
            let total_invalid = validation.invalid_key_indices.len();
            let total_keys = validation.total_keys;

            // Collect error examples (first 3)
            let error_examples: Vec<String> = validation
                .validation_errors
                .iter()
                .take(3)
                .cloned()
                .collect();

            let examples = if !error_examples.is_empty() {
                format!(": {}", error_examples.join("; "))
            } else {
                String::new()
            };

            Some(format!(
                "{}/{} pubkeys are invalid EC points{}",
                total_invalid, total_keys, examples
            ))
        } else {
            None
        }
    }

    /// Check if all pubkeys are valid EC points
    ///
    /// Uses full secp256k1 curve validation via shared aggregation helper.
    /// Returns true only if every single pubkey passes EC point validation.
    fn check_all_valid_ec_points(&self, outputs: &[TransactionOutput], _db: &Database) -> bool {
        use crate::analysis::aggregate_validation_for_outputs;

        if let Some(validation) = aggregate_validation_for_outputs(outputs) {
            // Return true only if ALL pubkeys are valid EC points
            validation.all_valid_ec_points
        } else {
            // If we can't validate (no extractable pubkeys), assume invalid
            false
        }
    }

    /// Check for dust-level amounts in P2MS outputs
    ///
    /// Data-carrying protocols typically use minimal amounts (dust) to reduce costs
    /// while still being accepted by the network. Legitimate multisig transactions
    /// typically have meaningful amounts of BTC.
    ///
    /// Threshold: <= 1000 satoshis per P2MS output
    /// This catches protocols like the October 2024+ mystery protocol (800 sats)
    ///
    /// NOTE: Expects pre-filtered multisig-only outputs (filtering done in classify())
    fn check_dust_amounts(&self, outputs: &[TransactionOutput], db: &Database) -> Option<String> {
        const DUST_THRESHOLD: u64 = 1000; // satoshis

        // Check if ALL multisig outputs have dust-level amounts
        let all_dust = outputs.iter().all(|output| output.amount <= DUST_THRESHOLD);

        if !all_dust {
            return None; // Some multisig outputs have significant amounts, likely legitimate
        }

        // Also verify that pubkeys are valid EC points (not obvious data)
        // This prevents double-classification with Unknown protocol
        if !self.check_all_valid_ec_points(outputs, db) {
            return None;
        }

        // Calculate statistics for the classification method
        let amounts: Vec<u64> = outputs.iter().map(|o| o.amount).collect();
        let min_amount = amounts.iter().min().unwrap_or(&0);
        let max_amount = amounts.iter().max().unwrap_or(&0);
        let avg_amount = if !amounts.is_empty() {
            amounts.iter().sum::<u64>() / amounts.len() as u64
        } else {
            0
        };

        Some(format!(
            "All {} P2MS outputs have dust-level amounts (min: {}, max: {}, avg: {} sats)",
            outputs.len(),
            min_amount,
            max_amount,
            avg_amount
        ))
    }

    /// Create a classification result
    fn create_classification(
        &self,
        txid: &str,
        variant: ProtocolVariant,
        method: String,
    ) -> ClassificationResult {
        ClassificationResult {
            txid: txid.to_string(),
            protocol: ProtocolType::LikelyDataStorage,
            variant: Some(variant),
            classification_details: ClassificationDetails {
                burn_patterns_detected: vec![],
                height_check_passed: true,
                protocol_signature_found: false,
                classification_method: method,
                additional_metadata: None,
                content_type: None, // No content extraction for LikelyDataStorage
            },
            classification_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FeeAnalysis;

    fn create_test_output(pubkey: &str, vout: u32) -> TransactionOutput {
        // Create a simple 1-of-1 multisig output for testing
        let script_hex = format!("5121{}51ae", pubkey);

        TransactionOutput {
            txid: "test_txid".to_string(),
            vout,
            height: 800000,
            amount: 10000, // Above dust threshold to avoid DustAmount classification
            script_hex,
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: serde_json::json!({
                "required_sigs": 1,
                "total_pubkeys": 1,
                "pubkeys": [pubkey]
            }),
            address: None,
        }
    }

    #[test]
    fn test_high_output_count_detection() {
        let classifier = LikelyDataStorageClassifier::new();
        let db = Database::new_v2(":memory:").unwrap();

        // Create 6 outputs with different valid pubkeys
        let pubkeys = [
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
        ];

        let outputs: Vec<TransactionOutput> = pubkeys
            .iter()
            .enumerate()
            .map(|(i, pubkey)| create_test_output(pubkey, i as u32))
            .collect();

        let tx = EnrichedTransaction::from_fee_analysis(
            "test_txid".to_string(),
            800000,
            FeeAnalysis {
                total_input_value: 0,
                total_output_value: 0,
                transaction_fee: 0,
                fee_per_byte: 0.0,
                transaction_size_bytes: 0,
                fee_per_kb: 0.0,
                total_p2ms_amount: 0,
                data_storage_fee_rate: 0.0,
                p2ms_outputs_count: 0,
            },
            outputs,
            vec![],
            6,
            false,
            vec![],
        );

        let result = classifier.classify(&tx, &db);
        assert!(result.is_some());

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::LikelyDataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::HighOutputCount)
        );
        assert!(classification
            .classification_details
            .classification_method
            .contains("6 P2MS outputs"));
    }

    #[test]
    fn test_no_classification_for_normal_transaction() {
        let classifier = LikelyDataStorageClassifier::new();
        let db = Database::new_v2(":memory:").unwrap();

        // Create a normal 2-output transaction with different pubkeys
        let outputs = vec![
            create_test_output(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                0,
            ),
            create_test_output(
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                1,
            ),
        ];

        let tx = EnrichedTransaction::from_fee_analysis(
            "test_txid".to_string(),
            800000,
            FeeAnalysis {
                total_input_value: 0,
                total_output_value: 0,
                transaction_fee: 0,
                fee_per_byte: 0.0,
                transaction_size_bytes: 0,
                fee_per_kb: 0.0,
                total_p2ms_amount: 0,
                data_storage_fee_rate: 0.0,
                p2ms_outputs_count: 0,
            },
            outputs,
            vec![],
            2,
            false,
            vec![],
        );

        let result = classifier.classify(&tx, &db);
        assert!(result.is_none());
    }

    #[test]
    fn test_dust_amount_detection() {
        let classifier = LikelyDataStorageClassifier::new();
        let db = Database::new_v2(":memory:").unwrap();

        // Create outputs with dust-level amounts (800 sats, matching Oct 2024+ pattern)
        let pubkey1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        // Create test outputs with 800 satoshi amounts
        fn create_dust_output(pubkey: &str, vout: u32, amount: u64) -> TransactionOutput {
            let script_hex = format!("5121{}51ae", pubkey);
            TransactionOutput {
                txid: "test_txid".to_string(),
                vout,
                height: 865000,
                amount,
                script_hex,
                script_type: "multisig".to_string(),
                is_coinbase: false,
                script_size: 0,
                metadata: serde_json::json!({
                    "required_sigs": 1,
                    "total_pubkeys": 1,
                    "pubkeys": [pubkey]
                }),
                address: None,
            }
        }

        let outputs = vec![
            create_dust_output(pubkey1, 0, 800),
            create_dust_output(pubkey2, 1, 800),
        ];

        let tx = EnrichedTransaction::from_fee_analysis(
            "test_txid".to_string(),
            865000,
            FeeAnalysis {
                total_input_value: 0,
                total_output_value: 0,
                transaction_fee: 0,
                fee_per_byte: 0.0,
                transaction_size_bytes: 0,
                fee_per_kb: 0.0,
                total_p2ms_amount: 1600,
                data_storage_fee_rate: 0.0,
                p2ms_outputs_count: 2,
            },
            outputs,
            vec![],
            2,
            false,
            vec![],
        );

        let result = classifier.classify(&tx, &db);
        assert!(
            result.is_some(),
            "Expected dust amount classification but got None"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::LikelyDataStorage);
        assert_eq!(classification.variant, Some(ProtocolVariant::DustAmount));
        assert!(classification
            .classification_details
            .classification_method
            .contains("dust-level amounts"));
        assert!(classification
            .classification_details
            .classification_method
            .contains("800 sats"));
    }
}
