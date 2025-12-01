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
use crate::shared::likely_data_storage::{detect, LikelyDataStorageVariant};
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
    ///
    /// Uses shared detection module to ensure consistency with Stage 4 (decoder).
    pub fn classify(
        &self,
        tx: &EnrichedTransaction,
        _db: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        trace!(
            "Checking transaction {} for LikelyDataStorage patterns",
            tx.txid
        );

        // Filter to P2MS outputs ONLY (collect owned values for shared detect function)
        let p2ms_outputs: Vec<_> = filter_p2ms_for_classification(&tx.outputs)
            .into_iter()
            .cloned()
            .collect();

        // Single call to unified detection logic (shared with Stage 4)
        if let Some(result) = detect(&p2ms_outputs) {
            debug!(
                "Transaction {} classified as LikelyDataStorage ({}): {}",
                tx.txid,
                match result.variant {
                    LikelyDataStorageVariant::InvalidECPoint => "InvalidECPoint",
                    LikelyDataStorageVariant::HighOutputCount => "HighOutputCount",
                    LikelyDataStorageVariant::DustAmount => "DustAmount",
                },
                result.details
            );

            // Map shared variant to Stage 3 ProtocolVariant (exact match)
            let protocol_variant = match result.variant {
                LikelyDataStorageVariant::InvalidECPoint => ProtocolVariant::InvalidECPoint,
                LikelyDataStorageVariant::HighOutputCount => ProtocolVariant::HighOutputCount,
                LikelyDataStorageVariant::DustAmount => ProtocolVariant::DustAmount,
            };

            // Build Stage 3-specific output classifications (spendability analysis)
            let output_classifications = self.build_output_classifications(
                &p2ms_outputs,
                protocol_variant.clone(),
                &result.details,
            );

            let tx_classification =
                self.create_classification(&tx.txid, protocol_variant, result.details);

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
                // Content type is None because LikelyDataStorage performs PATTERN DETECTION only.
                // Actual data extraction and content type detection occurs in Stage 4 (decoder).
                // This is intentional and architecturally correct.
                content_type: None,
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
