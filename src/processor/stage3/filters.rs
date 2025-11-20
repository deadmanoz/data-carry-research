//! Standard filtering utilities for Stage 3 protocol classification
//!
//! This module provides mandatory helper functions to ensure protocol classifiers
//! only classify P2MS outputs, preventing non-P2MS pollution in the classification table.

use crate::types::TransactionOutput;

/// Filter to ONLY P2MS outputs for spendability classification.
///
/// **CRITICAL**: All protocol classifiers MUST use this when inserting
/// into `p2ms_output_classifications` to prevent non-P2MS pollution.
///
/// # Why This Exists
///
/// `EnrichedTransaction.outputs` contains ALL output types (P2PKH, P2SH, OP_RETURN, P2MS, etc.)
/// for protocol detection purposes (Exodus address, OP_RETURN markers, etc.). However, only
/// P2MS outputs should be classified and inserted into `p2ms_output_classifications`.
///
/// This helper enforces that constraint at the application level (complemented by a database
/// trigger at the data level).
///
/// # Examples
///
/// ```rust,ignore
/// use crate::processor::stage3::filter_p2ms_for_classification;
///
/// fn classify(&self, tx: &EnrichedTransaction, db: &Database) -> Option<ClassificationResult> {
///     // Protocol detection can use ANY output type
///     let has_exodus = tx.outputs.iter().any(|o| is_exodus_address(o));
///
///     if !has_exodus {
///         return None;
///     }
///
///     // Classification MUST filter to P2MS ONLY
///     let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
///
///     for output in p2ms_outputs {
///         // Analyse and classify
///         let spendability = SpendabilityAnalyser::analyse(output);
///         db.insert_output_classification(...);  // Only P2MS outputs
///     }
///
///     Some(classification)
/// }
/// ```
pub fn filter_p2ms_for_classification(outputs: &[TransactionOutput]) -> Vec<&TransactionOutput> {
    outputs
        .iter()
        .filter(|o| o.script_type == "multisig")
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_output(script_type: &str, vout: u32) -> TransactionOutput {
        TransactionOutput {
            txid: "test_txid".to_string(),
            vout,
            amount: 10000,
            height: 12345,
            script_hex: "deadbeef".to_string(),
            script_type: script_type.to_string(),
            is_coinbase: false,
            script_size: 25,
            metadata: json!({}),
            address: None,
        }
    }

    #[test]
    fn test_filters_only_multisig() {
        let outputs = vec![
            create_test_output("multisig", 0),
            create_test_output("p2pkh", 1),
            create_test_output("multisig", 2),
            create_test_output("op_return", 3),
            create_test_output("multisig", 4),
            create_test_output("p2sh", 5),
        ];

        let p2ms_outputs = filter_p2ms_for_classification(&outputs);

        assert_eq!(
            p2ms_outputs.len(),
            3,
            "Should filter to only 3 multisig outputs"
        );
        assert_eq!(p2ms_outputs[0].vout, 0);
        assert_eq!(p2ms_outputs[1].vout, 2);
        assert_eq!(p2ms_outputs[2].vout, 4);
    }

    #[test]
    fn test_returns_empty_when_no_multisig() {
        let outputs = vec![
            create_test_output("p2pkh", 0),
            create_test_output("op_return", 1),
            create_test_output("p2sh", 2),
        ];

        let p2ms_outputs = filter_p2ms_for_classification(&outputs);

        assert_eq!(
            p2ms_outputs.len(),
            0,
            "Should return empty vec when no multisig outputs"
        );
    }

    #[test]
    fn test_returns_all_when_all_multisig() {
        let outputs = vec![
            create_test_output("multisig", 0),
            create_test_output("multisig", 1),
            create_test_output("multisig", 2),
        ];

        let p2ms_outputs = filter_p2ms_for_classification(&outputs);

        assert_eq!(
            p2ms_outputs.len(),
            3,
            "Should return all outputs when all are multisig"
        );
    }

    #[test]
    fn test_preserves_references() {
        let outputs = vec![
            create_test_output("multisig", 0),
            create_test_output("p2pkh", 1),
        ];

        let p2ms_outputs = filter_p2ms_for_classification(&outputs);

        // Verify we get references, not copies
        assert_eq!(p2ms_outputs.len(), 1);
        assert_eq!(p2ms_outputs[0].txid, "test_txid");
    }
}
