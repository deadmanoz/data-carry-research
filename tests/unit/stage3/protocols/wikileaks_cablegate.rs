//! Stage 3 WikiLeaks Cablegate Protocol Classification Tests
//!
//! Tests verifying the WikiLeaks Cablegate classification logic:
//! - Tool transactions detected by hardcoded TXIDs (don't have donation address)
//! - Data transactions require WikiLeaks donation address + height range 229,991-230,256
//! - Output count alone does NOT trigger classification (bug fix)

use data_carry_research::database::traits::Stage1Operations;
use data_carry_research::processor::stage3::wikileaks_cablegate::WikiLeaksCablegateClassifier;
use data_carry_research::processor::stage3::ProtocolSpecificClassifier;
use data_carry_research::types::{script_metadata::MultisigInfo, EnrichedTransaction, TransactionOutput};
use serial_test::serial;

use crate::common::fixtures;
use crate::common::protocol_test_base::setup_protocol_test;

/// Create a transaction with specified number of P2MS outputs
fn create_transaction_with_p2ms_outputs(
    txid: &str,
    height: u32,
    num_outputs: usize,
) -> EnrichedTransaction {
    let mut tx = fixtures::create_test_enriched_transaction(txid);
    tx.height = height;

    let info = MultisigInfo {
        pubkeys: vec![
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".to_string(),
        ],
        required_sigs: 1,
        total_pubkeys: 2,
    };

    let outputs: Vec<TransactionOutput> = (0..num_outputs)
        .map(|vout| TransactionOutput {
            txid: txid.to_string(),
            vout: vout as u32,
            height,
            amount: 1000,
            script_hex: "mock_multisig_script".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(&info).unwrap(),
            address: None,
        })
        .collect();

    tx.outputs = outputs;
    tx.p2ms_outputs_count = num_outputs;
    tx
}

/// Bug fix verification: Output count alone does NOT trigger classification
mod bug_fix_verification {
    use super::*;

    #[test]
    #[serial]
    fn test_100_plus_outputs_without_address_not_classified() -> anyhow::Result<()> {
        let (mut test_db, _config) = setup_protocol_test("wikileaks_100_outputs")?;
        let classifier = WikiLeaksCablegateClassifier::new();

        // 105 P2MS outputs but NO WikiLeaks donation address
        let txid = "not_cablegate_100_outputs_1234567890123456789012345678901234";
        let tx = create_transaction_with_p2ms_outputs(txid, 230_000, 105);

        test_db
            .database_mut()
            .insert_transaction_output_batch(&tx.outputs)?;

        let result = classifier.classify(&tx, test_db.database_mut());
        assert!(
            result.is_none(),
            "100+ P2MS outputs WITHOUT WikiLeaks address should NOT be classified"
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_4_to_10_outputs_without_address_not_classified() -> anyhow::Result<()> {
        let (mut test_db, _config) = setup_protocol_test("wikileaks_few_outputs")?;
        let classifier = WikiLeaksCablegateClassifier::new();

        // 6 P2MS outputs (4-10 range from old heuristic) but NO WikiLeaks address
        let txid = "not_cablegate_few_outputs_123456789012345678901234567890123456";
        let tx = create_transaction_with_p2ms_outputs(txid, 229_992, 6);

        test_db
            .database_mut()
            .insert_transaction_output_batch(&tx.outputs)?;

        let result = classifier.classify(&tx, test_db.database_mut());
        assert!(
            result.is_none(),
            "4-10 P2MS outputs WITHOUT WikiLeaks address should NOT be classified"
        );

        Ok(())
    }
}
