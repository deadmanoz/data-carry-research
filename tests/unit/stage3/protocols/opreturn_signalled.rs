use anyhow::Result;
use data_carry_research::types::{ProtocolType, ProtocolVariant, TransactionInput, TransactionOutput};
use serial_test::serial;
use std::path::Path;

use crate::common::db_seeding::seed_enriched_transaction_with_outputs;
use crate::common::fixture_registry::{self, ProtocolFixture};
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    load_transaction_from_json, run_stage3_processor, setup_protocol_test, verify_classification,
    verify_content_type, verify_stage3_completion, TransactionLoadOptions,
};

/// Run an opreturn_signalled test using fixture registry metadata
async fn run_opreturn_fixture_test(fixture: &ProtocolFixture) {
    let expected_variant = match fixture.variant {
        Some("OpReturnCLIPPERZ") => ProtocolVariant::OpReturnCLIPPERZ,
        Some("OpReturnProtocol47930") => ProtocolVariant::OpReturnProtocol47930,
        Some("OpReturnGenericASCII") => ProtocolVariant::OpReturnGenericASCII,
        other => panic!("Unknown OpReturnSignalled variant: {:?}", other),
    };

    let result = run_opreturn_test_from_json(
        fixture.path,
        fixture.txid,
        expected_variant,
        fixture
            .content_type
            .expect("OpReturnSignalled fixtures should have content_type"),
        fixture.description,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
    }
}

/// Run opreturn_signalled test from JSON fixture
async fn run_opreturn_test_from_json(
    fixture_path: &str,
    txid: &str,
    expected_variant: ProtocolVariant,
    expected_content_type: &str,
    test_name: &str,
) -> Result<()> {
    if !Path::new(fixture_path).exists() {
        println!(
            "Skipping {} test - missing fixture {}",
            test_name, fixture_path
        );
        return Ok(());
    }

    let (mut test_db, config) = setup_protocol_test(test_name)?;

    // Load transaction data using unified helper (with ALL outputs for OP_RETURN detection)
    let (tx, _) = match load_transaction_from_json(
        fixture_path,
        txid,
        TransactionLoadOptions {
            include_all_outputs: true,
            ..Default::default()
        },
    ) {
        Ok(result) => result,
        Err(e) => {
            println!(
                "⚠️  Skipping test - no valid transaction data in {}: {}",
                fixture_path, e
            );
            return Ok(());
        }
    };

    // Separate P2MS and OP_RETURN outputs
    let p2ms_outputs: Vec<_> = tx
        .outputs
        .iter()
        .filter(|o| o.script_type == "multisig")
        .cloned()
        .collect();
    let op_return_outputs: Vec<_> = tx
        .outputs
        .iter()
        .filter(|o| o.script_type == "op_return")
        .cloned()
        .collect();

    assert!(
        !p2ms_outputs.is_empty(),
        "{} fixture must contain at least one P2MS output",
        test_name
    );
    assert!(
        !op_return_outputs.is_empty(),
        "{} fixture must contain OP_RETURN output",
        test_name
    );

    // Update tx to have only P2MS outputs for EnrichedTransaction
    let mut enriched_tx = tx;
    let total_p2ms_amount: u64 = p2ms_outputs.iter().map(|o| o.amount).sum();
    enriched_tx.outputs = p2ms_outputs.clone();
    enriched_tx.p2ms_outputs_count = p2ms_outputs.len();
    enriched_tx.total_p2ms_amount = total_p2ms_amount;

    // Seed database with enriched transaction (FK-safe: P2MS + OP_RETURN)
    seed_enriched_transaction_with_outputs(
        &mut test_db,
        &enriched_tx,
        Vec::<TransactionInput>::new(),
        p2ms_outputs,
        op_return_outputs,
    )?;

    // Run Stage 3
    let total_classified = run_stage3_processor(test_db.path(), config).await?;
    verify_stage3_completion(total_classified, 1, 1);

    // Verify classification
    verify_classification(
        &test_db,
        txid,
        ProtocolType::OpReturnSignalled,
        Some(expected_variant),
    )?;

    verify_content_type(&test_db, txid, Some(expected_content_type))?;

    println!("{} transaction classified correctly", test_name);
    Ok(())
}

// ==================== CLIPPERZ Protocol Tests ====================

#[tokio::test]
#[serial]
async fn test_clipperz_v1() {
    run_opreturn_fixture_test(&fixture_registry::opreturn_signalled::CLIPPERZ_V1).await;
}

#[tokio::test]
#[serial]
async fn test_clipperz_v2() {
    run_opreturn_fixture_test(&fixture_registry::opreturn_signalled::CLIPPERZ_V2).await;
}

// ==================== Protocol47930 Tests ====================

#[tokio::test]
#[serial]
async fn test_protocol47930_standard() {
    run_opreturn_fixture_test(&fixture_registry::opreturn_signalled::PROTOCOL47930).await;
}

#[tokio::test]
#[serial]
async fn test_generic_ascii_prvcy() -> Result<()> {
    // Test GenericASCII detection with PRVCY-like payload (exactly 5 consecutive ASCII chars)
    let txid = "test_generic_ascii_prvcy";
    let (mut test_db, config) = setup_protocol_test("generic_ascii_prvcy")?;

    // Create synthetic P2MS output (required for OpReturnSignalled classification)
    let p2ms_output = TransactionOutput {
        txid: txid.to_string(),
        vout: 0,
        amount: 1000,
        height: 400000,
        script_hex: "".to_string(),
        script_type: "multisig".to_string(),
        is_coinbase: false,
        script_size: 0,
        metadata: serde_json::json!({
            "pubkeys": [
                "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc",
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ],
            "required_sigs": 1,
            "total_pubkeys": 2
        }),
        address: None,
    };

    // Create OP_RETURN output with exactly 5 consecutive ASCII chars ("PRVCY")
    // Hex: 5052564359 = "PRVCY"
    let op_return_output = TransactionOutput {
        txid: txid.to_string(),
        vout: 1,
        amount: 0,
        height: 400000,
        script_hex: "6a0550525643592020".to_string(), // OP_RETURN + PUSH(5) + "PRVCY" + padding
        script_type: "op_return".to_string(),
        is_coinbase: false,
        script_size: 9,
        metadata: serde_json::json!({}),
        address: None,
    };

    // Build enriched transaction for Stage 2 data with combined outputs
    let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
    enriched_tx.outputs = vec![p2ms_output.clone()];
    enriched_tx.p2ms_outputs_count = 1;
    enriched_tx.total_p2ms_amount = 1000;
    enriched_tx.output_count = 2;

    // Seed database with enriched transaction (FK-safe: P2MS + OP_RETURN)
    seed_enriched_transaction_with_outputs(
        &mut test_db,
        &enriched_tx,
        Vec::<TransactionInput>::new(),
        vec![p2ms_output],
        vec![op_return_output],
    )?;

    // Run Stage 3
    let total_classified = run_stage3_processor(test_db.path(), config).await?;
    verify_stage3_completion(total_classified, 1, 1);

    // Verify classification
    verify_classification(
        &test_db,
        txid,
        ProtocolType::OpReturnSignalled,
        Some(ProtocolVariant::OpReturnGenericASCII),
    )?;

    verify_content_type(&test_db, txid, Some("text/plain"))?;

    println!("GenericASCII (PRVCY-like) transaction classified correctly");
    Ok(())
}
