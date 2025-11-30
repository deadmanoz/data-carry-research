use anyhow::Result;
use data_carry_research::types::{
    ProtocolType, ProtocolVariant, TransactionInput, TransactionOutput,
};
use serde_json::Value;
use serial_test::serial;
use std::fs::File;
use std::path::Path;

use crate::common::db_seeding::seed_enriched_transaction_with_outputs;
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    load_p2ms_outputs_from_json, run_stage3_processor, setup_protocol_test, verify_classification,
    verify_content_type, verify_stage3_completion,
};

fn extract_op_returns(json_tx: &Value, txid: &str) -> Result<Vec<TransactionOutput>> {
    use data_carry_research::types::script_metadata::parse_opreturn_script;

    let mut outputs = Vec::new();

    if let Some(vouts) = json_tx.get("vout").and_then(|v| v.as_array()) {
        for vout in vouts {
            let script_pub_key = vout.get("scriptPubKey").and_then(|spk| spk.as_object());
            let script_type = script_pub_key
                .and_then(|spk| spk.get("type"))
                .and_then(|t| t.as_str());

            if script_type == Some("nulldata") {
                if let (Some(hex), Some(n), Some(val)) = (
                    script_pub_key
                        .and_then(|spk| spk.get("hex"))
                        .and_then(|h| h.as_str()),
                    vout.get("n").and_then(|n| n.as_u64()),
                    vout.get("value").and_then(|v| v.as_f64()),
                ) {
                    // Parse OP_RETURN using shared parser
                    let metadata = if let Some(op_data) = parse_opreturn_script(hex) {
                        serde_json::json!({
                            "op_return_hex": op_data.op_return_hex,
                            "protocol_prefix_hex": op_data.protocol_prefix_hex,
                            "data_hex": op_data.data_hex,
                            "data_length": op_data.data_length
                        })
                    } else {
                        serde_json::json!({})
                    };

                    outputs.push(TransactionOutput {
                        txid: txid.to_string(),
                        vout: n as u32,
                        height: 0,
                        amount: (val * 100_000_000.0) as u64, // Convert BTC to satoshis
                        script_hex: hex.to_string(),
                        script_type: "op_return".to_string(),
                        is_coinbase: false,
                        script_size: hex.len() / 2,
                        metadata,
                        address: None, // OP_RETURN outputs don't have addresses
                    });
                }
            }
        }
    }

    Ok(outputs)
}

// ==================== CLIPPERZ Protocol Tests ====================

#[tokio::test]
#[serial]
async fn test_clipperz_v1() -> Result<()> {
    let txid = "08437467cbb88640b40185169293b138e216ec1a970f596e3c915ce74021d85e";
    let fixture_path = "tests/test_data/opreturn_signalled/clipperz_v1.json";

    if !Path::new(fixture_path).exists() {
        println!(
            "Skipping CLIPPERZ v1 test - missing fixture {}",
            fixture_path
        );
        return Ok(());
    }

    let (mut test_db, config) = setup_protocol_test("clipperz_v1")?;

    // Load P2MS outputs from fixture
    let p2ms_outputs = load_p2ms_outputs_from_json(fixture_path, txid)?;
    assert!(
        !p2ms_outputs.is_empty(),
        "CLIPPERZ fixture must contain at least one P2MS output"
    );

    // Extract OP_RETURN outputs from fixture
    let json_value: Value = serde_json::from_reader(File::open(fixture_path)?)?;
    let op_return_outputs = extract_op_returns(&json_value, txid)?;
    assert!(
        !op_return_outputs.is_empty(),
        "CLIPPERZ fixture must contain OP_RETURN output"
    );

    // Build enriched transaction for Stage 2 data
    let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
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
        Some(ProtocolVariant::OpReturnCLIPPERZ),
    )?;

    verify_content_type(&test_db, txid, Some("application/octet-stream"))?;

    println!("CLIPPERZ v1 transaction classified correctly");
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_clipperz_v2() -> Result<()> {
    let txid = "4bc03ae94ae9775db84fc3d7ef859fad9d4267beacf209ac53bd960ed6a4a0b2";
    let fixture_path = "tests/test_data/opreturn_signalled/clipperz_v2.json";

    if !Path::new(fixture_path).exists() {
        println!(
            "Skipping CLIPPERZ v2 test - missing fixture {}",
            fixture_path
        );
        return Ok(());
    }

    let (mut test_db, config) = setup_protocol_test("clipperz_v2")?;

    // Load P2MS outputs
    let p2ms_outputs = load_p2ms_outputs_from_json(fixture_path, txid)?;
    assert!(
        !p2ms_outputs.is_empty(),
        "CLIPPERZ fixture must contain at least one P2MS output"
    );

    // Extract OP_RETURN outputs from fixture
    let json_value: Value = serde_json::from_reader(File::open(fixture_path)?)?;
    let op_return_outputs = extract_op_returns(&json_value, txid)?;
    assert!(
        !op_return_outputs.is_empty(),
        "CLIPPERZ fixture must contain OP_RETURN output"
    );

    // Build enriched transaction for Stage 2 data with combined outputs
    let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
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
        Some(ProtocolVariant::OpReturnCLIPPERZ),
    )?;

    verify_content_type(&test_db, txid, Some("application/octet-stream"))?;

    println!("CLIPPERZ v2 transaction classified correctly");
    Ok(())
}

// ==================== Protocol47930 Tests ====================

#[tokio::test]
#[serial]
async fn test_protocol47930_standard() -> Result<()> {
    let txid = "82d0872a72032c21cadfa1f7590f661f00c1bc663c4eb93b5730df40c7b87cbf";
    let fixture_path = "tests/test_data/opreturn_signalled/protocol47930.json";

    if !Path::new(fixture_path).exists() {
        println!(
            "Skipping Protocol47930 test - missing fixture {}",
            fixture_path
        );
        return Ok(());
    }

    let (mut test_db, config) = setup_protocol_test("protocol47930_standard")?;

    // Load P2MS outputs
    let p2ms_outputs = load_p2ms_outputs_from_json(fixture_path, txid)?;
    assert!(
        !p2ms_outputs.is_empty(),
        "Protocol47930 fixture must contain at least one P2MS output"
    );

    // Extract OP_RETURN outputs from fixture
    let json_value: Value = serde_json::from_reader(File::open(fixture_path)?)?;
    let op_return_outputs = extract_op_returns(&json_value, txid)?;
    assert!(
        !op_return_outputs.is_empty(),
        "Protocol47930 fixture must contain OP_RETURN output"
    );

    // Build enriched transaction for Stage 2 data with combined outputs
    let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
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
        Some(ProtocolVariant::OpReturnProtocol47930),
    )?;

    verify_content_type(&test_db, txid, Some("application/octet-stream"))?;

    println!("Protocol47930 transaction classified correctly");
    Ok(())
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
