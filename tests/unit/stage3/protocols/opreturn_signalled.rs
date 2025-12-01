//! Stage 3 OP_RETURN Signalled Protocol Classification Tests
//!
//! This test suite validates the OP_RETURN Signalled protocol classification functionality
//! in the Bitcoin P2MS Data-Carrying Protocol Analyser.
//!
//! ## Test Coverage
//!
//! ### Transaction Patterns Tested:
//! - **CLIPPERZ**: Notarisation protocol with "CLIPPERZ" signature in OP_RETURN
//! - **Protocol47930**: 0xbb3a marker + 2-of-2 multisig
//! - **GenericASCII**: Generic ASCII OP_RETURN protocols (catch-all)
//!
//! ### Real Bitcoin Transactions:
//! All tests use authentic Bitcoin mainnet transaction data from JSON fixtures,
//! ensuring validation against real-world OP_RETURN signalled protocol usage.

use anyhow::Result;
use data_carry_research::types::{ProtocolType, ProtocolVariant, TransactionOutput};
use serial_test::serial;

use crate::common::db_seeding::seed_enriched_transaction;
use crate::common::fixture_registry::{self, ProtocolFixture};
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    run_stage3_processor, setup_protocol_test, verify_classification, verify_content_type,
    verify_stage3_completion, ProtocolTestBuilder,
};

/// Run an opreturn_signalled test using the unified ProtocolTestBuilder
async fn run_opreturn_fixture_test(fixture: &'static ProtocolFixture) {
    // OP_RETURN Signalled requires all outputs for OP_RETURN detection
    let result = ProtocolTestBuilder::from_fixture(fixture)
        .with_all_outputs()
        .execute()
        .await;

    if let Err(e) = result {
        panic!("OpReturnSignalled test failed: {}", e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLIPPERZ Protocol Tests
// ═══════════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol47930 Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn test_protocol47930_standard() {
    run_opreturn_fixture_test(&fixture_registry::opreturn_signalled::PROTOCOL47930).await;
}

// ═══════════════════════════════════════════════════════════════════════════════
// GenericASCII Tests (Synthetic)
// ═══════════════════════════════════════════════════════════════════════════════

/// Test GenericASCII detection with PRVCY-like payload (exactly 5 consecutive ASCII chars)
///
/// This is a synthetic test that creates its own outputs rather than using fixtures,
/// so it cannot use the ProtocolTestBuilder.
#[tokio::test]
#[serial]
async fn test_generic_ascii_prvcy() -> Result<()> {
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

    // Build enriched transaction with ALL outputs
    let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
    enriched_tx.outputs = vec![p2ms_output, op_return_output]; // Both outputs
    enriched_tx.p2ms_outputs_count = 1;
    enriched_tx.total_p2ms_amount = 1000;
    enriched_tx.output_count = 2;

    // Seed database with enriched transaction (FK-safe)
    seed_enriched_transaction(&mut test_db, &enriched_tx, Vec::new())?;

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
