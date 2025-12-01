//! Stage 3 PPk Protocol Classification Tests
//!
//! This test suite validates the PPk protocol classification functionality
//! in the Bitcoin P2MS Data-Carrying Protocol Analyser.
//!
//! ## Test Coverage
//!
//! ### Transaction Patterns Tested:
//! - **Profile**: JSON profile data via RT transport (two transport encodings tested):
//!   - RT TLV in OP_RETURN with 1-of-2 multisig (OP_RETURN transport)
//!   - RT data in 3rd pubkey + OP_RETURN completion with 1-of-3 multisig (P2MS-embedded transport)
//! - **Registration**: Number string registrations (e.g., "313", "421")
//! - **Message**: Promotional messages containing "PPk" or "ppk" substring
//! - **Unknown**: Other PPk applications with marker pubkey
//!
//! ### PPk Marker Detection:
//! - Primary identification via marker pubkey: `0320a0de360cc2ae8672db7d557086a4e7c8eca062c0a5a4ba9922dee0aacf3e12`
//! - Marker appears in position 2 (second pubkey) of multisig outputs
//! - 4 distinct protocol variants organised by application purpose
//!
//! ### Real Bitcoin Transactions:
//! All tests use authentic Bitcoin mainnet transaction data from JSON fixtures,
//! ensuring validation against real-world PPk protocol usage.

use data_carry_research::database::Database;
use data_carry_research::types::TransactionOutput;
use serial_test::serial;

// Import standardised test utilities
use crate::common::db_seeding::seed_enriched_transaction;
use crate::common::fixture_registry::{self, ProtocolFixture};
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    run_stage3_processor, setup_protocol_test, ProtocolTestBuilder,
};

/// Run a PPk test using the unified ProtocolTestBuilder
async fn run_ppk_fixture_test(fixture: &'static ProtocolFixture) {
    // PPk requires all outputs for RT transport detection via OP_RETURN
    let result = ProtocolTestBuilder::from_fixture(fixture)
        .with_all_outputs()
        .execute()
        .await;

    if let Err(e) = result {
        panic!("PPk test failed: {}", e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PPk Protocol Classification Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn test_ppk_rt_standard() {
    run_ppk_fixture_test(&fixture_registry::ppk::RT_STANDARD).await;
}

#[tokio::test]
#[serial]
async fn test_ppk_rt_p2ms_embedded() {
    run_ppk_fixture_test(&fixture_registry::ppk::RT_P2MS_EMBEDDED).await;
}

#[tokio::test]
#[serial]
async fn test_ppk_registration() {
    run_ppk_fixture_test(&fixture_registry::ppk::REGISTRATION).await;
}

#[tokio::test]
#[serial]
async fn test_ppk_message() {
    run_ppk_fixture_test(&fixture_registry::ppk::MESSAGE).await;
}

#[tokio::test]
#[serial]
async fn test_ppk_unknown() {
    run_ppk_fixture_test(&fixture_registry::ppk::UNKNOWN).await;
}

/// Test PPk marker detection with synthetic transaction (no marker)
///
/// This negative test ensures PPk classification doesn't match transactions
/// without the PPk marker pubkey. Uses synthetic data rather than fixtures.
#[tokio::test]
#[serial]
async fn test_ppk_no_marker_negative() {
    let (mut test_db, config) = setup_protocol_test("test_ppk_no_marker").unwrap();

    // Create transaction WITHOUT PPk marker
    let txid = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut tx = fixtures::create_test_enriched_transaction(txid);
    tx.height = 400000;

    // Add P2MS output WITHOUT PPk marker (different pubkey in position 2)
    use data_carry_research::types::script_metadata::MultisigInfo;
    let info = MultisigInfo {
        pubkeys: vec![
            "0356bbdcfb07e334177b218d5286e51ed7a006b84b4c0b9d241ae530d611641901".to_string(),
            "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(), // NOT PPk marker
            "031f5254207b22766572223a312c2261757468223a2230222c227469746c65223a".to_string(),
        ],
        required_sigs: 1,
        total_pubkeys: 3,
    };

    tx.outputs = vec![TransactionOutput {
        txid: txid.to_string(),
        vout: 0,
        height: 400000,
        amount: 1000,
        script_hex: "51210356bbdcfb07e334177b218d5286e51ed7a006b84b4c0b9d241ae530d6116419012103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff21031f5254207b22766572223a312c2261757468223a2230222c227469746c65223a53ae".to_string(),
        script_type: "multisig".to_string(),
        is_coinbase: false,
        script_size: 105,
        metadata: serde_json::to_value(info).unwrap(),
        address: None,
    }];
    tx.p2ms_outputs_count = 1;

    seed_enriched_transaction(&mut test_db, &tx, Vec::new()).unwrap();

    // Run Stage 3 processor
    let _total_classified = run_stage3_processor(test_db.path(), config).await.unwrap();

    // Verify NO PPk classification occurred using direct SQL query
    let db = Database::new(test_db.path()).unwrap();
    let ppk_count: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'PPk'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        ppk_count, 0,
        "PPk should not classify transaction without marker"
    );

    println!("✅ PPk negative test PASSED (no false positives)\n");
}
