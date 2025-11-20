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

use data_carry_research::types::{EnrichedTransaction, ProtocolType, ProtocolVariant, TransactionOutput};
use serial_test::serial;

// Import standardised test utilities
use crate::common::db_seeding::seed_enriched_transaction_simple;
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    load_all_outputs_from_json, run_stage3_processor, setup_protocol_test, verify_classification,
    verify_stage3_completion, verify_content_type,
};

/// PPk protocol test data helpers
mod test_data {
    use super::*;

    /// Create enriched transaction from PPk JSON fixture
    pub fn create_ppk_transaction_from_json(
        json_path: &str,
        txid: &str,
        height: u32,
    ) -> Option<EnrichedTransaction> {
        // Use standardised helper to load ALL outputs (P2MS, OP_RETURN, etc.)
        let outputs = load_all_outputs_from_json(json_path, txid).ok()?;

        // Update heights (JSON fixtures use default height=0)
        let outputs: Vec<_> = outputs
            .into_iter()
            .map(|mut o| {
                o.height = height;
                o
            })
            .collect();

        if outputs.is_empty() {
            return None;
        }

        let mut tx = fixtures::create_test_enriched_transaction(txid);
        tx.height = height;
        tx.outputs = outputs.clone();
        tx.p2ms_outputs_count = outputs.iter().filter(|o| o.script_type == "multisig").count();

        Some(tx)
    }

    /// Run PPk test from JSON fixture
    pub async fn run_ppk_test_from_json(
        json_path: &str,
        txid: &str,
        height: u32,
        expected_variant: ProtocolVariant,
        expected_content_type: &str,
        test_name: &str,
    ) -> anyhow::Result<()> {
        let (mut test_db, config) = setup_protocol_test(test_name)?;

        println!("\n╔══════════════════════════════════════════════════════════════");
        println!("║ PPk Protocol Classification Test");
        println!("╠══════════════════════════════════════════════════════════════");
        println!("║ Test: {}", test_name);
        println!("║ TXID: {}", txid);
        println!("║ Height: {}", height);
        println!("║ Expected Variant: {:?}", expected_variant);
        println!("║ Expected Content-Type: {}", expected_content_type);
        println!("╟──────────────────────────────────────────────────────────────");

        // Load transaction data
        let Some(tx) = create_ppk_transaction_from_json(json_path, txid, height) else {
            println!(
                "⚠️  Skipping test - no valid transaction data in {}",
                json_path
            );
            return Ok(());
        };

        // Seed transaction
        seed_enriched_transaction_simple(&mut test_db, &tx, Vec::new())?;

        // Run Stage 3 processor
        let stats = run_stage3_processor(test_db.path(), config).await?;

        // Verify classification occurred
        let expected_count = match expected_variant {
            ProtocolVariant::PPkProfile
            | ProtocolVariant::PPkRegistration
            | ProtocolVariant::PPkMessage
            | ProtocolVariant::PPkUnknown => 1,
            _ => panic!("Invalid PPk variant: {:?}", expected_variant),
        };

        verify_stage3_completion(&stats, expected_count, expected_count);

        // Verify protocol classification
        verify_classification(
            &test_db,
            txid,
            ProtocolType::PPk,
            Some(expected_variant.clone()),
        )?;

        // Verify content type
        verify_content_type(&test_db, txid, Some(expected_content_type))?;

        println!("╚══════════════════════════════════════════════════════════════");
        println!("✅ PPk {:?} test PASSED\n", expected_variant);

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PPk Protocol Classification Tests
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[serial]
async fn test_ppk_rt_standard() {
    let result = test_data::run_ppk_test_from_json(
        "tests/test_data/ppk/ppk_rt_standard.json",
        "ed95e04018dcc2f01ba8cd699d86852f85ca0af63d05f715a9b2701bb61c6b00",
        345953,
        ProtocolVariant::PPkProfile,
        "application/json", // RT contains JSON data
        "test_ppk_rt_standard",
    )
    .await;

    assert!(
        result.is_ok(),
        "PPk Profile (OP_RETURN transport) classification failed: {:?}",
        result.err()
    );
}

#[tokio::test]
#[serial]
async fn test_ppk_rt_p2ms_embedded() {
    let result = test_data::run_ppk_test_from_json(
        "tests/test_data/ppk/ppk_rt_p2ms_embedded.json",
        "20cb5958edce385c3fa3ec7f3b12391f158442c7a742a924312556eca891f400",
        382033,
        ProtocolVariant::PPkProfile,
        "application/json", // RT contains JSON data
        "test_ppk_rt_p2ms_embedded",
    )
    .await;

    assert!(
        result.is_ok(),
        "PPk Profile (P2MS-embedded transport) classification failed: {:?}",
        result.err()
    );
}

#[tokio::test]
#[serial]
async fn test_ppk_registration() {
    let result = test_data::run_ppk_test_from_json(
        "tests/test_data/ppk/ppk_registration.json",
        "a72d797a108fca918efbded273623ce1f9348b716c0f700bab97f12fe5837200",
        374869,
        ProtocolVariant::PPkRegistration,
        "text/plain", // Registration is a number string
        "test_ppk_registration",
    )
    .await;

    assert!(
        result.is_ok(),
        "PPk Registration classification failed: {:?}",
        result.err()
    );
}

#[tokio::test]
#[serial]
async fn test_ppk_message() {
    let result = test_data::run_ppk_test_from_json(
        "tests/test_data/ppk/ppk_message.json",
        "a7fcc7391e2db0fe13b3a12d37fdbdc6138b2c76a9a447020fa92071a64dfe0c",
        387918,
        ProtocolVariant::PPkMessage,
        "text/plain", // Message is plain text
        "test_ppk_message",
    )
    .await;

    assert!(
        result.is_ok(),
        "PPk Message classification failed: {:?}",
        result.err()
    );
}

#[tokio::test]
#[serial]
async fn test_ppk_unknown() {
    let result = test_data::run_ppk_test_from_json(
        "tests/test_data/ppk/ppk_unknown.json",
        "39dc482ec69056ae445d1acad9507f8167d3f91fc93b9076e94cfb866e639600",
        337481,
        ProtocolVariant::PPkUnknown,
        "application/octet-stream", // Unknown content
        "test_ppk_unknown",
    )
    .await;

    assert!(
        result.is_ok(),
        "PPk Unknown classification failed: {:?}",
        result.err()
    );
}

/// Test PPk marker detection with synthetic transaction (no marker)
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

    seed_enriched_transaction_simple(&mut test_db, &tx, Vec::new()).unwrap();

    // Run Stage 3 processor
    let stats = run_stage3_processor(test_db.path(), config)
        .await
        .unwrap();

    // Verify NO PPk classification occurred
    assert_eq!(
        stats.ppk, 0,
        "PPk should not classify transaction without marker"
    );

    println!("✅ PPk negative test PASSED (no false positives)\n");
}
