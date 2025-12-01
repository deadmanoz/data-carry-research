//! Stage 3 Likely Legitimate Multisig Classification Tests
//!
//! Validates that legitimate multisig transactions (all valid EC points) are:
//! 1. Classified at transaction level
//! 2. Have per-output classifications created
//! 3. Include complete spendability analysis
//!
//! Uses real blockchain transaction data from production database to ensure
//! classification accuracy matches what's observed in practice.

use data_carry_research::types::ProtocolType;
use serial_test::serial;

use crate::common::fixture_registry::likely_legitimate;
use crate::common::protocol_test_base::{
    load_p2ms_outputs_from_json, run_stage3_processor, setup_protocol_test, verify_classification,
    verify_output_spendability, ProtocolTestBuilder,
};
use crate::common::db_seeding::build_and_seed_from_p2ms;

/// Test that real legitimate 2-of-3 multisig is correctly classified
///
/// Uses transaction cd27c98d... from block 234568 (May 2013) - a genuine
/// 2-of-3 multisig with all valid compressed EC point pubkeys.
#[tokio::test]
#[serial]
async fn test_legitimate_multisig_from_fixture() -> anyhow::Result<()> {
    ProtocolTestBuilder::from_fixture(&likely_legitimate::MULTISIG_2OF3_CD27C9)
        .skip_content_type() // LikelyLegitimateMultisig has no content type (not data-carrying)
        .execute()
        .await?;

    Ok(())
}

/// Test spendability analysis details for legitimate multisig
///
/// Verifies that each output has correct spendability data including:
/// - is_spendable = true (all valid EC points)
/// - real_pubkey_count matches actual pubkeys
/// - spendability_reason = "AllValidECPoints"
#[tokio::test]
#[serial]
async fn test_legitimate_p2ms_spendability_details() -> anyhow::Result<()> {
    let fixture = &likely_legitimate::MULTISIG_2OF3_CD27C9;
    let (mut test_db, config) = setup_protocol_test("legitimate_multisig_spendability")?;

    // Load P2MS outputs from fixture
    let p2ms_outputs = load_p2ms_outputs_from_json(fixture.path, fixture.txid)?;

    // Build and seed the transaction
    let _tx = build_and_seed_from_p2ms(
        &mut test_db,
        fixture.txid,
        p2ms_outputs,
        "76979566535003a737813caafcf4ccf841667be6da7dcc282fc1562ecc18d998", // First input txid
    )?;

    // Run Stage 3 classification
    run_stage3_processor(test_db.path(), config).await?;

    // Verify classification
    verify_classification(
        &test_db,
        fixture.txid,
        ProtocolType::LikelyLegitimateMultisig,
        None, // Variant checked separately
    )?;

    // Verify output-level spendability
    verify_output_spendability(&test_db, fixture.txid, ProtocolType::LikelyLegitimateMultisig)?;

    // Verify spendability details
    let conn = rusqlite::Connection::open(test_db.path())?;
    let mut stmt = conn.prepare(
        "SELECT vout, is_spendable, spendability_reason, real_pubkey_count
         FROM p2ms_output_classifications
         WHERE txid = ?1 AND protocol = 'LikelyLegitimateMultisig'
         ORDER BY vout",
    )?;

    let outputs_result: Result<Vec<_>, _> = stmt
        .query_map([fixture.txid], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u8>(3)?,
            ))
        })?
        .collect();

    let output_classifications = outputs_result?;
    assert!(
        !output_classifications.is_empty(),
        "Should have at least one output classification"
    );

    for (vout, is_spendable, reason, real_count) in output_classifications {
        println!(
            "Output {}: is_spendable={}, reason={}, real_count={}",
            vout, is_spendable, reason, real_count
        );
        assert!(is_spendable, "Output {} should be spendable", vout);
        assert_eq!(
            reason, "AllValidECPoints",
            "Output {} should have AllValidECPoints reason",
            vout
        );
        assert!(
            real_count >= 2,
            "Output {} should have at least 2 real pubkeys",
            vout
        );
    }

    Ok(())
}
