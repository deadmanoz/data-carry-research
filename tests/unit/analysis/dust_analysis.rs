//! Unit tests for dust threshold analysis functionality
//!
//! Tests the DustAnalyser which reports on P2MS outputs relative to Bitcoin Core's
//! dust thresholds (546 sats for non-segwit, 294 sats for segwit destinations).

use crate::common::analysis_test_setup::{
    create_analysis_test_db, insert_complete_p2ms_output, insert_test_enriched_transaction,
    insert_test_output, insert_test_output_classification, insert_test_p2ms_output,
    insert_test_tx_classification, seed_analysis_blocks, TestClassificationParams,
    TestOutputClassificationParams, TestOutputParams, TestP2msOutputParams,
};
use data_carry_research::analysis::analyse_dust_thresholds;
use data_carry_research::errors::AppResult;
use data_carry_research::types::ProtocolType;

use data_carry_research::database::Database;

/// Seed test data with outputs at various dust threshold boundaries
///
/// Creates outputs at these specific amounts to test boundary conditions:
/// - 0 sats (below both thresholds)
/// - 293 sats (below 294, thus below both)
/// - 294 sats (exactly at segwit threshold, below non-segwit)
/// - 545 sats (below 546, above 294)
/// - 546 sats (exactly at non-segwit threshold, not dust)
/// - 547 sats (above both thresholds)
/// - 1000 sats (well above dust)
fn seed_boundary_test_data(db: &Database) -> AppResult<()> {
    // Insert stub blocks
    seed_analysis_blocks(db, &[100000, 100001])?;

    // BitcoinStamps - outputs at 0, 293, 294, 545 sats (all below 546)
    let stamps_amounts = [0, 293, 294, 545];
    for (vout, amount) in stamps_amounts.iter().enumerate() {
        insert_test_output(
            db,
            &TestOutputParams::multisig("stamps_tx1", vout as i64, 100000, *amount, 100),
        )?;
        insert_test_p2ms_output(
            db,
            &TestP2msOutputParams::standard("stamps_tx1", vout as i64),
        )?;
    }

    // Counterparty - outputs at 546, 547, 1000 sats (all at or above 546)
    let cp_amounts = [546, 547, 1000];
    for (vout, amount) in cp_amounts.iter().enumerate() {
        insert_test_output(
            db,
            &TestOutputParams::multisig("cp_tx1", vout as i64, 100001, *amount, 100),
        )?;
        insert_test_p2ms_output(db, &TestP2msOutputParams::standard("cp_tx1", vout as i64))?;
    }

    // Insert enriched transactions
    insert_test_enriched_transaction(db, "stamps_tx1", 100000)?;
    insert_test_enriched_transaction(db, "cp_tx1", 100001)?;

    // Insert transaction classifications (parent)
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("stamps_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("cp_tx1", "Counterparty")
            .with_content_type("application/octet-stream"),
    )?;

    // Insert output classifications (child)
    for vout in 0..4 {
        insert_test_output_classification(
            db,
            &TestOutputClassificationParams::spendable("stamps_tx1", vout, "BitcoinStamps")
                .with_variant("StampsClassic")
                .with_content_type("image/png"),
        )?;
    }
    for vout in 0..3 {
        insert_test_output_classification(
            db,
            &TestOutputClassificationParams::unspendable("cp_tx1", vout, "Counterparty")
                .with_content_type("application/octet-stream"),
        )?;
    }

    Ok(())
}

#[test]
fn test_global_dust_analysis_boundaries() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_boundary_test_data(&db)?;

    let report = analyse_dust_thresholds(&db)?;

    // Verify global totals
    assert_eq!(
        report.global_stats.total_outputs, 7,
        "Should have 7 total outputs"
    );
    // 0 + 293 + 294 + 545 + 546 + 547 + 1000 = 3225
    assert_eq!(
        report.global_stats.total_value_sats, 3225,
        "Total value should be 3225 sats"
    );

    // Below 546 (cumulative): 0, 293, 294, 545 = 4 outputs
    assert_eq!(
        report.global_stats.below_non_segwit_threshold.count, 4,
        "4 outputs below 546 sats"
    );
    // Value: 0 + 293 + 294 + 545 = 1132
    assert_eq!(
        report.global_stats.below_non_segwit_threshold.value, 1132,
        "Value below 546: 1132 sats"
    );

    // Below 294 (subset): 0, 293 = 2 outputs
    assert_eq!(
        report.global_stats.below_segwit_threshold.count, 2,
        "2 outputs below 294 sats"
    );
    // Value: 0 + 293 = 293
    assert_eq!(
        report.global_stats.below_segwit_threshold.value, 293,
        "Value below 294: 293 sats"
    );

    // Above dust (>= 546): 546, 547, 1000 = 3 outputs
    assert_eq!(
        report.global_stats.above_dust.count, 3,
        "3 outputs at or above 546 sats"
    );
    // Value: 546 + 547 + 1000 = 2093
    assert_eq!(
        report.global_stats.above_dust.value, 2093,
        "Value above dust: 2093 sats"
    );

    Ok(())
}

#[test]
fn test_per_protocol_breakdown() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_boundary_test_data(&db)?;

    let report = analyse_dust_thresholds(&db)?;

    // Should have 2 protocols
    assert_eq!(
        report.protocol_breakdown.len(),
        2,
        "Should have 2 protocols"
    );

    // Find BitcoinStamps (all below 546)
    let stamps = report
        .protocol_breakdown
        .iter()
        .find(|p| p.protocol == ProtocolType::BitcoinStamps)
        .expect("Should have BitcoinStamps");
    assert_eq!(stamps.total_outputs, 4, "BitcoinStamps has 4 outputs");
    assert_eq!(
        stamps.below_non_segwit_threshold.count, 4,
        "All 4 below 546"
    );
    assert_eq!(stamps.below_segwit_threshold.count, 2, "2 below 294");
    assert_eq!(stamps.above_dust.count, 0, "0 above dust");

    // Find Counterparty (all at or above 546)
    let cp = report
        .protocol_breakdown
        .iter()
        .find(|p| p.protocol == ProtocolType::Counterparty)
        .expect("Should have Counterparty");
    assert_eq!(cp.total_outputs, 3, "Counterparty has 3 outputs");
    assert_eq!(cp.below_non_segwit_threshold.count, 0, "0 below 546");
    assert_eq!(cp.below_segwit_threshold.count, 0, "0 below 294");
    assert_eq!(cp.above_dust.count, 3, "All 3 above dust");

    Ok(())
}

#[test]
fn test_protocol_ordering() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_boundary_test_data(&db)?;

    let report = analyse_dust_thresholds(&db)?;

    // Protocols should be sorted by canonical ProtocolType enum discriminant order
    // BitcoinStamps comes before Counterparty in the enum
    assert_eq!(report.protocol_breakdown.len(), 2);
    assert_eq!(
        report.protocol_breakdown[0].protocol,
        ProtocolType::BitcoinStamps
    );
    assert_eq!(
        report.protocol_breakdown[1].protocol,
        ProtocolType::Counterparty
    );

    Ok(())
}

#[test]
fn test_empty_database() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    // Don't seed any data

    let report = analyse_dust_thresholds(&db)?;

    // All counts should be zero
    assert_eq!(report.global_stats.total_outputs, 0);
    assert_eq!(report.global_stats.total_value_sats, 0);
    assert_eq!(report.global_stats.below_non_segwit_threshold.count, 0);
    assert_eq!(report.global_stats.below_segwit_threshold.count, 0);
    assert_eq!(report.global_stats.above_dust.count, 0);

    // All percentages should be 0.0 (not NaN from division by zero)
    assert_eq!(
        report.global_stats.below_non_segwit_threshold.pct_count,
        0.0
    );
    assert_eq!(report.global_stats.below_segwit_threshold.pct_count, 0.0);
    assert_eq!(report.global_stats.above_dust.pct_count, 0.0);

    // No protocol breakdown
    assert!(report.protocol_breakdown.is_empty());

    // No unclassified outputs
    assert_eq!(report.unclassified_count, 0);
    assert_eq!(report.unclassified_value_sats, 0);

    Ok(())
}

#[test]
fn test_spent_outputs_excluded() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Unspent output (should be included)
    insert_test_output(
        &db,
        &TestOutputParams::multisig("test_tx1", 0, 100000, 500, 100),
    )?;

    // Spent output (should be excluded)
    insert_test_output(
        &db,
        &TestOutputParams::multisig("test_tx1", 1, 100000, 600, 100).spent(),
    )?;

    let report = analyse_dust_thresholds(&db)?;

    // Should only count the unspent output
    assert_eq!(
        report.global_stats.total_outputs, 1,
        "Should only count unspent output"
    );
    assert_eq!(
        report.global_stats.total_value_sats, 500,
        "Should only count unspent value"
    );

    Ok(())
}

#[test]
fn test_unclassified_vs_unknown() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000, 100001])?;

    // Output classified as Unknown (has classification row with protocol='Unknown')
    insert_complete_p2ms_output(&db, "unknown_tx", 0, 100000, 500, 100)?;
    insert_test_enriched_transaction(&db, "unknown_tx", 100000)?;
    insert_test_tx_classification(&db, &TestClassificationParams::new("unknown_tx", "Unknown"))?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("unknown_tx", 0, "Unknown"),
    )?;

    // Output truly unclassified (no classification row at all)
    insert_complete_p2ms_output(&db, "unclassified_tx", 0, 100001, 600, 100)?;
    // NO classification rows for unclassified_tx - this is intentional for the test

    let report = analyse_dust_thresholds(&db)?;

    // Global should see both outputs
    assert_eq!(report.global_stats.total_outputs, 2);
    assert_eq!(report.global_stats.total_value_sats, 1100);

    // Protocol breakdown should have Unknown (1 output)
    let unknown = report
        .protocol_breakdown
        .iter()
        .find(|p| p.protocol == ProtocolType::Unknown);
    assert!(
        unknown.is_some(),
        "Unknown should appear in protocol breakdown"
    );
    assert_eq!(unknown.unwrap().total_outputs, 1);

    // Unclassified should be tracked separately
    assert_eq!(report.unclassified_count, 1, "1 unclassified output");
    assert_eq!(
        report.unclassified_value_sats, 600,
        "Unclassified value: 600 sats"
    );

    // Reconciliation: classified_outputs_total + unclassified_count = global.total_outputs
    assert_eq!(
        report.classified_outputs_total + report.unclassified_count,
        report.global_stats.total_outputs,
        "Classified + unclassified should equal total"
    );

    Ok(())
}

#[test]
fn test_consistency_validation() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_boundary_test_data(&db)?;

    let report = analyse_dust_thresholds(&db)?;

    // Count consistency: below_546.count + above_dust.count == total_outputs
    let bucket_sum =
        report.global_stats.below_non_segwit_threshold.count + report.global_stats.above_dust.count;
    assert_eq!(
        bucket_sum, report.global_stats.total_outputs,
        "Bucket counts should sum to total"
    );

    // Value consistency: below_546.value + above_dust.value == total_value_sats
    let value_sum =
        report.global_stats.below_non_segwit_threshold.value + report.global_stats.above_dust.value;
    assert_eq!(
        value_sum, report.global_stats.total_value_sats,
        "Bucket values should sum to total"
    );

    // Subset consistency: below_294 <= below_546
    assert!(
        report.global_stats.below_segwit_threshold.count
            <= report.global_stats.below_non_segwit_threshold.count,
        "Below 294 should be subset of below 546"
    );
    assert!(
        report.global_stats.below_segwit_threshold.value
            <= report.global_stats.below_non_segwit_threshold.value,
        "Below 294 value should be subset of below 546 value"
    );

    // Protocol reconciliation
    let protocol_total: usize = report
        .protocol_breakdown
        .iter()
        .map(|p| p.total_outputs)
        .sum();
    assert_eq!(
        protocol_total + report.unclassified_count,
        report.global_stats.total_outputs,
        "Protocol sum + unclassified should equal global total"
    );

    Ok(())
}

#[test]
fn test_percentage_calculations() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_boundary_test_data(&db)?;

    let report = analyse_dust_thresholds(&db)?;

    // 4 out of 7 outputs below 546 = ~57.14%
    let expected_below_546_pct = (4.0 / 7.0) * 100.0;
    let actual = report.global_stats.below_non_segwit_threshold.pct_count;
    assert!(
        (actual - expected_below_546_pct).abs() < 0.01,
        "Below 546 percentage: expected {:.2}, got {:.2}",
        expected_below_546_pct,
        actual
    );

    // 2 out of 7 outputs below 294 = ~28.57%
    let expected_below_294_pct = (2.0 / 7.0) * 100.0;
    let actual = report.global_stats.below_segwit_threshold.pct_count;
    assert!(
        (actual - expected_below_294_pct).abs() < 0.01,
        "Below 294 percentage: expected {:.2}, got {:.2}",
        expected_below_294_pct,
        actual
    );

    // 3 out of 7 outputs above dust = ~42.86%
    let expected_above_pct = (3.0 / 7.0) * 100.0;
    let actual = report.global_stats.above_dust.pct_count;
    assert!(
        (actual - expected_above_pct).abs() < 0.01,
        "Above dust percentage: expected {:.2}, got {:.2}",
        expected_above_pct,
        actual
    );

    // Percentages should sum to ~100%
    let pct_sum = report.global_stats.below_non_segwit_threshold.pct_count
        + report.global_stats.above_dust.pct_count;
    assert!(
        (pct_sum - 100.0).abs() < 0.01,
        "Output percentages should sum to 100%, got {:.2}",
        pct_sum
    );

    Ok(())
}

#[test]
fn test_thresholds_values() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let report = analyse_dust_thresholds(&db)?;

    // Verify threshold constants are correct
    assert_eq!(
        report.thresholds.non_segwit_destination_sats, 546,
        "Non-segwit threshold should be 546"
    );
    assert_eq!(
        report.thresholds.segwit_destination_sats, 294,
        "Segwit threshold should be 294"
    );

    Ok(())
}

#[test]
fn test_all_outputs_in_one_bucket() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // All outputs above dust (1000 sats each)
    for vout in 0..5 {
        insert_complete_p2ms_output(&db, "all_high", vout, 100000, 1000, 100)?;
    }

    let report = analyse_dust_thresholds(&db)?;

    assert_eq!(report.global_stats.total_outputs, 5);
    assert_eq!(report.global_stats.below_non_segwit_threshold.count, 0);
    assert_eq!(report.global_stats.below_segwit_threshold.count, 0);
    assert_eq!(report.global_stats.above_dust.count, 5);
    assert_eq!(report.global_stats.above_dust.pct_count, 100.0);

    Ok(())
}

#[test]
fn test_non_multisig_outputs_excluded() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();
    seed_analysis_blocks(&db, &[100000])?;

    // Multisig output (should be included)
    insert_test_output(
        &db,
        &TestOutputParams::multisig("test_tx", 0, 100000, 500, 100),
    )?;

    // P2PKH output (should be excluded) - uses raw SQL since not multisig
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('test_tx', 1, 100000, 600, 'aabbcc', 'p2pkh', 0, 100, '{}', 0)",
        [],
    )?;

    // OP_RETURN output (should be excluded) - uses raw SQL since not multisig
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('test_tx', 2, 100000, 0, 'aabbcc', 'op_return', 0, 100, '{}', 0)",
        [],
    )?;

    let report = analyse_dust_thresholds(&db)?;

    // Should only count the multisig output
    assert_eq!(
        report.global_stats.total_outputs, 1,
        "Should only count multisig output"
    );
    assert_eq!(
        report.global_stats.total_value_sats, 500,
        "Should only count multisig value"
    );

    Ok(())
}
