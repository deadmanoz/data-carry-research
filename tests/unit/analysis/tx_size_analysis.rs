//! Unit tests for transaction size distribution analysis functionality
//!
//! Tests the TxSizeAnalyser which reports transaction size distributions across
//! P2MS transactions, with global and per-protocol breakdowns plus percentiles.

use crate::common::analysis_test_setup::{
    create_analysis_test_db, insert_complete_p2ms_output, insert_test_output_classification,
    insert_test_tx_classification, seed_analysis_blocks, TestClassificationParams,
    TestOutputClassificationParams,
};
use data_carry_research::analysis::analyse_tx_sizes;
use data_carry_research::errors::AppResult;
use data_carry_research::types::ProtocolType;

/// Helper to insert an enriched transaction with specific size and fee parameters.
///
/// This is specific to tx_size tests as they need precise control over sizes and fees.
fn insert_size_test_enriched_tx(
    db: &data_carry_research::database::Database,
    txid: &str,
    height: i64,
    size_bytes: i64,
    fee: i64,
    is_coinbase: bool,
) -> AppResult<()> {
    let fee_per_byte = if size_bytes > 0 {
        fee as f64 / size_bytes as f64
    } else {
        0.0
    };
    let conn = db.connection();
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES (?1, ?2, 2000, 1000, ?3, ?4, ?5, ?6, 1000, ?4, 1, 1, 1, ?7)",
        rusqlite::params![
            txid,
            height,
            fee,
            fee_per_byte,
            size_bytes,
            fee_per_byte * 1000.0,
            is_coinbase as i32
        ],
    )?;
    Ok(())
}

/// Seed test data with transactions at various size boundaries
///
/// Creates transactions at these specific sizes to test bucket assignment:
/// - 100 bytes (bucket 0: [0, 250))
/// - 300 bytes (bucket 1: [250, 500))
/// - 6000 bytes (bucket 5: [5000, 10000))
/// - 150000 bytes (bucket 9: [100000, ∞))
fn seed_size_test_data(db: &data_carry_research::database::Database) -> AppResult<()> {
    seed_analysis_blocks(db, &[100000, 100001])?;

    // small_tx: 100 bytes, 1000 sats fee (BitcoinStamps StampsClassic)
    insert_complete_p2ms_output(db, "small_tx", 0, 100000, 1000, 100)?;
    insert_size_test_enriched_tx(db, "small_tx", 100000, 100, 1000, false)?;
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("small_tx", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::unspendable("small_tx", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    // medium_tx: 300 bytes, 2000 sats fee (BitcoinStamps StampsSRC20)
    insert_complete_p2ms_output(db, "medium_tx", 0, 100000, 1000, 300)?;
    insert_size_test_enriched_tx(db, "medium_tx", 100000, 300, 2000, false)?;
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("medium_tx", "BitcoinStamps")
            .with_variant("StampsSRC20")
            .with_content_type("application/json"),
    )?;
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::unspendable("medium_tx", 0, "BitcoinStamps")
            .with_variant("StampsSRC20")
            .with_content_type("application/json"),
    )?;

    // large_tx: 6000 bytes, 9000 sats fee (Counterparty)
    insert_complete_p2ms_output(db, "large_tx", 0, 100001, 1000, 6000)?;
    insert_size_test_enriched_tx(db, "large_tx", 100001, 6000, 9000, false)?;
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("large_tx", "Counterparty"),
    )?;
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::unspendable("large_tx", 0, "Counterparty"),
    )?;

    // huge_tx: 150000 bytes, 199000 sats fee (BitcoinStamps StampsClassic)
    insert_complete_p2ms_output(db, "huge_tx", 0, 100001, 1000, 150000)?;
    insert_size_test_enriched_tx(db, "huge_tx", 100001, 150000, 199000, false)?;
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("huge_tx", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::unspendable("huge_tx", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    Ok(())
}

#[test]
fn test_global_distribution_bucket_assignment() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // Verify total transactions
    assert_eq!(
        report.global_distribution.total_transactions, 4,
        "Should have 4 transactions"
    );

    // Verify bucket assignments
    // Bucket 0: [0, 250) - should have small_tx (100 bytes)
    assert_eq!(
        report.global_distribution.buckets[0].count, 1,
        "Bucket [0, 250) should have 1 transaction"
    );

    // Bucket 1: [250, 500) - should have medium_tx (300 bytes)
    assert_eq!(
        report.global_distribution.buckets[1].count, 1,
        "Bucket [250, 500) should have 1 transaction"
    );

    // Bucket 5: [5000, 10000) - should have large_tx (6000 bytes)
    assert_eq!(
        report.global_distribution.buckets[5].count, 1,
        "Bucket [5000, 10000) should have 1 transaction"
    );

    // Bucket 9: [100000, ∞) - should have huge_tx (150000 bytes)
    assert_eq!(
        report.global_distribution.buckets[9].count, 1,
        "Bucket [100000+] should have 1 transaction"
    );

    Ok(())
}

#[test]
fn test_total_fees_in_buckets() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // Total fees: 1000 + 2000 + 9000 + 199000 = 211000 sats
    assert_eq!(
        report.global_distribution.total_fees_sats, 211000,
        "Total fees should be 211000 sats"
    );

    // Bucket 0 should have 1000 sats fee (small_tx)
    assert_eq!(
        report.global_distribution.buckets[0].value, 1000,
        "Bucket [0, 250) should have 1000 sats fees"
    );

    // Bucket 9 should have 199000 sats fee (huge_tx)
    assert_eq!(
        report.global_distribution.buckets[9].value, 199000,
        "Bucket [100000+] should have 199000 sats fees"
    );

    Ok(())
}

#[test]
fn test_percentiles_calculation() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // With 4 transactions: 100, 300, 6000, 150000 (sorted)
    // Percentile indices: (n-1) * p / 100 where n=4
    // p25: (3 * 25) / 100 = 0 → sizes[0] = 100
    // p50: (3 * 50) / 100 = 1 → sizes[1] = 300
    // p75: (3 * 75) / 100 = 2 → sizes[2] = 6000
    // p90: (3 * 90) / 100 = 2 → sizes[2] = 6000
    // p95: (3 * 95) / 100 = 2 → sizes[2] = 6000
    // p99: (3 * 99) / 100 = 2 → sizes[2] = 6000

    let percentiles = report
        .global_distribution
        .percentiles
        .expect("Should have percentiles");

    assert_eq!(percentiles.p25, 100, "p25 should be 100 bytes");
    assert_eq!(percentiles.p50, 300, "p50 should be 300 bytes");
    assert_eq!(percentiles.p75, 6000, "p75 should be 6000 bytes");
    assert_eq!(percentiles.p90, 6000, "p90 should be 6000 bytes");
    assert_eq!(
        percentiles.p99, 6000,
        "p99 should be 6000 bytes (small dataset)"
    );

    Ok(())
}

#[test]
fn test_per_protocol_distribution() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // Should have 2 protocols: BitcoinStamps and Counterparty
    assert_eq!(
        report.protocol_distributions.len(),
        2,
        "Should have 2 protocols"
    );

    // Find BitcoinStamps (3 transactions: small, medium, huge)
    let stamps = report
        .protocol_distributions
        .iter()
        .find(|p| p.protocol == ProtocolType::BitcoinStamps)
        .expect("Should have BitcoinStamps");

    assert_eq!(
        stamps.total_transactions, 3,
        "BitcoinStamps has 3 transactions"
    );
    // Total fees: 1000 + 2000 + 199000 = 202000
    assert_eq!(
        stamps.total_fees_sats, 202000,
        "BitcoinStamps total fees: 202000"
    );

    // Find Counterparty (1 transaction: large)
    let cp = report
        .protocol_distributions
        .iter()
        .find(|p| p.protocol == ProtocolType::Counterparty)
        .expect("Should have Counterparty");

    assert_eq!(cp.total_transactions, 1, "Counterparty has 1 transaction");
    assert_eq!(cp.total_fees_sats, 9000, "Counterparty total fees: 9000");

    Ok(())
}

#[test]
fn test_protocol_ordering() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // Protocols should be sorted by canonical ProtocolType enum discriminant order
    // BitcoinStamps comes before Counterparty in the enum
    assert_eq!(report.protocol_distributions.len(), 2);
    assert_eq!(
        report.protocol_distributions[0].protocol,
        ProtocolType::BitcoinStamps
    );
    assert_eq!(
        report.protocol_distributions[1].protocol,
        ProtocolType::Counterparty
    );

    Ok(())
}

#[test]
fn test_empty_database() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    // Don't seed any data

    let report = analyse_tx_sizes(&db)?;

    // All counts should be zero
    assert_eq!(report.global_distribution.total_transactions, 0);
    assert_eq!(report.global_distribution.total_fees_sats, 0);
    assert_eq!(report.global_distribution.total_size_bytes, 0);
    assert!(report.global_distribution.percentiles.is_none());

    // All buckets should be empty
    for bucket in &report.global_distribution.buckets {
        assert_eq!(bucket.count, 0);
        assert_eq!(bucket.value, 0);
    }

    // No protocol distributions
    assert!(report.protocol_distributions.is_empty());

    Ok(())
}

#[test]
fn test_min_max_avg_sizes() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // Min: 100, Max: 150000
    assert_eq!(
        report.global_distribution.min_size_bytes,
        Some(100),
        "Min size should be 100 bytes"
    );
    assert_eq!(
        report.global_distribution.max_size_bytes,
        Some(150000),
        "Max size should be 150000 bytes"
    );

    // Total size: 100 + 300 + 6000 + 150000 = 156400
    assert_eq!(
        report.global_distribution.total_size_bytes, 156400,
        "Total size should be 156400 bytes"
    );

    // Average: 156400 / 4 = 39100
    let expected_avg = 156400.0 / 4.0;
    let actual_avg = report.global_distribution.avg_size_bytes;
    assert!(
        (actual_avg - expected_avg).abs() < 0.01,
        "Average size should be {:.2}, got {:.2}",
        expected_avg,
        actual_avg
    );

    Ok(())
}

#[test]
fn test_excluded_zero_size_count() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;
    let conn = db.connection();

    // Add a transaction with zero size (should be excluded from analysis)
    seed_analysis_blocks(&db, &[100002])?;
    insert_complete_p2ms_output(&db, "zero_size_tx", 0, 100002, 1000, 100)?;

    // Insert with transaction_size_bytes = 0 (indicates missing/invalid data)
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('zero_size_tx', 100002, 2000, 1000, 1000, 0.0, 0, 0.0, 1000, 0.0, 1, 1, 1, 0)",
        [],
    )?;

    let report = analyse_tx_sizes(&db)?;

    // Should still have 4 transactions (zero-size excluded)
    assert_eq!(
        report.global_distribution.total_transactions, 4,
        "Should have 4 transactions (zero-size excluded)"
    );

    // Should track the excluded count
    assert_eq!(
        report.global_distribution.excluded_null_count, 1,
        "Should have 1 excluded transaction with zero size"
    );

    Ok(())
}

#[test]
fn test_coinbase_excluded() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Regular transaction (should be included)
    insert_complete_p2ms_output(&db, "regular_tx", 0, 100000, 1000, 100)?;
    insert_size_test_enriched_tx(&db, "regular_tx", 100000, 100, 1000, false)?;

    // Coinbase transaction (should be excluded)
    insert_complete_p2ms_output(&db, "coinbase_tx", 0, 100000, 5000000, 200)?;
    insert_size_test_enriched_tx(&db, "coinbase_tx", 100000, 200, 0, true)?;

    let report = analyse_tx_sizes(&db)?;

    // Should only have 1 transaction (coinbase excluded)
    assert_eq!(
        report.global_distribution.total_transactions, 1,
        "Should have 1 transaction (coinbase excluded)"
    );
    assert_eq!(
        report.global_distribution.total_size_bytes, 100,
        "Total size should be 100 bytes"
    );

    Ok(())
}

#[test]
fn test_per_protocol_avg_fee_per_byte() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // BitcoinStamps: total_fees = 202000, total_size = 100 + 300 + 150000 = 150400
    // avg_fee_per_byte = 202000 / 150400 ≈ 1.343
    let stamps = report
        .protocol_distributions
        .iter()
        .find(|p| p.protocol == ProtocolType::BitcoinStamps)
        .expect("Should have BitcoinStamps");

    let expected_stamps_avg = 202000.0 / 150400.0;
    assert!(
        (stamps.avg_fee_per_byte - expected_stamps_avg).abs() < 0.01,
        "BitcoinStamps avg_fee_per_byte: expected {:.4}, got {:.4}",
        expected_stamps_avg,
        stamps.avg_fee_per_byte
    );

    // Counterparty: total_fees = 9000, total_size = 6000
    // avg_fee_per_byte = 9000 / 6000 = 1.5
    let cp = report
        .protocol_distributions
        .iter()
        .find(|p| p.protocol == ProtocolType::Counterparty)
        .expect("Should have Counterparty");

    assert!(
        (cp.avg_fee_per_byte - 1.5).abs() < 0.01,
        "Counterparty avg_fee_per_byte: expected 1.5, got {:.4}",
        cp.avg_fee_per_byte
    );

    Ok(())
}

#[test]
fn test_bucket_ranges_consistency() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // Verify bucket ranges are contiguous
    for i in 0..report.global_distribution.buckets.len() - 1 {
        let current = &report.global_distribution.buckets[i];
        let next = &report.global_distribution.buckets[i + 1];

        assert_eq!(
            current.range_max,
            next.range_min,
            "Bucket {} max ({}) should equal bucket {} min ({})",
            i,
            current.range_max,
            i + 1,
            next.range_min
        );
    }

    // Verify first bucket starts at 0
    assert_eq!(
        report.global_distribution.buckets[0].range_min, 0,
        "First bucket should start at 0"
    );

    // Verify last bucket is open-ended (u32::MAX)
    assert_eq!(
        report.global_distribution.buckets.last().unwrap().range_max,
        u32::MAX,
        "Last bucket should be open-ended"
    );

    Ok(())
}

#[test]
fn test_bucket_count_consistency() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_size_test_data(&db)?;

    let report = analyse_tx_sizes(&db)?;

    // Sum of all bucket counts should equal total transactions
    let bucket_sum: usize = report
        .global_distribution
        .buckets
        .iter()
        .map(|b| b.count)
        .sum();
    assert_eq!(
        bucket_sum, report.global_distribution.total_transactions,
        "Bucket counts should sum to total transactions"
    );

    // Sum of all bucket fees should equal total fees
    let fee_sum: u64 = report
        .global_distribution
        .buckets
        .iter()
        .map(|b| b.value)
        .sum();
    assert_eq!(
        fee_sum, report.global_distribution.total_fees_sats,
        "Bucket fees should sum to total fees"
    );

    Ok(())
}
