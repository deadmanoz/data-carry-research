//! Unit tests for Bitcoin Stamps variant temporal distribution analysis
//!
//! Tests the StampsVariantTemporalAnalyser which aggregates Bitcoin Stamps outputs
//! by variant over weekly time buckets.

use crate::common::analysis_test_setup::create_analysis_test_db;
use data_carry_research::analysis::StampsVariantTemporalAnalyser;
use data_carry_research::errors::AppResult;

/// Seed a Bitcoin Stamps output with specified variant
///
/// FK-compliant seeding order:
/// 1. blocks
/// 2. transaction_outputs
/// 3. p2ms_outputs
/// 4. enriched_transactions
/// 5. transaction_classifications (PARENT)
/// 6. p2ms_output_classifications (CHILD)
#[allow(clippy::too_many_arguments)]
fn seed_stamps_output(
    conn: &rusqlite::Connection,
    txid: &str,
    vout: i32,
    height: i64,
    timestamp: Option<i64>,
    amount: i64,
    variant: Option<&str>,
) -> AppResult<()> {
    // 1. Insert block
    if let Some(ts) = timestamp {
        conn.execute(
            "INSERT OR IGNORE INTO blocks (height, timestamp) VALUES (?1, ?2)",
            [height, ts],
        )?;
    } else {
        conn.execute(
            "INSERT OR IGNORE INTO blocks (height, timestamp) VALUES (?1, NULL)",
            [height],
        )?;
    }

    // 2. Insert transaction output
    conn.execute(
        "INSERT OR IGNORE INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES (?1, ?2, ?3, ?4, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        rusqlite::params![txid, vout, height, amount],
    )?;

    // 3. Insert p2ms_outputs
    conn.execute(
        "INSERT OR IGNORE INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES (?1, ?2, 1, 3, '[]')",
        rusqlite::params![txid, vout],
    )?;

    // 4. Insert enriched transaction
    conn.execute(
        "INSERT OR IGNORE INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES (?1, ?2, 1000, 500, 500, 1.0, 500, 2.0, 500, 2.0, 1, 1, 1, 0)",
        rusqlite::params![txid, height],
    )?;

    // 5. Insert transaction classification
    conn.execute(
        "INSERT OR IGNORE INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES (?1, 'BitcoinStamps', ?2, 1, 'SignatureBased', 'image/png')",
        rusqlite::params![txid, variant],
    )?;

    // 6. Insert p2ms_output_classification
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES (?1, ?2, 'BitcoinStamps', ?3, 1, 'SignatureBased', 'image/png', 0, 'InvalidECPoints')",
        rusqlite::params![txid, vout, variant],
    )?;

    Ok(())
}

#[test]
fn test_empty_database() -> AppResult<()> {
    let db = create_analysis_test_db()?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    assert_eq!(report.total_outputs, 0, "Should have 0 outputs");
    assert_eq!(report.total_value_sats, 0, "Should have 0 value");
    assert!(
        report.variant_totals.is_empty(),
        "Variant totals should be empty"
    );
    assert!(report.weekly_data.is_empty(), "Weekly data should be empty");
    assert!(
        report.first_appearances.is_empty(),
        "First appearances should be empty"
    );
    assert_eq!(
        report.null_variant_count, 0,
        "NULL variant count should be 0"
    );
    assert_eq!(report.date_range_start, "", "Date range should be empty");
    assert_eq!(report.date_range_end, "", "Date range should be empty");

    Ok(())
}

#[test]
fn test_single_variant_single_week() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // 2024-01-11 00:00:00 UTC = 1704931200 (Thursday, start of a week bucket)
    let timestamp = 1704931200i64;

    seed_stamps_output(
        conn,
        "tx1",
        0,
        800000,
        Some(timestamp),
        1000,
        Some("Classic"),
    )?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    assert_eq!(report.total_outputs, 1, "Should have 1 output");
    assert_eq!(report.total_value_sats, 1000, "Value should be 1000");
    assert_eq!(report.variant_totals.len(), 1, "Should have 1 variant");
    assert_eq!(report.variant_totals[0].variant, "Classic");
    assert_eq!(report.variant_totals[0].count, 1);
    assert!((report.variant_totals[0].percentage - 100.0).abs() < 0.01);

    assert_eq!(report.weekly_data.len(), 1, "Should have 1 weekly entry");
    assert_eq!(report.weekly_data[0].variant, "Classic");
    assert_eq!(report.weekly_data[0].count, 1);

    assert_eq!(
        report.first_appearances.len(),
        1,
        "Should have 1 first appearance"
    );
    assert_eq!(report.first_appearances[0].variant, "Classic");
    assert_eq!(report.first_appearances[0].first_height, 800000);

    Ok(())
}

#[test]
fn test_multiple_variants_single_week() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    let timestamp = 1704931200i64; // 2024-01-11

    seed_stamps_output(
        conn,
        "tx1",
        0,
        800000,
        Some(timestamp),
        1000,
        Some("Classic"),
    )?;
    seed_stamps_output(
        conn,
        "tx2",
        0,
        800001,
        Some(timestamp + 100),
        2000,
        Some("SRC-20"),
    )?;
    seed_stamps_output(
        conn,
        "tx3",
        0,
        800002,
        Some(timestamp + 200),
        3000,
        Some("Classic"),
    )?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    assert_eq!(report.total_outputs, 3, "Should have 3 outputs");
    assert_eq!(report.total_value_sats, 6000, "Total value should be 6000");

    // Check variant totals (sorted by count descending)
    assert_eq!(report.variant_totals.len(), 2, "Should have 2 variants");
    assert_eq!(report.variant_totals[0].variant, "Classic");
    assert_eq!(report.variant_totals[0].count, 2);
    assert_eq!(report.variant_totals[1].variant, "SRC-20");
    assert_eq!(report.variant_totals[1].count, 1);

    // Percentages should sum to ~100%
    let total_pct: f64 = report.variant_totals.iter().map(|v| v.percentage).sum();
    assert!(
        (total_pct - 100.0).abs() < 0.01,
        "Percentages should sum to ~100%"
    );

    Ok(())
}

#[test]
fn test_multiple_weeks() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Week 1: 2024-01-11 (timestamp 1704931200)
    seed_stamps_output(
        conn,
        "w1_tx1",
        0,
        800000,
        Some(1704931200),
        1000,
        Some("Classic"),
    )?;

    // Week 2: 2024-01-18 (timestamp 1705536000)
    seed_stamps_output(
        conn,
        "w2_tx1",
        0,
        800100,
        Some(1705536000),
        2000,
        Some("SRC-20"),
    )?;
    seed_stamps_output(
        conn,
        "w2_tx2",
        0,
        800101,
        Some(1705536000 + 100),
        3000,
        Some("Classic"),
    )?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    assert_eq!(report.total_outputs, 3, "Should have 3 outputs");

    // Weekly data should have entries for both weeks and both variants
    assert!(
        report.weekly_data.len() >= 2,
        "Should have entries for multiple weeks"
    );

    // Check ordering (by week_bucket ascending)
    let week_buckets: Vec<i64> = report.weekly_data.iter().map(|w| w.week_bucket).collect();
    for i in 1..week_buckets.len() {
        assert!(
            week_buckets[i] >= week_buckets[i - 1],
            "Week buckets should be in order"
        );
    }

    Ok(())
}

#[test]
fn test_null_variant_detection() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    let timestamp = 1704931200i64;

    // Valid variant
    seed_stamps_output(
        conn,
        "tx1",
        0,
        800000,
        Some(timestamp),
        1000,
        Some("Classic"),
    )?;

    // NULL variant (bug indicator)
    seed_stamps_output(conn, "tx2", 0, 800001, Some(timestamp + 100), 2000, None)?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    // Main report should only include valid variants
    assert_eq!(report.total_outputs, 1, "Should have 1 valid output");
    assert_eq!(
        report.total_value_sats, 1000,
        "Value should only include valid outputs"
    );

    // NULL variant count should be reported separately
    assert_eq!(report.null_variant_count, 1, "Should detect 1 NULL variant");

    Ok(())
}

#[test]
fn test_null_only_dataset() -> AppResult<()> {
    // Test that databases with ONLY NULL variants still report null_variant_count
    // (fixes bug where null-only datasets returned default report with count=0)
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    let timestamp = 1704931200i64;

    // Only NULL variant outputs (no valid variants)
    seed_stamps_output(conn, "tx1", 0, 800000, Some(timestamp), 1000, None)?;
    seed_stamps_output(conn, "tx2", 0, 800001, Some(timestamp + 100), 2000, None)?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    // Main report should have 0 outputs (NULL variants excluded from weekly data)
    assert_eq!(report.total_outputs, 0, "Should have 0 valid outputs");
    assert!(report.variant_totals.is_empty(), "No valid variants");
    assert!(
        report.weekly_data.is_empty(),
        "No weekly data for NULL variants"
    );

    // BUT null_variant_count should still be populated
    assert_eq!(
        report.null_variant_count, 2,
        "Should detect 2 NULL variants even with no valid outputs"
    );

    Ok(())
}

#[test]
fn test_null_timestamp_exclusion() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Valid timestamp
    seed_stamps_output(
        conn,
        "tx1",
        0,
        800000,
        Some(1704931200),
        1000,
        Some("Classic"),
    )?;

    // NULL timestamp (should be excluded from temporal analysis)
    seed_stamps_output(conn, "tx2", 0, 800001, None, 2000, Some("SRC-20"))?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    // Main report should only include outputs with valid timestamps
    assert_eq!(
        report.total_outputs, 1,
        "Should have 1 output with valid timestamp"
    );
    assert_eq!(report.variant_totals.len(), 1, "Should have 1 variant");
    assert_eq!(report.variant_totals[0].variant, "Classic");

    Ok(())
}

#[test]
fn test_first_appearance_deterministic_tie_breaking() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    let timestamp = 1704931200i64;

    // Two outputs at same height - first_txid should be lexicographically smallest
    seed_stamps_output(
        conn,
        "zzz_txid",
        0,
        800000,
        Some(timestamp),
        1000,
        Some("Classic"),
    )?;
    seed_stamps_output(
        conn,
        "aaa_txid",
        0,
        800000,
        Some(timestamp),
        2000,
        Some("Classic"),
    )?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    assert_eq!(report.first_appearances.len(), 1);
    assert_eq!(report.first_appearances[0].variant, "Classic");
    assert_eq!(report.first_appearances[0].first_height, 800000);
    // "aaa_txid" should be selected as it's lexicographically smallest
    assert_eq!(report.first_appearances[0].first_txid, "aaa_txid");

    Ok(())
}

#[test]
fn test_variant_names_canonical() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    let timestamp = 1704931200i64;
    let variants = [
        "Classic",
        "SRC-20",
        "SRC-721",
        "SRC-101",
        "HTML",
        "Compressed",
        "Data",
        "Unknown",
    ];

    for (i, variant) in variants.iter().enumerate() {
        let txid = format!("tx_{}", i);
        seed_stamps_output(
            conn,
            &txid,
            0,
            800000 + i as i64,
            Some(timestamp + i as i64 * 86400),
            1000,
            Some(variant),
        )?;
    }

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    assert_eq!(
        report.total_outputs,
        variants.len(),
        "Should have all variants"
    );
    assert_eq!(
        report.variant_totals.len(),
        variants.len(),
        "All variants should be distinct"
    );

    // Check that all canonical variant names are present
    let variant_names: Vec<&str> = report
        .variant_totals
        .iter()
        .map(|v| v.variant.as_str())
        .collect();
    for expected in &variants {
        assert!(
            variant_names.contains(expected),
            "Missing variant: {}",
            expected
        );
    }

    Ok(())
}

#[test]
fn test_percentage_calculation() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    let timestamp = 1704931200i64;

    // Create 10 outputs: 7 Classic, 3 SRC-20
    for i in 0..7 {
        let txid = format!("classic_tx_{}", i);
        seed_stamps_output(
            conn,
            &txid,
            0,
            800000 + i,
            Some(timestamp + i * 100),
            1000,
            Some("Classic"),
        )?;
    }
    for i in 0..3 {
        let txid = format!("src20_tx_{}", i);
        seed_stamps_output(
            conn,
            &txid,
            0,
            800100 + i,
            Some(timestamp + (7 + i) * 100),
            1000,
            Some("SRC-20"),
        )?;
    }

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    assert_eq!(report.total_outputs, 10);

    let classic = report
        .variant_totals
        .iter()
        .find(|v| v.variant == "Classic")
        .unwrap();
    let src20 = report
        .variant_totals
        .iter()
        .find(|v| v.variant == "SRC-20")
        .unwrap();

    assert_eq!(classic.count, 7);
    assert!(
        (classic.percentage - 70.0).abs() < 0.01,
        "Classic should be 70%"
    );

    assert_eq!(src20.count, 3);
    assert!(
        (src20.percentage - 30.0).abs() < 0.01,
        "SRC-20 should be 30%"
    );

    // Total percentages should sum to 100%
    let total_pct: f64 = report.variant_totals.iter().map(|v| v.percentage).sum();
    assert!(
        (total_pct - 100.0).abs() < 0.01,
        "Percentages should sum to 100%"
    );

    Ok(())
}

#[test]
fn test_plotly_chart_generation() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Week 1
    seed_stamps_output(
        conn,
        "tx1",
        0,
        800000,
        Some(1704931200),
        1000,
        Some("Classic"),
    )?;
    seed_stamps_output(
        conn,
        "tx2",
        0,
        800001,
        Some(1704931200 + 100),
        2000,
        Some("SRC-20"),
    )?;

    // Week 2
    seed_stamps_output(
        conn,
        "tx3",
        0,
        800100,
        Some(1705536000),
        3000,
        Some("Classic"),
    )?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;
    let chart = report.to_plotly_chart();

    // Should have one trace per variant
    assert_eq!(
        chart.data.len(),
        2,
        "Should have 2 traces (one per variant)"
    );

    // All traces should be stacked area
    for trace in &chart.data {
        assert_eq!(
            trace.stackgroup,
            Some("one".to_string()),
            "Should have stackgroup"
        );
        assert_eq!(trace.fill, Some("tonexty".to_string()), "Should have fill");
        assert_eq!(trace.trace_type, "scatter", "Should be scatter type");
    }

    // Layout should have proper configuration
    assert!(chart.layout.title.text.contains("Bitcoin Stamps Variant"));
    assert_eq!(chart.layout.xaxis.axis_type, Some("date".to_string()));

    Ok(())
}

#[test]
fn test_spent_outputs_excluded() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    let timestamp = 1704931200i64;

    // Unspent output (should be included)
    seed_stamps_output(
        conn,
        "unspent_tx",
        0,
        800000,
        Some(timestamp),
        1000,
        Some("Classic"),
    )?;

    // Manually insert a spent output (FK-compliant order)
    // 1. Block
    conn.execute(
        "INSERT INTO blocks (height, timestamp) VALUES (800001, ?1)",
        [timestamp + 100],
    )?;
    // 2. Transaction output (marked as spent)
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('spent_tx', 0, 800001, 2000, 'aabbcc', 'multisig', 0, 100, '{}', 1)",
        [],
    )?;
    // 3. P2MS output
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('spent_tx', 0, 1, 3, '[]')",
        [],
    )?;
    // 4. Enriched transaction (needed for FK)
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('spent_tx', 800001, 1000, 500, 500, 1.0, 500, 2.0, 500, 2.0, 1, 1, 1, 0)",
        [],
    )?;
    // 5. Transaction classification (PARENT)
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('spent_tx', 'BitcoinStamps', 'SRC-20', 1, 'SignatureBased', 'application/json')",
        [],
    )?;
    // 6. P2MS output classification (CHILD)
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('spent_tx', 0, 'BitcoinStamps', 'SRC-20', 1, 'SignatureBased', 'application/json', 0, 'InvalidECPoints')",
        [],
    )?;

    let report = StampsVariantTemporalAnalyser::analyse_temporal_distribution(&db)?;

    // Only unspent output should be included
    assert_eq!(
        report.total_outputs, 1,
        "Should only have 1 output (spent excluded)"
    );
    assert_eq!(report.variant_totals.len(), 1);
    assert_eq!(report.variant_totals[0].variant, "Classic");

    Ok(())
}
