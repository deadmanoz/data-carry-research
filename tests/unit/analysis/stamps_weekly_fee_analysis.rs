//! Unit tests for Bitcoin Stamps weekly fee analysis functionality
//!
//! Tests the StampsWeeklyFeeAnalyser which aggregates transaction fees
//! for Bitcoin Stamps at the week level with proper de-duplication.

use crate::common::analysis_test_setup::create_analysis_test_db;
use data_carry_research::analysis::StampsWeeklyFeeAnalyser;
use data_carry_research::errors::AppResult;

/// Seed a single Bitcoin Stamps transaction with associated data
///
/// FK-compliant seeding order:
/// 1. blocks
/// 2. transaction_outputs
/// 3. p2ms_outputs
/// 4. enriched_transactions
/// 5. transaction_classifications (PARENT - must come BEFORE output classifications)
/// 6. p2ms_output_classifications (CHILD)
///
/// # Arguments
/// * `params` - Transaction parameters (txid, height, timestamp, fee, script_size, is_coinbase, num_outputs)
#[allow(clippy::too_many_arguments)]
fn seed_stamps_transaction(
    conn: &rusqlite::Connection,
    txid: &str,
    height: i64,
    timestamp: Option<i64>,
    fee: i64,
    script_size: i64,
    is_coinbase: bool,
    num_outputs: i32,
) -> AppResult<()> {
    // 1. Insert block (with or without timestamp)
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

    // 2. Insert transaction outputs
    for vout in 0..num_outputs {
        conn.execute(
            "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
             is_coinbase, script_size, metadata_json, is_spent)
             VALUES (?1, ?2, ?3, 500, 'aabbcc', 'multisig', ?4, ?5, '{}', 0)",
            rusqlite::params![
                txid,
                vout,
                height,
                if is_coinbase { 1 } else { 0 },
                script_size
            ],
        )?;
    }

    // 3. Insert p2ms_outputs
    for vout in 0..num_outputs {
        conn.execute(
            "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
             VALUES (?1, ?2, 1, 3, '[]')",
            rusqlite::params![txid, vout],
        )?;
    }

    // 4. Insert enriched transaction
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES (?1, ?2, ?3, ?4, ?5, 1.0, 500, 2.0, ?4, 2.0, ?6, 1, ?6, ?7)",
        rusqlite::params![
            txid,
            height,
            fee + 1000,
            1000,
            fee,
            num_outputs,
            if is_coinbase { 1 } else { 0 }
        ],
    )?;

    // 5. Insert transaction classification (PARENT - must come BEFORE output classifications)
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES (?1, 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'image/png')",
        rusqlite::params![txid],
    )?;

    // 6. Insert p2ms_output_classifications (CHILD)
    for vout in 0..num_outputs {
        conn.execute(
            "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
             classification_method, content_type, is_spendable, spendability_reason)
             VALUES (?1, ?2, 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'image/png', 0, 'InvalidECPoints')",
            rusqlite::params![txid, vout],
        )?;
    }

    Ok(())
}

#[test]
fn test_empty_database() -> AppResult<()> {
    let db = create_analysis_test_db()?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    // All counts should be zero
    assert_eq!(report.total_weeks, 0, "Should have 0 weeks");
    assert_eq!(report.total_transactions, 0, "Should have 0 transactions");
    assert_eq!(report.total_fees_sats, 0, "Should have 0 fees");
    assert!(report.weekly_data.is_empty(), "Weekly data should be empty");

    // Summary should have empty date range strings (not fake dates)
    assert_eq!(
        report.summary.date_range_start, "",
        "Date range start should be empty"
    );
    assert_eq!(
        report.summary.date_range_end, "",
        "Date range end should be empty"
    );
    assert_eq!(
        report.summary.total_fees_btc, 0.0,
        "Total fees BTC should be 0"
    );
    assert_eq!(
        report.summary.avg_fee_per_tx_sats, 0.0,
        "Avg fee should be 0"
    );
    assert_eq!(
        report.summary.avg_fee_per_byte_sats, 0.0,
        "Avg fee/byte should be 0"
    );

    Ok(())
}

#[test]
fn test_single_week_single_transaction() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // 2024-01-11 00:00:00 UTC = 1704931200 (Thursday, start of a week bucket)
    let timestamp = 1704931200i64;
    let fee = 10000i64;
    let script_size = 100i64;

    seed_stamps_transaction(
        conn,
        "stamps_tx1",
        800000,
        Some(timestamp),
        fee,
        script_size,
        false,
        1,
    )?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    assert_eq!(report.total_weeks, 1, "Should have 1 week");
    assert_eq!(report.total_transactions, 1, "Should have 1 transaction");
    assert_eq!(
        report.total_fees_sats, fee as u64,
        "Total fees should match"
    );

    // Verify weekly data
    assert_eq!(report.weekly_data.len(), 1);
    let week = &report.weekly_data[0];
    assert_eq!(week.transaction_count, 1);
    assert_eq!(week.total_fees_sats, fee as u64);
    assert_eq!(week.avg_fee_sats, fee as f64);
    assert_eq!(week.total_script_bytes, script_size as u64);
    assert_eq!(week.avg_fee_per_byte_sats, fee as f64 / script_size as f64);

    // Verify ISO date format
    assert!(
        week.week_start_iso.starts_with("2024-"),
        "ISO date should start with year"
    );
    assert!(
        week.week_end_iso.starts_with("2024-"),
        "End ISO should start with year"
    );

    // Verify summary
    assert!(!report.summary.date_range_start.is_empty());
    assert!(!report.summary.date_range_end.is_empty());
    assert_eq!(report.summary.total_fees_btc, fee as f64 / 100_000_000.0);

    Ok(())
}

#[test]
fn test_multi_week_aggregation() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Week 1: 2024-01-11 (timestamp 1704931200)
    seed_stamps_transaction(
        conn,
        "week1_tx1",
        800000,
        Some(1704931200),
        10000,
        100,
        false,
        1,
    )?;
    seed_stamps_transaction(
        conn,
        "week1_tx2",
        800001,
        Some(1704931200 + 86400),
        20000,
        100,
        false,
        1,
    )?;

    // Week 2: 2024-01-18 (timestamp 1705536000)
    seed_stamps_transaction(
        conn,
        "week2_tx1",
        800100,
        Some(1705536000),
        30000,
        100,
        false,
        1,
    )?;

    // Week 3: 2024-01-25 (timestamp 1706140800)
    seed_stamps_transaction(
        conn,
        "week3_tx1",
        800200,
        Some(1706140800),
        40000,
        100,
        false,
        1,
    )?;
    seed_stamps_transaction(
        conn,
        "week3_tx2",
        800201,
        Some(1706140800 + 3600),
        50000,
        100,
        false,
        1,
    )?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    assert_eq!(report.total_weeks, 3, "Should have 3 weeks");
    assert_eq!(report.total_transactions, 5, "Should have 5 transactions");
    assert_eq!(report.total_fees_sats, 150000, "Total fees should be sum");

    // Verify ordering (by week_bucket ascending)
    assert!(
        report.weekly_data[0].week_bucket < report.weekly_data[1].week_bucket,
        "Week 1 bucket should be less than week 2"
    );
    assert!(
        report.weekly_data[1].week_bucket < report.weekly_data[2].week_bucket,
        "Week 2 bucket should be less than week 3"
    );

    // Week 1: 2 transactions, 30000 sats total
    assert_eq!(report.weekly_data[0].transaction_count, 2);
    assert_eq!(report.weekly_data[0].total_fees_sats, 30000);
    assert_eq!(report.weekly_data[0].avg_fee_sats, 15000.0);

    // Week 2: 1 transaction, 30000 sats
    assert_eq!(report.weekly_data[1].transaction_count, 1);
    assert_eq!(report.weekly_data[1].total_fees_sats, 30000);

    // Week 3: 2 transactions, 90000 sats total
    assert_eq!(report.weekly_data[2].transaction_count, 2);
    assert_eq!(report.weekly_data[2].total_fees_sats, 90000);

    Ok(())
}

#[test]
fn test_multi_output_deduplication() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Single transaction with 3 P2MS outputs - fee should be counted ONCE
    let fee = 50000i64;
    let script_size = 100i64;
    seed_stamps_transaction(
        conn,
        "multi_output_tx",
        800000,
        Some(1704931200),
        fee,
        script_size,
        false,
        3,
    )?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    assert_eq!(
        report.total_transactions, 1,
        "Should have 1 transaction (not 3)"
    );
    assert_eq!(
        report.total_fees_sats, fee as u64,
        "Fee should be counted once"
    );

    let week = &report.weekly_data[0];
    assert_eq!(week.transaction_count, 1, "Week should have 1 transaction");
    assert_eq!(week.total_fees_sats, fee as u64, "Week fee should match");
    // Script bytes should be sum of all outputs: 3 * 100 = 300
    assert_eq!(
        week.total_script_bytes,
        3 * script_size as u64,
        "Script bytes should sum all outputs"
    );

    Ok(())
}

#[test]
fn test_null_timestamp_exclusion() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Transaction with valid timestamp (should be included)
    seed_stamps_transaction(
        conn,
        "valid_tx",
        800000,
        Some(1704931200),
        10000,
        100,
        false,
        1,
    )?;

    // Transaction with NULL timestamp (should be excluded)
    seed_stamps_transaction(conn, "null_ts_tx", 800001, None, 20000, 100, false, 1)?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    assert_eq!(
        report.total_transactions, 1,
        "Should have 1 transaction (NULL timestamp excluded)"
    );
    assert_eq!(
        report.total_fees_sats, 10000,
        "Only valid tx fee should count"
    );

    Ok(())
}

#[test]
fn test_zero_script_bytes_division() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Create a transaction with classification but NO p2ms_output_classifications rows
    // This tests division-by-zero handling for avg_fee_per_byte_sats

    conn.execute(
        "INSERT INTO blocks (height, timestamp) VALUES (800000, 1704931200)",
        [],
    )?;

    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('no_output_tx', 800000, 11000, 1000, 10000, 1.0, 500, 2.0, 1000, 2.0, 1, 1, 1, 0)",
        [],
    )?;

    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('no_output_tx', 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'image/png')",
        [],
    )?;

    // Note: NO p2ms_output_classifications or transaction_outputs rows

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    assert_eq!(report.total_transactions, 1, "Should have 1 transaction");
    assert_eq!(report.total_fees_sats, 10000, "Fee should be counted");

    let week = &report.weekly_data[0];
    assert_eq!(week.total_script_bytes, 0, "Script bytes should be 0");
    assert_eq!(
        week.avg_fee_per_byte_sats, 0.0,
        "Avg fee/byte should be 0.0 (not NaN/Inf)"
    );
    assert!(
        !week.avg_fee_per_byte_sats.is_nan() && !week.avg_fee_per_byte_sats.is_infinite(),
        "Should handle division by zero gracefully"
    );

    Ok(())
}

#[test]
fn test_coinbase_exclusion() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Normal transaction (should be included)
    seed_stamps_transaction(
        conn,
        "normal_tx",
        800000,
        Some(1704931200),
        10000,
        100,
        false,
        1,
    )?;

    // Coinbase transaction (should be excluded)
    seed_stamps_transaction(
        conn,
        "coinbase_tx",
        800001,
        Some(1704931200 + 100),
        20000,
        100,
        true,
        1,
    )?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    assert_eq!(
        report.total_transactions, 1,
        "Should have 1 transaction (coinbase excluded)"
    );
    assert_eq!(
        report.total_fees_sats, 10000,
        "Only normal tx fee should count"
    );

    Ok(())
}

#[test]
fn test_non_stamps_protocols_excluded() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // BitcoinStamps transaction (should be included)
    seed_stamps_transaction(
        conn,
        "stamps_tx",
        800000,
        Some(1704931200),
        10000,
        100,
        false,
        1,
    )?;

    // Counterparty transaction (should be excluded)
    conn.execute(
        "INSERT OR IGNORE INTO blocks (height, timestamp) VALUES (800001, 1704931300)",
        [],
    )?;
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('cp_tx', 800001, 21000, 1000, 20000, 1.0, 500, 2.0, 1000, 2.0, 1, 1, 1, 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('cp_tx', 'Counterparty', NULL, 1, 'SignatureBased', 'application/octet-stream')",
        [],
    )?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    assert_eq!(
        report.total_transactions, 1,
        "Should only have BitcoinStamps transaction"
    );
    assert_eq!(
        report.total_fees_sats, 10000,
        "Only Stamps fee should count"
    );

    Ok(())
}

#[test]
fn test_week_boundary_calculation() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Timestamps exactly at week boundaries
    // Week bucket 2827 starts at 1704844800 (2024-01-10 00:00:00 UTC, a Wednesday)
    // Week bucket 2828 starts at 1705449600 (2024-01-17 00:00:00 UTC)

    seed_stamps_transaction(
        conn,
        "tx_week_2827",
        800000,
        Some(1704844800),
        10000,
        100,
        false,
        1,
    )?;
    seed_stamps_transaction(
        conn,
        "tx_week_2828",
        800001,
        Some(1705449600),
        20000,
        100,
        false,
        1,
    )?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    assert_eq!(report.total_weeks, 2, "Should have 2 weeks");

    // Verify week buckets are consecutive
    assert_eq!(
        report.weekly_data[1].week_bucket - report.weekly_data[0].week_bucket,
        1,
        "Week buckets should be consecutive"
    );

    Ok(())
}

#[test]
fn test_plotly_chart_generation() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    seed_stamps_transaction(conn, "tx1", 800000, Some(1704931200), 10000, 100, false, 1)?;
    seed_stamps_transaction(conn, "tx2", 800001, Some(1705536000), 20000, 200, false, 1)?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;
    let chart = report.to_plotly_chart();

    // Should have 3 traces
    assert_eq!(chart.data.len(), 3, "Should have 3 traces");
    assert_eq!(chart.data[0].name, "Total Fees (BTC)");
    assert_eq!(chart.data[1].name, "Avg Fee/Tx (sats)");
    assert_eq!(chart.data[2].name, "Avg sats/byte");

    // Verify trace types
    assert_eq!(chart.data[0].trace_type, "bar");
    assert_eq!(chart.data[1].trace_type, "scatter");
    assert_eq!(chart.data[2].trace_type, "scatter");

    // Third trace should be hidden by default
    assert_eq!(chart.data[2].visible, Some("legendonly".to_string()));

    // X values should be ISO dates
    assert_eq!(chart.data[0].x.len(), 2);
    assert!(
        chart.data[0].x[0].contains('-'),
        "X values should be ISO dates"
    );

    // Layout should have proper configuration
    assert_eq!(chart.layout.title.text, "Bitcoin Stamps Weekly Fees");
    assert_eq!(chart.layout.xaxis.axis_type, Some("date".to_string()));
    let yaxis2 = chart
        .layout
        .yaxis2
        .as_ref()
        .expect("yaxis2 should be present");
    assert_eq!(yaxis2.overlaying, "y");
    assert_eq!(yaxis2.side, "right");

    Ok(())
}

#[test]
fn test_summary_calculations() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Week 1: 2 tx, 30000 sats, 200 bytes
    seed_stamps_transaction(
        conn,
        "w1_tx1",
        800000,
        Some(1704931200),
        10000,
        100,
        false,
        1,
    )?;
    seed_stamps_transaction(
        conn,
        "w1_tx2",
        800001,
        Some(1704931200 + 100),
        20000,
        100,
        false,
        1,
    )?;

    // Week 2: 1 tx, 30000 sats, 100 bytes
    seed_stamps_transaction(
        conn,
        "w2_tx1",
        800100,
        Some(1705536000),
        30000,
        100,
        false,
        1,
    )?;

    let report = StampsWeeklyFeeAnalyser::analyse_weekly_fees(&db)?;

    // Total: 3 tx, 60000 sats, 300 bytes
    assert_eq!(report.total_transactions, 3);
    assert_eq!(report.total_fees_sats, 60000);

    // Summary avg_fee_per_tx: 60000 / 3 = 20000
    assert_eq!(report.summary.avg_fee_per_tx_sats, 20000.0);

    // Summary total_fees_btc: 60000 / 100_000_000 = 0.0006
    assert_eq!(report.summary.total_fees_btc, 0.0006);

    // Date range should span both weeks
    assert!(!report.summary.date_range_start.is_empty());
    assert!(!report.summary.date_range_end.is_empty());
    assert_ne!(
        report.summary.date_range_start,
        report.summary.date_range_end
    );

    Ok(())
}
