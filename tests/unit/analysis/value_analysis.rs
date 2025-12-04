//! Unit tests for value analysis with variant breakdown
//!
//! Tests the `analyse_value_distribution` function which provides per-protocol
//! and per-variant value statistics for P2MS outputs.

use crate::common::analysis_test_setup::create_analysis_test_db;
use data_carry_research::analysis::analyse_value_distribution;
use data_carry_research::errors::AppResult;
use data_carry_research::types::analysis_results::FeeAnalysisReport;

/// Seed a P2MS output with classification data
///
/// FK-compliant seeding order:
/// 1. blocks
/// 2. transaction_outputs
/// 3. p2ms_outputs
/// 4. enriched_transactions
/// 5. transaction_classifications (PARENT)
/// 6. p2ms_output_classifications (CHILD)
#[allow(clippy::too_many_arguments)]
fn seed_classified_output(
    conn: &rusqlite::Connection,
    txid: &str,
    vout: i32,
    height: i64,
    amount: i64,
    protocol: &str,
    variant: Option<&str>,
) -> AppResult<()> {
    // 1. Insert block
    conn.execute(
        "INSERT OR IGNORE INTO blocks (height, timestamp) VALUES (?1, ?1 * 600)",
        [height],
    )?;

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
         VALUES (?1, ?2, 10000, 5000, 500, 1.0, 500, 2.0, 5000, 2.0, 1, 1, 1, 0)",
        rusqlite::params![txid, height],
    )?;

    // 5. Insert transaction classification
    conn.execute(
        "INSERT OR IGNORE INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES (?1, ?2, ?3, 1, 'SignatureBased', 'image/png')",
        rusqlite::params![txid, protocol, variant],
    )?;

    // 6. Insert p2ms_output_classification
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES (?1, ?2, ?3, ?4, 1, 'SignatureBased', 'image/png', 0, 'InvalidECPoints')",
        rusqlite::params![txid, vout, protocol, variant],
    )?;

    Ok(())
}

#[test]
fn test_empty_database() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let fee_report = FeeAnalysisReport::default();

    let report = analyse_value_distribution(&db, fee_report)?;

    assert_eq!(report.overall_statistics.total_outputs_analysed, 0);
    assert_eq!(report.overall_statistics.total_btc_locked_in_p2ms, 0);
    assert!(report.protocol_value_breakdown.is_empty());

    Ok(())
}

#[test]
fn test_single_protocol_no_variants() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Seed output with NULL variant
    seed_classified_output(conn, "tx1", 0, 800000, 10000, "BitcoinStamps", None)?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    assert_eq!(report.overall_statistics.total_outputs_analysed, 1);
    assert_eq!(report.overall_statistics.total_btc_locked_in_p2ms, 10000);
    assert_eq!(report.protocol_value_breakdown.len(), 1);

    let protocol = &report.protocol_value_breakdown[0];
    assert_eq!(protocol.output_count, 1);
    assert_eq!(protocol.total_btc_value_sats, 10000);
    assert!(protocol.variant_breakdown.is_empty());
    assert_eq!(protocol.null_variant_value_sats, 10000);

    Ok(())
}

#[test]
fn test_single_protocol_with_variants() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Seed outputs with variants
    seed_classified_output(
        conn,
        "tx1",
        0,
        800000,
        10000,
        "BitcoinStamps",
        Some("Classic"),
    )?;
    seed_classified_output(
        conn,
        "tx2",
        0,
        800001,
        20000,
        "BitcoinStamps",
        Some("SRC-20"),
    )?;
    seed_classified_output(
        conn,
        "tx3",
        0,
        800002,
        15000,
        "BitcoinStamps",
        Some("Classic"),
    )?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    assert_eq!(report.overall_statistics.total_outputs_analysed, 3);
    assert_eq!(report.overall_statistics.total_btc_locked_in_p2ms, 45000);
    assert_eq!(report.protocol_value_breakdown.len(), 1);

    let protocol = &report.protocol_value_breakdown[0];
    assert_eq!(protocol.output_count, 3);
    assert_eq!(protocol.total_btc_value_sats, 45000);
    assert_eq!(protocol.variant_breakdown.len(), 2);
    assert_eq!(protocol.null_variant_value_sats, 0);

    // Check variants are sorted by value descending
    let classic = protocol
        .variant_breakdown
        .iter()
        .find(|v| v.variant == "Classic")
        .unwrap();
    let src20 = protocol
        .variant_breakdown
        .iter()
        .find(|v| v.variant == "SRC-20")
        .unwrap();

    assert_eq!(classic.output_count, 2);
    assert_eq!(classic.total_btc_value_sats, 25000);
    assert_eq!(src20.output_count, 1);
    assert_eq!(src20.total_btc_value_sats, 20000);

    // First entry should be Classic (25000 > 20000)
    assert_eq!(protocol.variant_breakdown[0].variant, "Classic");
    assert_eq!(protocol.variant_breakdown[1].variant, "SRC-20");

    Ok(())
}

#[test]
fn test_variant_percentages_sum_to_100() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Seed 10 outputs with different variants
    seed_classified_output(
        conn,
        "tx1",
        0,
        800000,
        1000,
        "BitcoinStamps",
        Some("Classic"),
    )?;
    seed_classified_output(
        conn,
        "tx2",
        0,
        800001,
        2000,
        "BitcoinStamps",
        Some("SRC-20"),
    )?;
    seed_classified_output(
        conn,
        "tx3",
        0,
        800002,
        3000,
        "BitcoinStamps",
        Some("Classic"),
    )?;
    seed_classified_output(
        conn,
        "tx4",
        0,
        800003,
        1500,
        "BitcoinStamps",
        Some("SRC-721"),
    )?;
    seed_classified_output(
        conn,
        "tx5",
        0,
        800004,
        2500,
        "BitcoinStamps",
        Some("Classic"),
    )?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    let protocol = &report.protocol_value_breakdown[0];
    let total_percentage: f64 = protocol
        .variant_breakdown
        .iter()
        .map(|v| v.percentage)
        .sum();

    // Percentages should sum to 100% within floating-point tolerance
    assert!(
        (total_percentage - 100.0).abs() < 0.01,
        "Percentages sum to {:.4}%, expected ~100%",
        total_percentage
    );

    Ok(())
}

#[test]
fn test_variant_sum_equals_protocol_total() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Mix of variant and NULL variant outputs
    seed_classified_output(
        conn,
        "tx1",
        0,
        800000,
        10000,
        "BitcoinStamps",
        Some("Classic"),
    )?;
    seed_classified_output(
        conn,
        "tx2",
        0,
        800001,
        20000,
        "BitcoinStamps",
        Some("SRC-20"),
    )?;
    seed_classified_output(conn, "tx3", 0, 800002, 5000, "BitcoinStamps", None)?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    let protocol = &report.protocol_value_breakdown[0];

    // Invariant: sum(variant_breakdown.total_btc_value_sats) + null_variant_value_sats
    //            == protocol.total_btc_value_sats
    let variant_sum: u64 = protocol
        .variant_breakdown
        .iter()
        .map(|v| v.total_btc_value_sats)
        .sum();
    let expected_total = variant_sum + protocol.null_variant_value_sats;

    assert_eq!(
        expected_total, protocol.total_btc_value_sats,
        "Variant sum ({}) + null ({}) != protocol total ({})",
        variant_sum, protocol.null_variant_value_sats, protocol.total_btc_value_sats
    );

    Ok(())
}

#[test]
fn test_multiple_protocols_with_variants() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // BitcoinStamps
    seed_classified_output(
        conn,
        "stamps1",
        0,
        800000,
        10000,
        "BitcoinStamps",
        Some("Classic"),
    )?;
    seed_classified_output(
        conn,
        "stamps2",
        0,
        800001,
        20000,
        "BitcoinStamps",
        Some("SRC-20"),
    )?;

    // Counterparty
    seed_classified_output(
        conn,
        "cp1",
        0,
        800002,
        5000,
        "Counterparty",
        Some("Broadcast"),
    )?;
    seed_classified_output(conn, "cp2", 0, 800003, 8000, "Counterparty", Some("Send"))?;
    seed_classified_output(
        conn,
        "cp3",
        0,
        800004,
        3000,
        "Counterparty",
        Some("Broadcast"),
    )?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    assert_eq!(report.overall_statistics.total_outputs_analysed, 5);
    assert_eq!(report.overall_statistics.total_btc_locked_in_p2ms, 46000);
    assert_eq!(report.protocol_value_breakdown.len(), 2);

    // Find BitcoinStamps protocol
    let stamps = report
        .protocol_value_breakdown
        .iter()
        .find(|p| p.protocol.display_name() == "Bitcoin Stamps")
        .unwrap();
    assert_eq!(stamps.output_count, 2);
    assert_eq!(stamps.total_btc_value_sats, 30000);
    assert_eq!(stamps.variant_breakdown.len(), 2);

    // Find Counterparty protocol
    let cp = report
        .protocol_value_breakdown
        .iter()
        .find(|p| p.protocol.display_name() == "Counterparty")
        .unwrap();
    assert_eq!(cp.output_count, 3);
    assert_eq!(cp.total_btc_value_sats, 16000);
    assert_eq!(cp.variant_breakdown.len(), 2);

    Ok(())
}

#[test]
fn test_zero_value_protocol() -> AppResult<()> {
    // Edge case: protocol with zero total value should not panic
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Seed with zero value (edge case)
    seed_classified_output(conn, "tx1", 0, 800000, 0, "BitcoinStamps", Some("Classic"))?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    assert_eq!(report.protocol_value_breakdown.len(), 1);
    let protocol = &report.protocol_value_breakdown[0];
    assert_eq!(protocol.total_btc_value_sats, 0);

    // Variant percentages should be 0, not NaN or infinite
    for variant in &protocol.variant_breakdown {
        assert!(!variant.percentage.is_nan(), "Percentage should not be NaN");
        assert!(
            !variant.percentage.is_infinite(),
            "Percentage should not be infinite"
        );
        assert_eq!(variant.percentage, 0.0);
    }

    Ok(())
}

#[test]
fn test_variant_sorting_deterministic() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Create variants with same value - should be sorted by name
    seed_classified_output(conn, "tx1", 0, 800000, 1000, "BitcoinStamps", Some("Zebra"))?;
    seed_classified_output(conn, "tx2", 0, 800001, 1000, "BitcoinStamps", Some("Alpha"))?;
    seed_classified_output(
        conn,
        "tx3",
        0,
        800002,
        1000,
        "BitcoinStamps",
        Some("Middle"),
    )?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    let protocol = &report.protocol_value_breakdown[0];
    let variant_names: Vec<&str> = protocol
        .variant_breakdown
        .iter()
        .map(|v| v.variant.as_str())
        .collect();

    // Same value, so sorted alphabetically
    assert_eq!(variant_names, vec!["Alpha", "Middle", "Zebra"]);

    Ok(())
}

#[test]
fn test_spent_outputs_excluded() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Unspent output
    seed_classified_output(
        conn,
        "unspent",
        0,
        800000,
        10000,
        "BitcoinStamps",
        Some("Classic"),
    )?;

    // Manually create a spent output
    conn.execute(
        "INSERT OR IGNORE INTO blocks (height, timestamp) VALUES (800001, 800001 * 600)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('spent', 0, 800001, 20000, 'aabbcc', 'multisig', 0, 100, '{}', 1)",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('spent', 0, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('spent', 800001, 10000, 5000, 500, 1.0, 500, 2.0, 5000, 2.0, 1, 1, 1, 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('spent', 'BitcoinStamps', 'SRC-20', 1, 'SignatureBased', 'image/png')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('spent', 0, 'BitcoinStamps', 'SRC-20', 1, 'SignatureBased', 'image/png', 0, 'InvalidECPoints')",
        [],
    )?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    // Only unspent should be counted
    assert_eq!(report.overall_statistics.total_outputs_analysed, 1);
    assert_eq!(report.overall_statistics.total_btc_locked_in_p2ms, 10000);

    let protocol = &report.protocol_value_breakdown[0];
    assert_eq!(protocol.variant_breakdown.len(), 1);
    assert_eq!(protocol.variant_breakdown[0].variant, "Classic");

    Ok(())
}

#[test]
fn test_multi_output_transaction() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Same txid, different vouts (multi-output transaction)
    seed_classified_output(
        conn,
        "multi_tx",
        0,
        800000,
        5000,
        "BitcoinStamps",
        Some("Classic"),
    )?;

    // Manually add second output for same transaction
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('multi_tx', 1, 800000, 3000, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('multi_tx', 1, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('multi_tx', 1, 'BitcoinStamps', 'SRC-20', 1, 'SignatureBased', 'image/png', 0, 'InvalidECPoints')",
        [],
    )?;

    let fee_report = FeeAnalysisReport::default();
    let report = analyse_value_distribution(&db, fee_report)?;

    // Both outputs should be counted separately
    assert_eq!(report.overall_statistics.total_outputs_analysed, 2);
    assert_eq!(report.overall_statistics.total_btc_locked_in_p2ms, 8000);

    // But transaction count should be 1
    let protocol = &report.protocol_value_breakdown[0];
    assert_eq!(protocol.transaction_count, 1);
    assert_eq!(protocol.output_count, 2);

    Ok(())
}
