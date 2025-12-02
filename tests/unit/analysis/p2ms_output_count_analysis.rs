//! Unit tests for P2MS output count distribution analysis functionality
//!
//! Tests the P2msOutputCountAnalyser which reports distribution of P2MS output
//! counts per transaction, with global and per-protocol breakdowns plus percentiles.
//! Tracks total satoshi value per bucket (USER DIRECTIVE).

use crate::common::analysis_test_setup::create_analysis_test_db;
use data_carry_research::analysis::analyse_output_counts;
use data_carry_research::database::Database;
use data_carry_research::errors::AppResult;
use data_carry_research::types::ProtocolType;

/// Seed test data with transactions having various P2MS output counts
///
/// Creates transactions to test bucket assignment:
/// - tx_1_output: 1 P2MS output (bucket 0: [1, 2))
/// - tx_2_outputs: 2 P2MS outputs (bucket 1: [2, 3))
/// - tx_3_outputs: 3 P2MS outputs (bucket 2: [3, 4))
/// - tx_5_outputs: 5 P2MS outputs (bucket 3: [4, 6))
/// - tx_8_outputs: 8 P2MS outputs (bucket 4: [6, 11))
/// - tx_50_outputs: 50 P2MS outputs (bucket 6: [21, 51))
/// - tx_150_outputs: 150 P2MS outputs (bucket 8: [101, ∞))
fn seed_output_count_test_data(db: &Database) -> AppResult<()> {
    let conn = db.connection();

    // Insert stub blocks
    conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])?;
    conn.execute("INSERT INTO blocks (height) VALUES (100001)", [])?;

    // Helper to insert P2MS outputs for a transaction
    let insert_p2ms_outputs = |txid: &str, count: usize, amount_per_output: i64| -> AppResult<()> {
        for vout in 0..count {
            conn.execute(
                "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
                 is_coinbase, script_size, metadata_json, is_spent)
                 VALUES (?1, ?2, 100000, ?3, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
                rusqlite::params![txid, vout, amount_per_output],
            )?;
            conn.execute(
                "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
                 VALUES (?1, ?2, 1, 3, '[]')",
                rusqlite::params![txid, vout],
            )?;
        }
        Ok(())
    };

    // Transaction with 1 P2MS output (1000 sats)
    insert_p2ms_outputs("tx_1_output", 1, 1000)?;

    // Transaction with 2 P2MS outputs (500 sats each = 1000 total)
    insert_p2ms_outputs("tx_2_outputs", 2, 500)?;

    // Transaction with 3 P2MS outputs (333 sats each ≈ 999 total)
    insert_p2ms_outputs("tx_3_outputs", 3, 333)?;

    // Transaction with 5 P2MS outputs (200 sats each = 1000 total)
    insert_p2ms_outputs("tx_5_outputs", 5, 200)?;

    // Transaction with 8 P2MS outputs (125 sats each = 1000 total)
    insert_p2ms_outputs("tx_8_outputs", 8, 125)?;

    // Transaction with 50 P2MS outputs (20 sats each = 1000 total)
    insert_p2ms_outputs("tx_50_outputs", 50, 20)?;

    // Transaction with 150 P2MS outputs (10 sats each = 1500 total)
    insert_p2ms_outputs("tx_150_outputs", 150, 10)?;

    Ok(())
}

/// Seed test data with classifications for per-protocol testing
///
/// FK-safe seeding order: blocks → transaction_outputs → p2ms_outputs →
///                        transaction_classifications → p2ms_output_classifications
///
/// Test data:
/// - stamps_1: 1 output (1000 sats) - bucket [1,2)
/// - stamps_2: 2 outputs (500 sats each = 1000 total) - bucket [2,3)
/// - cp_3: 3 outputs (333 sats each = 999 total) - bucket [3,4)
fn seed_classified_test_data(db: &Database) -> AppResult<()> {
    let conn = db.connection();

    // Insert stub blocks
    conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])?;

    // ============ ALL transaction_outputs FIRST ============
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('stamps_1', 0, 100000, 1000, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('stamps_2', 0, 100000, 500, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('stamps_2', 1, 100000, 500, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('cp_3', 0, 100000, 333, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('cp_3', 1, 100000, 333, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('cp_3', 2, 100000, 333, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;

    // ============ ALL p2ms_outputs SECOND ============
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('stamps_1', 0, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('stamps_2', 0, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('stamps_2', 1, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('cp_3', 0, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('cp_3', 1, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('cp_3', 2, 1, 3, '[]')",
        [],
    )?;

    // ============ ALL enriched_transactions THIRD (FK parent for transaction_classifications) ============
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('stamps_1', 100000, 2000, 1000, 1000, 10.0, 100, 10000.0, 1000, 10.0, 1, 1, 1, 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('stamps_2', 100000, 2000, 1000, 1000, 10.0, 100, 10000.0, 1000, 10.0, 2, 1, 2, 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('cp_3', 100000, 2000, 999, 1001, 10.0, 100, 10000.0, 999, 10.0, 3, 1, 3, 0)",
        [],
    )?;

    // ============ ALL transaction_classifications FOURTH (parent for p2ms_output_classifications) ============
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant,
         protocol_signature_found, classification_method, content_type)
         VALUES ('stamps_1', 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'application/octet-stream')",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant,
         protocol_signature_found, classification_method, content_type)
         VALUES ('stamps_2', 'BitcoinStamps', 'StampsSRC20', 1, 'SignatureBased', 'application/octet-stream')",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant,
         protocol_signature_found, classification_method, content_type)
         VALUES ('cp_3', 'Counterparty', NULL, 1, 'SignatureBased', 'application/octet-stream')",
        [],
    )?;

    // ============ ALL p2ms_output_classifications FOURTH (child) ============
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant,
         protocol_signature_found, classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('stamps_1', 0, 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'application/octet-stream', 0, 'InvalidECPoints')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant,
         protocol_signature_found, classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('stamps_2', 0, 'BitcoinStamps', 'StampsSRC20', 1, 'SignatureBased', 'application/octet-stream', 0, 'InvalidECPoints')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant,
         protocol_signature_found, classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('stamps_2', 1, 'BitcoinStamps', 'StampsSRC20', 1, 'SignatureBased', 'application/octet-stream', 0, 'InvalidECPoints')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant,
         protocol_signature_found, classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('cp_3', 0, 'Counterparty', NULL, 1, 'SignatureBased', 'application/octet-stream', 0, 'InvalidECPoints')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant,
         protocol_signature_found, classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('cp_3', 1, 'Counterparty', NULL, 1, 'SignatureBased', 'application/octet-stream', 0, 'InvalidECPoints')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant,
         protocol_signature_found, classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('cp_3', 2, 'Counterparty', NULL, 1, 'SignatureBased', 'application/octet-stream', 0, 'InvalidECPoints')",
        [],
    )?;

    Ok(())
}

#[test]
fn test_global_distribution_bucket_assignment() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_output_count_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

    // Verify total transactions (7 transactions with outputs)
    assert_eq!(
        report.global_distribution.total_transactions, 7,
        "Should have 7 transactions"
    );

    // Total P2MS outputs: 1 + 2 + 3 + 5 + 8 + 50 + 150 = 219
    assert_eq!(
        report.global_distribution.total_p2ms_outputs, 219,
        "Should have 219 total P2MS outputs"
    );

    // Verify bucket assignments
    // Bucket 0: [1, 2) - tx_1_output (1 output)
    assert_eq!(
        report.global_distribution.buckets[0].count, 1,
        "Bucket [1, 2) should have 1 transaction"
    );

    // Bucket 1: [2, 3) - tx_2_outputs (2 outputs)
    assert_eq!(
        report.global_distribution.buckets[1].count, 1,
        "Bucket [2, 3) should have 1 transaction"
    );

    // Bucket 2: [3, 4) - tx_3_outputs (3 outputs)
    assert_eq!(
        report.global_distribution.buckets[2].count, 1,
        "Bucket [3, 4) should have 1 transaction"
    );

    // Bucket 3: [4, 6) - tx_5_outputs (5 outputs)
    assert_eq!(
        report.global_distribution.buckets[3].count, 1,
        "Bucket [4, 6) should have 1 transaction"
    );

    // Bucket 4: [6, 11) - tx_8_outputs (8 outputs)
    assert_eq!(
        report.global_distribution.buckets[4].count, 1,
        "Bucket [6, 11) should have 1 transaction"
    );

    // Bucket 6: [21, 51) - tx_50_outputs (50 outputs)
    assert_eq!(
        report.global_distribution.buckets[6].count, 1,
        "Bucket [21, 51) should have 1 transaction"
    );

    // Bucket 8: [101, ∞) - tx_150_outputs (150 outputs)
    assert_eq!(
        report.global_distribution.buckets[8].count, 1,
        "Bucket [101, ∞) should have 1 transaction"
    );

    Ok(())
}

#[test]
fn test_total_value_in_buckets() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_output_count_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

    // Total value: 1000 + 1000 + 999 + 1000 + 1000 + 1000 + 1500 = 7499 sats
    assert_eq!(
        report.global_distribution.total_value_sats, 7499,
        "Total value should be 7499 sats"
    );

    // Bucket 0: [1, 2) value = 1000 sats (tx_1_output)
    assert_eq!(
        report.global_distribution.buckets[0].value, 1000,
        "Bucket [1, 2) should have 1000 sats"
    );

    // Bucket 8: [101, ∞) value = 1500 sats (tx_150_outputs: 150 * 10)
    assert_eq!(
        report.global_distribution.buckets[8].value, 1500,
        "Bucket [101, ∞) should have 1500 sats"
    );

    Ok(())
}

#[test]
fn test_percentiles_calculation() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_output_count_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

    // With 7 transactions with output counts: 1, 2, 3, 5, 8, 50, 150 (sorted)
    // Percentile indices: (n-1) * p / 100 where n=7
    // p25: (6 * 25) / 100 = 1 → counts[1] = 2
    // p50: (6 * 50) / 100 = 3 → counts[3] = 5
    // p75: (6 * 75) / 100 = 4 → counts[4] = 8
    // p90: (6 * 90) / 100 = 5 → counts[5] = 50
    // p95: (6 * 95) / 100 = 5 → counts[5] = 50
    // p99: (6 * 99) / 100 = 5 → counts[5] = 50

    let percentiles = report
        .global_distribution
        .percentiles
        .expect("Should have percentiles");

    assert!(percentiles.p25 <= 2, "p25 should be ≤2 outputs");
    assert!(percentiles.p50 <= 5, "p50 should be ≤5 outputs");
    assert!(percentiles.p75 <= 8, "p75 should be ≤8 outputs");
    assert!(percentiles.p90 <= 50, "p90 should be ≤50 outputs");
    assert!(percentiles.p95 <= 50, "p95 should be ≤50 outputs");
    assert!(percentiles.p99 <= 150, "p99 should be ≤150 outputs");

    Ok(())
}

#[test]
fn test_per_protocol_distribution() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_classified_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

    // Should have 2 protocols: BitcoinStamps and Counterparty
    assert_eq!(
        report.protocol_distributions.len(),
        2,
        "Should have 2 protocols"
    );

    // Find BitcoinStamps (2 transactions: stamps_1 with 1 output, stamps_2 with 2 outputs)
    let stamps = report
        .protocol_distributions
        .iter()
        .find(|p| p.protocol == ProtocolType::BitcoinStamps)
        .expect("Should have BitcoinStamps");

    assert_eq!(
        stamps.total_transactions, 2,
        "BitcoinStamps has 2 transactions"
    );
    // Total outputs: 1 + 2 = 3
    assert_eq!(
        stamps.total_p2ms_outputs, 3,
        "BitcoinStamps has 3 P2MS outputs"
    );
    // Total value: 1000 + 1000 = 2000
    assert_eq!(
        stamps.total_value_sats, 2000,
        "BitcoinStamps total value: 2000 sats"
    );

    // Find Counterparty (1 transaction: cp_3 with 3 outputs)
    let cp = report
        .protocol_distributions
        .iter()
        .find(|p| p.protocol == ProtocolType::Counterparty)
        .expect("Should have Counterparty");

    assert_eq!(cp.total_transactions, 1, "Counterparty has 1 transaction");
    // Total outputs: 3
    assert_eq!(cp.total_p2ms_outputs, 3, "Counterparty has 3 P2MS outputs");
    // Total value: 999 (333 * 3)
    assert_eq!(
        cp.total_value_sats, 999,
        "Counterparty total value: 999 sats"
    );

    Ok(())
}

#[test]
fn test_protocol_ordering() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_classified_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

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

    let report = analyse_output_counts(&db)?;

    // All counts should be zero
    assert_eq!(report.global_distribution.total_transactions, 0);
    assert_eq!(report.global_distribution.total_p2ms_outputs, 0);
    assert_eq!(report.global_distribution.total_value_sats, 0);
    assert!(report.global_distribution.percentiles.is_none());

    // All buckets should be empty
    for bucket in &report.global_distribution.buckets {
        assert_eq!(bucket.count, 0);
        assert_eq!(bucket.value, 0);
    }

    // No protocol distributions
    assert!(report.protocol_distributions.is_empty());

    // No unclassified
    assert_eq!(report.unclassified_transaction_count, 0);

    Ok(())
}

#[test]
fn test_min_max_avg_output_counts() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_output_count_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

    // Min: 1, Max: 150
    assert_eq!(
        report.global_distribution.min_output_count,
        Some(1),
        "Min output count should be 1"
    );
    assert_eq!(
        report.global_distribution.max_output_count,
        Some(150),
        "Max output count should be 150"
    );

    // Average: 219 outputs / 7 transactions ≈ 31.29
    let expected_avg = 219.0 / 7.0;
    let actual_avg = report.global_distribution.avg_output_count;
    assert!(
        (actual_avg - expected_avg).abs() < 0.01,
        "Average output count should be {:.2}, got {:.2}",
        expected_avg,
        actual_avg
    );

    Ok(())
}

#[test]
fn test_unclassified_count() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_output_count_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

    // All 7 transactions are unclassified (no classifications inserted)
    assert_eq!(
        report.unclassified_transaction_count, 7,
        "Should have 7 unclassified transactions"
    );

    Ok(())
}

#[test]
fn test_bucket_ranges_consistency() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_output_count_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

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

    // Verify first bucket starts at 1 (not 0 - can't have 0 outputs)
    assert_eq!(
        report.global_distribution.buckets[0].range_min, 1,
        "First bucket should start at 1"
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
    seed_output_count_test_data(&db)?;

    let report = analyse_output_counts(&db)?;

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

    // Sum of all bucket values should equal total value
    let value_sum: u64 = report
        .global_distribution
        .buckets
        .iter()
        .map(|b| b.value)
        .sum();
    assert_eq!(
        value_sum, report.global_distribution.total_value_sats,
        "Bucket values should sum to total value"
    );

    Ok(())
}

#[test]
fn test_spent_outputs_excluded() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Insert stub block
    conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])?;

    // Insert unspent P2MS outputs (should be included)
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('unspent_tx', 0, 100000, 1000, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('unspent_tx', 0, 1, 3, '[]')",
        [],
    )?;

    // Insert spent P2MS outputs (should be excluded)
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('spent_tx', 0, 100000, 2000, 'aabbcc', 'multisig', 0, 100, '{}', 1)",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('spent_tx', 0, 1, 3, '[]')",
        [],
    )?;

    let report = analyse_output_counts(&db)?;

    // Should only have 1 transaction (spent excluded)
    assert_eq!(
        report.global_distribution.total_transactions, 1,
        "Should have 1 transaction (spent excluded)"
    );
    assert_eq!(
        report.global_distribution.total_value_sats, 1000,
        "Total value should be 1000 sats"
    );

    Ok(())
}

#[test]
fn test_non_multisig_excluded() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    let conn = db.connection();

    // Insert stub block
    conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])?;

    // Insert multisig output (should be included)
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('multisig_tx', 0, 100000, 1000, 'aabbcc', 'multisig', 0, 100, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('multisig_tx', 0, 1, 3, '[]')",
        [],
    )?;

    // Insert p2pkh output (should be excluded - not multisig)
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('p2pkh_tx', 0, 100000, 2000, 'aabbcc', 'p2pkh', 0, 100, '{}', 0)",
        [],
    )?;

    let report = analyse_output_counts(&db)?;

    // Should only have 1 transaction (p2pkh excluded)
    assert_eq!(
        report.global_distribution.total_transactions, 1,
        "Should have 1 transaction (p2pkh excluded)"
    );
    assert_eq!(
        report.global_distribution.total_value_sats, 1000,
        "Total value should be 1000 sats"
    );

    Ok(())
}
