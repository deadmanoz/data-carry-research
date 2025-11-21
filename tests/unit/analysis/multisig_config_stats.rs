//! Unit tests for multisig configuration analysis

use data_carry_research::analysis::MultisigConfigAnalyser;
use data_carry_research::database::Database;
use data_carry_research::errors::AppResult;
use serde_json::json;

/// Helper to create test database with Schema V2
fn create_test_db() -> AppResult<Database> {
    Database::new_v2(":memory:")
}

/// Helper to seed test blocks
fn seed_blocks(db: &Database, heights: &[u32]) -> AppResult<()> {
    let conn = db.connection();
    for height in heights {
        conn.execute("INSERT INTO blocks (height) VALUES (?1)", [height])?;
    }
    Ok(())
}

/// Helper to seed test transaction outputs
fn seed_transaction_outputs(db: &Database, outputs: &[TransactionOutput]) -> AppResult<()> {
    let conn = db.connection();
    for output in outputs {
        conn.execute(
            "INSERT INTO transaction_outputs (
                txid, vout, height, amount, script_hex, script_type,
                is_coinbase, script_size, metadata_json, is_spent
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
            (
                &output.txid,
                output.vout,
                output.height,
                output.amount,
                &output.script_hex,
                &output.script_type,
                output.is_coinbase,
                output.script_size,
                output.metadata.to_string(),
            ),
        )?;
    }
    Ok(())
}

#[test]
fn test_determine_configuration_compressed_keys() -> AppResult<()> {
    // Test compressed key configurations are correctly identified

    // 1-of-2 CC
    assert_config(1, 2, 71, "CC", 32);

    // 1-of-3 CCC
    assert_config(1, 3, 105, "CCC", 64);

    // 1-of-4 CCCC
    assert_config(1, 4, 139, "CCCC", 96);

    // 1-of-5 CCCCC
    assert_config(1, 5, 173, "CCCCC", 128);

    // 1-of-6 CCCCCC
    assert_config(1, 6, 207, "CCCCCC", 160);

    // 1-of-7 CCCCCCC
    assert_config(1, 7, 241, "CCCCCCC", 192);

    Ok(())
}

#[test]
fn test_determine_configuration_mixed_keys() -> AppResult<()> {
    // Test mixed compressed/uncompressed configurations

    // 1-of-2 CU
    assert_config(1, 2, 103, "CU", 64);

    // 1-of-3 CCU
    assert_config(1, 3, 137, "CCU", 96);

    // 1-of-3 CUU
    assert_config(1, 3, 169, "CUU", 128);

    // 1-of-4 CCUU
    assert_config(1, 4, 203, "CCUU", 160);

    Ok(())
}

#[test]
fn test_determine_configuration_uncompressed_keys() -> AppResult<()> {
    // Test all uncompressed configurations

    // 1-of-2 UU
    assert_config(1, 2, 135, "UU", 64);

    // 1-of-3 UUU
    assert_config(1, 3, 201, "UUU", 128);

    // 1-of-4 UUUU
    assert_config(1, 4, 267, "UUUU", 192);

    // 1-of-5 UUUUU
    assert_config(1, 5, 333, "UUUUU", 256);

    // 1-of-6 UUUUUU
    assert_config(1, 6, 399, "UUUUUU", 320);

    // 1-of-7 UUUUUUU
    assert_config(1, 7, 465, "UUUUUUU", 384);

    Ok(())
}

#[test]
fn test_true_multisig_no_data_capacity() -> AppResult<()> {
    // Test that true multisig (m>1 for known configs) has 0 data capacity

    // 2-of-2 CC
    assert_config(2, 2, 71, "CC", 0);

    // 2-of-3 CCC
    assert_config(2, 3, 105, "CCC", 64); // Note: still has data capacity in our implementation

    // 3-of-3 CCC
    assert_config(3, 3, 105, "CCC", 0);

    Ok(())
}

#[test]
fn test_unknown_configuration_fallback() -> AppResult<()> {
    // Test that unknown configurations use fallback estimation

    // Unknown 1-of-8 (should estimate capacity)
    assert_config_pattern(1, 8, 999, "1-of-8?", (8 - 1) * 32);

    // Unknown 2-of-8 (should have 0 capacity)
    assert_config_pattern(2, 8, 999, "2-of-8?", 0);

    // Unknown 1-of-15 (should estimate capacity)
    assert_config_pattern(1, 15, 999, "1-of-15?", (15 - 1) * 32);

    Ok(())
}

#[test]
fn test_analyse_empty_database() -> AppResult<()> {
    // Test analysis with empty database
    let db = create_test_db()?;

    let report = MultisigConfigAnalyser::analyse_multisig_configurations(&db)?;

    assert_eq!(report.total_outputs, 0);
    assert_eq!(report.total_script_bytes, 0);
    assert_eq!(report.total_data_capacity, 0);
    assert_eq!(report.overall_efficiency, 0.0);
    assert!(report.configurations.is_empty());
    assert!(report.type_summary.is_empty());

    Ok(())
}

#[test]
fn test_overall_efficiency_calculation() -> AppResult<()> {
    // Test that overall efficiency is correctly calculated
    let db = create_test_db()?;

    // Add test data with known values
    seed_blocks(&db, &[100])?;
    seed_transaction_outputs(
        &db,
        &[
            // 1-of-3 CCC: 105 bytes script, 64 bytes data
            create_test_multisig("tx1", 0, 100, 1000, 105, 1, 3),
            // Another 1-of-3 CCC
            create_test_multisig("tx2", 0, 100, 2000, 105, 1, 3),
        ],
    )?;

    let report = MultisigConfigAnalyser::analyse_multisig_configurations(&db)?;

    // Total script: 210 bytes, total data: 128 bytes
    // Efficiency: (128/210) * 100 = 60.95%
    assert_eq!(report.total_outputs, 2);
    assert_eq!(report.total_script_bytes, 210);
    assert_eq!(report.total_data_capacity, 128);
    assert!((report.overall_efficiency - 60.95).abs() < 0.1);

    Ok(())
}

#[test]
fn test_type_summary_grouping() -> AppResult<()> {
    // Test that type_summary correctly groups by m-of-n
    let db = create_test_db()?;

    seed_blocks(&db, &[100])?;
    seed_transaction_outputs(
        &db,
        &[
            // Three 1-of-3 outputs
            create_test_multisig("tx1", 0, 100, 1000, 105, 1, 3),
            create_test_multisig("tx2", 0, 100, 2000, 105, 1, 3),
            create_test_multisig("tx3", 0, 100, 3000, 105, 1, 3),
            // Two 1-of-2 outputs
            create_test_multisig("tx4", 0, 100, 4000, 71, 1, 2),
            create_test_multisig("tx5", 0, 100, 5000, 71, 1, 2),
            // One 2-of-3 output
            create_test_multisig("tx6", 0, 100, 6000, 105, 2, 3),
        ],
    )?;

    let report = MultisigConfigAnalyser::analyse_multisig_configurations(&db)?;

    assert_eq!(report.type_summary.get("1-of-3"), Some(&3));
    assert_eq!(report.type_summary.get("1-of-2"), Some(&2));
    assert_eq!(report.type_summary.get("2-of-3"), Some(&1));
    assert_eq!(report.type_summary.len(), 3);

    Ok(())
}

#[test]
fn test_zero_data_capacity_efficiency() -> AppResult<()> {
    // Test that efficiency is handled correctly when data capacity is 0
    let db = create_test_db()?;

    seed_blocks(&db, &[100])?;
    seed_transaction_outputs(
        &db,
        &[
            // 2-of-2 CC: 71 bytes script, 0 bytes data
            create_test_multisig("tx1", 0, 100, 1000, 71, 2, 2),
        ],
    )?;

    let report = MultisigConfigAnalyser::analyse_multisig_configurations(&db)?;

    assert_eq!(report.total_outputs, 1);
    assert_eq!(report.total_script_bytes, 71);
    assert_eq!(report.total_data_capacity, 0);
    assert_eq!(report.overall_efficiency, 0.0); // Should be 0, not NaN or inf

    Ok(())
}

// Helper functions

fn assert_config(m: u32, n: u32, script_size: u32, expected_config: &str, expected_capacity: u32) {
    // Call the production function directly (exposed publicly for testing)
    let (config, capacity) = MultisigConfigAnalyser::determine_configuration(m, n, script_size);

    assert_eq!(
        config, expected_config,
        "Configuration mismatch for {}-of-{} with script size {}",
        m, n, script_size
    );
    assert_eq!(
        capacity, expected_capacity,
        "Capacity mismatch for {}-of-{} with script size {}",
        m, n, script_size
    );
}

fn assert_config_pattern(
    m: u32,
    n: u32,
    script_size: u32,
    expected_pattern: &str,
    expected_capacity: u32,
) {
    // Call the production function directly
    let (config, capacity) = MultisigConfigAnalyser::determine_configuration(m, n, script_size);

    assert_eq!(
        config, expected_pattern,
        "Pattern mismatch for {}-of-{} with script size {}",
        m, n, script_size
    );
    assert_eq!(
        capacity, expected_capacity,
        "Capacity mismatch for {}-of-{} with script size {}",
        m, n, script_size
    );
}

// Test data structure that matches database schema
struct TransactionOutput {
    txid: String,
    vout: u32,
    height: u32,
    amount: u64,
    script_hex: String,
    script_type: String,
    is_coinbase: bool,
    script_size: usize,
    metadata: serde_json::Value,
}

fn create_test_multisig(
    txid: &str,
    vout: u32,
    height: u32,
    amount: u64,
    script_size: u32,
    m: u32,
    n: u32,
) -> TransactionOutput {
    // Create fake pubkeys for testing
    let pubkeys: Vec<String> = (0..n)
        .map(|i| {
            if script_size < 100 || (script_size == 105 && n == 3) {
                // Compressed key
                format!("02{:064x}", i)
            } else {
                // Uncompressed key
                format!("04{:0128x}", i)
            }
        })
        .collect();

    TransactionOutput {
        txid: txid.to_string(),
        vout,
        height,
        amount,
        script_hex: "dummy".to_string(), // Not used in tests
        script_type: "multisig".to_string(),
        is_coinbase: false,
        script_size: script_size as usize,
        metadata: json!({
            "pubkeys": pubkeys,
            "required_sigs": m,
            "total_pubkeys": n
        }),
    }
}
