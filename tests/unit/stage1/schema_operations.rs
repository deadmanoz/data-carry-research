//! Schema Stage 1 Operations Tests
//!
//! Tests for the two-table atomic insert pattern:
//! 1. Stub blocks insertion
//! 2. transaction_outputs with is_spent = 0
//! 3. p2ms_outputs with extracted metadata
//!
//! These tests verify that the FK constraints, triggers, and data extraction
//! work correctly with the schema design.

use anyhow::Result;
use data_carry_research::database::traits::Stage1Operations;
use data_carry_research::types::script_metadata::MultisigInfo;
use data_carry_research::types::TransactionOutput;

// Import common test utilities
use crate::common::database::TestDatabase;

/// Helper function to create a P2MS TransactionOutput with metadata
fn create_p2ms_output(
    txid: &str,
    vout: u32,
    height: u32,
    pubkeys: Vec<String>,
    required_sigs: u32,
) -> TransactionOutput {
    let info = MultisigInfo {
        pubkeys: pubkeys.clone(),
        required_sigs,
        total_pubkeys: pubkeys.len() as u32,
    };

    TransactionOutput {
        txid: txid.to_string(),
        vout,
        height,
        amount: 546, // Dust limit
        script_hex: "test_script_hex".to_string(),
        script_type: "multisig".to_string(),
        is_coinbase: false,
        script_size: 100,
        metadata: serde_json::to_value(info).unwrap(),
        address: None, // Stage 1 doesn't populate addresses
    }
}

#[tokio::test]
async fn test_schema_initialisation() -> Result<()> {
    let test_db = TestDatabase::new("schema_init")?;

    // Verify schema was created by checking table exists via a simple query
    let count: i64 =
        test_db
            .database()
            .connection()
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))?;

    assert_eq!(count, 0, "blocks table should be empty initially");

    Ok(())
}

#[tokio::test]
async fn test_stub_blocks_creation() -> Result<()> {
    let mut test_db = TestDatabase::new("stub_blocks")?;

    // Create test outputs at different heights
    let outputs = vec![
        create_p2ms_output(
            "txid1",
            0,
            100_000,
            vec!["pubkey1".to_string(), "pubkey2".to_string()],
            2,
        ),
        create_p2ms_output(
            "txid2",
            0,
            100_001,
            vec!["pubkey3".to_string(), "pubkey4".to_string()],
            1,
        ),
        create_p2ms_output(
            "txid3",
            0,
            100_000, // Same height as txid1
            vec!["pubkey5".to_string()],
            1,
        ),
    ];

    // Insert the batch
    test_db
        .database_mut()
        .insert_transaction_output_batch(&outputs)?;

    // Verify stub blocks were created (2 unique heights: 100_000 and 100_001)
    let block_count: i64 =
        test_db
            .database()
            .connection()
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))?;

    assert_eq!(block_count, 2, "Should have 2 stub blocks");

    // Verify block 100_000 has NULL hash and timestamp
    let (hash, timestamp): (Option<String>, Option<i64>) =
        test_db.database().connection().query_row(
            "SELECT block_hash, timestamp FROM blocks WHERE height = 100000",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

    assert!(hash.is_none(), "Stub block should have NULL hash");
    assert!(timestamp.is_none(), "Stub block should have NULL timestamp");

    Ok(())
}

#[tokio::test]
async fn test_two_table_atomic_insert() -> Result<()> {
    let mut test_db = TestDatabase::new("two_table_insert")?;

    // Create test P2MS output
    let output = create_p2ms_output(
        "test_txid",
        0,
        100_000,
        vec![
            "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            "03cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe".to_string(),
        ],
        2,
    );

    // Insert the output
    test_db
        .database_mut()
        .insert_transaction_output_batch(&[output])?;

    // Verify transaction_outputs row exists
    let outputs_count: i64 = test_db.database().connection().query_row(
        "SELECT COUNT(*) FROM transaction_outputs WHERE txid = 'test_txid'",
        [],
        |row| row.get(0),
    )?;

    assert_eq!(outputs_count, 1, "Should have 1 row in transaction_outputs");

    // Verify p2ms_outputs row exists with extracted metadata
    let (required_sigs, total_pubkeys, pubkeys_json): (u32, u32, String) = test_db
        .database()
        .connection()
        .query_row(
            "SELECT required_sigs, total_pubkeys, pubkeys_json FROM p2ms_outputs WHERE txid = 'test_txid'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

    assert_eq!(required_sigs, 2, "Should have required_sigs = 2");
    assert_eq!(total_pubkeys, 2, "Should have total_pubkeys = 2");

    // Verify pubkeys_json can be deserialised
    let pubkeys: Vec<String> = serde_json::from_str(&pubkeys_json)?;
    assert_eq!(pubkeys.len(), 2, "Should have 2 pubkeys in JSON");
    assert_eq!(
        pubkeys[0],
        "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    );
    assert_eq!(
        pubkeys[1],
        "03cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
    );

    Ok(())
}

#[tokio::test]
async fn test_is_spent_defaults_to_zero() -> Result<()> {
    let mut test_db = TestDatabase::new("is_spent_default")?;

    // Create and insert test output
    let output = create_p2ms_output("test_txid", 0, 100_000, vec!["pubkey1".to_string()], 1);

    test_db
        .database_mut()
        .insert_transaction_output_batch(&[output])?;

    // Verify is_spent = 0 (unspent/UTXO)
    let is_spent: i64 = test_db.database().connection().query_row(
        "SELECT is_spent FROM transaction_outputs WHERE txid = 'test_txid'",
        [],
        |row| row.get(0),
    )?;

    assert_eq!(is_spent, 0, "is_spent should default to 0 (unspent)");

    Ok(())
}

#[tokio::test]
async fn test_fk_constraint_blocks() -> Result<()> {
    let test_db = TestDatabase::new("fk_blocks")?;

    // Try to insert transaction_outputs WITHOUT stub blocks first (should fail)
    let result = test_db.database().connection().execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, is_coinbase, is_spent)
         VALUES ('test_txid', 0, 999999, 546, 'hex', 'multisig', 100, 0, 0)",
        [],
    );

    assert!(
        result.is_err(),
        "Should fail due to FK constraint (blocks.height doesn't exist)"
    );

    Ok(())
}

#[tokio::test]
async fn test_trigger_enforces_p2ms_script_type() -> Result<()> {
    let test_db = TestDatabase::new("trigger_p2ms")?;

    // Insert stub block first
    test_db
        .database()
        .connection()
        .execute("INSERT INTO blocks (height) VALUES (100000)", [])?;

    // Insert transaction_outputs row with script_type = 'multisig'
    test_db.database().connection().execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, is_coinbase, is_spent)
         VALUES ('test_txid', 0, 100000, 546, 'hex', 'multisig', 100, 0, 0)",
        [],
    )?;

    // Now try to insert into p2ms_outputs (should succeed)
    let result = test_db.database().connection().execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('test_txid', 0, 1, 2, '[\"pubkey1\", \"pubkey2\"]')",
        [],
    );

    assert!(
        result.is_ok(),
        "Should succeed - transaction_outputs has script_type = multisig"
    );

    // Now create a non-P2MS output and try to insert into p2ms_outputs (should fail)
    test_db.database().connection().execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, is_coinbase, is_spent)
         VALUES ('test_txid2', 0, 100000, 546, 'hex', 'p2pkh', 100, 0, 0)",
        [],
    )?;

    let result = test_db.database().connection().execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('test_txid2', 0, 1, 2, '[\"pubkey1\", \"pubkey2\"]')",
        [],
    );

    assert!(
        result.is_err(),
        "Should fail - trigger enforces script_type = multisig"
    );

    Ok(())
}

#[tokio::test]
async fn test_batch_insert_multiple_outputs() -> Result<()> {
    let mut test_db = TestDatabase::new("batch_insert")?;

    // Create batch of 10 P2MS outputs across 3 heights
    let mut outputs = vec![];
    for i in 0..10 {
        let height = 100_000 + (i % 3); // Heights: 100000, 100001, 100002
        outputs.push(create_p2ms_output(
            &format!("txid_{}", i),
            0,
            height,
            vec![format!("pubkey_{}", i)],
            1,
        ));
    }

    // Insert batch
    test_db
        .database_mut()
        .insert_transaction_output_batch(&outputs)?;

    // Verify all outputs were inserted
    let outputs_count: i64 = test_db.database().connection().query_row(
        "SELECT COUNT(*) FROM transaction_outputs",
        [],
        |row| row.get(0),
    )?;

    assert_eq!(outputs_count, 10, "Should have 10 outputs");

    // Verify all P2MS metadata was inserted
    let p2ms_count: i64 = test_db.database().connection().query_row(
        "SELECT COUNT(*) FROM p2ms_outputs",
        [],
        |row| row.get(0),
    )?;

    assert_eq!(p2ms_count, 10, "Should have 10 P2MS metadata rows");

    // Verify 3 stub blocks were created
    let blocks_count: i64 =
        test_db
            .database()
            .connection()
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))?;

    assert_eq!(blocks_count, 3, "Should have 3 stub blocks");

    Ok(())
}

#[tokio::test]
async fn test_get_p2ms_outputs_for_transaction() -> Result<()> {
    let mut test_db = TestDatabase::new("get_p2ms_outputs")?;

    // Create and insert test outputs
    let outputs = vec![
        create_p2ms_output(
            "test_txid",
            0,
            100_000,
            vec!["pubkey1".to_string(), "pubkey2".to_string()],
            2,
        ),
        create_p2ms_output("test_txid", 1, 100_000, vec!["pubkey3".to_string()], 1),
    ];

    test_db
        .database_mut()
        .insert_transaction_output_batch(&outputs)?;

    // Retrieve outputs using the Stage1Operations trait method
    let retrieved = test_db
        .database()
        .get_p2ms_outputs_for_transaction("test_txid")?;

    assert_eq!(retrieved.len(), 2, "Should retrieve 2 outputs");

    // Verify metadata was correctly reconstructed
    let info1 = retrieved[0].multisig_info().expect("Should have metadata");
    assert_eq!(info1.required_sigs, 2);
    assert_eq!(info1.total_pubkeys, 2);
    assert_eq!(info1.pubkeys.len(), 2);

    let info2 = retrieved[1].multisig_info().expect("Should have metadata");
    assert_eq!(info2.required_sigs, 1);
    assert_eq!(info2.total_pubkeys, 1);
    assert_eq!(info2.pubkeys.len(), 1);

    Ok(())
}
