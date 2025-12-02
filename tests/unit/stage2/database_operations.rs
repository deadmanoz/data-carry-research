use anyhow::Result;
use data_carry_research::database::traits::{
    Stage1Operations, Stage2Operations, StatisticsOperations,
};
use data_carry_research::database::Database;
use data_carry_research::types::burn_patterns::{BurnPattern, BurnPatternType};
use data_carry_research::types::*;
use rusqlite::params;

// Import common test utilities
use crate::common::create_unique_test_db_path;
use crate::common::database::TestDatabase;
use crate::common::fixtures;

// Helper function to create test TransactionOutput
fn create_test_p2ms(txid: &str, vout: u32, amount: u64, pubkeys: Vec<String>) -> TransactionOutput {
    create_test_p2ms_with_height(txid, vout, amount, pubkeys, 0)
}

fn create_test_p2ms_with_height(
    txid: &str,
    vout: u32,
    amount: u64,
    pubkeys: Vec<String>,
    height: u32,
) -> TransactionOutput {
    use data_carry_research::types::script_metadata::MultisigInfo;
    let info = MultisigInfo {
        pubkeys: pubkeys.clone(),
        required_sigs: if pubkeys.is_empty() { 0 } else { 1 },
        total_pubkeys: pubkeys.len() as u32,
    };
    TransactionOutput {
        txid: txid.to_string(),
        vout,
        height,
        amount,
        script_hex: "script".to_string(),
        script_type: "multisig".to_string(),
        is_coinbase: false,
        script_size: 50,
        metadata: serde_json::to_value(info).unwrap(),
        address: None,
    }
}

fn seed_stage1_outputs_for_tx(
    db: &mut Database,
    txid: &str,
    height: u32,
    count: usize,
) -> Result<Vec<TransactionOutput>> {
    let mut outputs = Vec::new();
    for vout in 0..count {
        let pubkey = format!("02{:064x}", vout + 1);
        let output = create_test_p2ms_with_height(txid, vout as u32, 1000, vec![pubkey], height);
        outputs.push(output);
    }

    db.insert_p2ms_batch(&outputs)?;
    Ok(outputs)
}

/// Tests for Stage 2 database operations
///
/// These tests verify database schema creation, data insertion,
/// and query operations for Stage 2 enriched transaction data.

#[tokio::test]
async fn test_stage2_schema_initialisation() -> Result<()> {
    let test_db = TestDatabase::new("schema_init")?;

    // Indirectly validate schema by calling stats on empty DB (should not error)
    let stats = test_db.database().get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 0);

    Ok(())
    // Database is automatically cleaned up on drop
}

#[tokio::test]
async fn test_enriched_transaction_insertion() -> Result<()> {
    let mut test_db = TestDatabase::new("tx_insertion")?;

    // Create test enriched transaction with burn patterns
    let mut enriched_tx = fixtures::enriched_tx_with_burns("test_txid");
    // Add burn patterns to match test expectations
    enriched_tx.burn_patterns_detected = fixtures::stamps_burn_patterns();

    // Insert the transaction with empty inputs for this test
    let inputs: Vec<TransactionInput> = vec![];
    let outputs = seed_stage1_outputs_for_tx(
        test_db.database_mut(),
        &enriched_tx.txid,
        enriched_tx.height,
        1,
    )?;
    test_db
        .database_mut()
        .insert_enriched_transactions_batch(&[(enriched_tx, inputs, outputs)])?;

    // Verify insertion by checking stats
    let stats = test_db.database().get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 1);
    assert_eq!(stats.transactions_with_burn_patterns, 1);
    assert_eq!(stats.total_burn_patterns_detected, 2); // Test transaction has 2 patterns
    assert_eq!(stats.coinbase_transactions, 0);
    assert_eq!(stats.regular_transactions, 1);

    Ok(())
    // Database is automatically cleaned up on drop
}

#[tokio::test]
async fn test_rpc_only_multisig_outputs_marked_spent() -> Result<()> {
    let mut test_db = TestDatabase::new("stage2_rpc_spent_flags")?;

    // Create a baseline enriched transaction
    let mut enriched_tx = fixtures::create_test_enriched_transaction("rpc_spent_tx");
    enriched_tx.height = 123_456;

    // Stage 1 seeds only vout 0 as part of the UTXO set
    let stage1_outputs = seed_stage1_outputs_for_tx(
        test_db.database_mut(),
        &enriched_tx.txid,
        enriched_tx.height,
        1,
    )?;

    // Simulate RPC revealing an additional multisig output (vout 1) that is already spent
    let mut all_outputs = stage1_outputs.clone();
    all_outputs.push(create_test_p2ms_with_height(
        &enriched_tx.txid,
        1,
        2_000,
        vec!["03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()],
        enriched_tx.height,
    ));

    test_db
        .database_mut()
        .insert_enriched_transactions_batch(&[(enriched_tx, Vec::new(), all_outputs)])?;

    // vout 0 originated from Stage 1 (UTXO), so it must remain unspent
    let vout0_is_spent: i64 = test_db.database().connection().query_row(
        "SELECT is_spent FROM transaction_outputs WHERE txid = ?1 AND vout = 0",
        params!["rpc_spent_tx"],
        |row| row.get(0),
    )?;
    assert_eq!(vout0_is_spent, 0);

    // vout 1 was only discovered via RPC, so it must be marked spent
    let vout1_is_spent: i64 = test_db.database().connection().query_row(
        "SELECT is_spent FROM transaction_outputs WHERE txid = ?1 AND vout = 1",
        params!["rpc_spent_tx"],
        |row| row.get(0),
    )?;
    assert_eq!(vout1_is_spent, 1);

    Ok(())
}

#[tokio::test]
async fn test_enriched_transaction_batch_insertion() -> Result<()> {
    let mut test_db = TestDatabase::new("batch_insertion")?;

    // Create multiple test transactions
    let mut transactions = vec![];
    for i in 0..10 {
        let mut tx = fixtures::create_test_enriched_transaction(&format!("test_txid_{}", i));
        tx.transaction_fee = 1000 + (i as u64 * 100); // Different fees

        if i % 2 == 0 {
            // Add burn patterns for even-numbered transactions
            tx.burn_patterns_detected = vec![BurnPattern {
                pattern_type: BurnPatternType::Stamps22Pattern,
                vout: 0,
                pubkey_index: 0,
                pattern_data: "022222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            }];
        } else {
            tx.burn_patterns_detected = vec![];
        }

        transactions.push(tx);
    }

    // Insert all transactions with empty inputs for this test
    for tx in &transactions {
        let inputs: Vec<TransactionInput> = vec![];
        let outputs = seed_stage1_outputs_for_tx(
            test_db.database_mut(),
            &tx.txid,
            tx.height,
            tx.p2ms_outputs_count.max(1),
        )?;
        test_db
            .database_mut()
            .insert_enriched_transactions_batch(&[(tx.clone(), inputs.clone(), outputs)])?;
    }

    // Verify batch insertion
    let stats = test_db.database().get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 10);
    assert_eq!(stats.transactions_with_burn_patterns, 5); // Half have patterns
    assert_eq!(stats.coinbase_transactions, 0);
    assert_eq!(stats.regular_transactions, 10);

    // Check fee calculations
    let expected_total_fees: u64 = (0..10).map(|i| 1000 + (i * 100)).sum();
    assert_eq!(stats.total_fees_analysed, expected_total_fees);

    Ok(())
}

#[tokio::test]
async fn test_unprocessed_transaction_queries() -> Result<()> {
    let db_path = create_unique_test_db_path("unprocessed_queries");
    let mut db = Database::new(&db_path)?;

    // First, add some P2MS outputs (Stage 1 data)
    for txid in ["tx1", "tx2", "tx3"] {
        seed_stage1_outputs_for_tx(&mut db, txid, 0, 2)?;
    }

    // Get unprocessed transactions (all should be unprocessed initially)
    let unprocessed = db.get_unprocessed_transactions(10)?;
    assert_eq!(unprocessed.len(), 3);
    assert!(unprocessed.contains(&"tx1".to_string()));
    assert!(unprocessed.contains(&"tx2".to_string()));
    assert!(unprocessed.contains(&"tx3".to_string()));

    // Process one transaction
    let mut enriched_tx = create_test_enriched_transaction();
    enriched_tx.txid = "tx1".to_string();
    let inputs: Vec<TransactionInput> = vec![];
    let outputs = seed_stage1_outputs_for_tx(
        &mut db,
        &enriched_tx.txid,
        enriched_tx.height,
        enriched_tx
            .burn_patterns_detected
            .len()
            .max(enriched_tx.p2ms_outputs_count),
    )?;
    db.insert_enriched_transactions_batch(&[(enriched_tx, inputs, outputs)])?;

    // Check unprocessed again - should be 2 remaining
    let unprocessed = db.get_unprocessed_transactions(10)?;
    assert_eq!(unprocessed.len(), 2);
    assert!(!unprocessed.contains(&"tx1".to_string())); // This one is processed
    assert!(unprocessed.contains(&"tx2".to_string()));
    assert!(unprocessed.contains(&"tx3".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_p2ms_outputs_for_transaction() -> Result<()> {
    let db_path = create_unique_test_db_path("p2ms_outputs");
    let mut db = Database::new(&db_path)?;

    // Add multiple P2MS outputs for the same transaction
    let txid = "test_transaction";
    let outputs = vec![
        {
            use data_carry_research::types::script_metadata::MultisigInfo;
            let info = MultisigInfo {
                pubkeys: vec!["key1".to_string(), "key2".to_string()],
                required_sigs: 1,
                total_pubkeys: 2,
            };
            TransactionOutput {
                txid: txid.to_string(),
                vout: 0,
                height: 0,
                amount: 1000,
                script_hex: "script1".to_string(),
                script_type: "multisig".to_string(),
                is_coinbase: false,
                script_size: 100,
                metadata: serde_json::to_value(info).unwrap(),
                address: None,
            }
        },
        {
            use data_carry_research::types::script_metadata::MultisigInfo;
            let info = MultisigInfo {
                pubkeys: vec!["key3".to_string(), "key4".to_string()],
                required_sigs: 1,
                total_pubkeys: 2,
            };
            TransactionOutput {
                txid: txid.to_string(),
                vout: 1,
                height: 0,
                amount: 2000,
                script_hex: "script2".to_string(),
                script_type: "multisig".to_string(),
                is_coinbase: false,
                script_size: 100,
                metadata: serde_json::to_value(info).unwrap(),
                address: None,
            }
        },
    ];

    for output in &outputs {
        let batch = vec![output.clone()];
        db.insert_p2ms_batch(&batch)?;
    }

    // Retrieve P2MS outputs for the transaction
    let retrieved = db.get_p2ms_outputs_for_transaction(txid)?;
    assert_eq!(retrieved.len(), 2);

    // Verify data integrity
    assert_eq!(retrieved[0].txid, txid);
    assert_eq!(retrieved[1].txid, txid);
    assert_eq!(retrieved[0].vout, 0);
    assert_eq!(retrieved[1].vout, 1);
    assert_eq!(retrieved[0].amount + retrieved[1].amount, 3000);

    Ok(())
}

#[tokio::test]
async fn test_coinbase_transaction_handling() -> Result<()> {
    let db_path = create_unique_test_db_path("coinbase_handling");
    let mut db = Database::new(&db_path)?;

    // Create coinbase enriched transaction
    let mut coinbase_tx = create_test_enriched_transaction();
    coinbase_tx.txid = "coinbase_tx".to_string();
    coinbase_tx.is_coinbase = true;
    coinbase_tx.transaction_fee = 0; // Coinbase has no fee
    coinbase_tx.fee_per_byte = 0.0;
    coinbase_tx.data_storage_fee_rate = 0.0;
    coinbase_tx.total_input_value = 0; // Coinbase has no inputs
    coinbase_tx.input_count = 0;
    coinbase_tx.burn_patterns_detected = vec![];

    // Insert coinbase transaction with empty inputs (coinbase has no real inputs)
    let inputs: Vec<TransactionInput> = vec![];
    db.insert_enriched_transactions_batch(&[(coinbase_tx, inputs, Vec::new())])?;

    // Verify coinbase statistics
    let stats = db.get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 1);
    assert_eq!(stats.coinbase_transactions, 1);
    assert_eq!(stats.regular_transactions, 0);
    assert_eq!(stats.total_fees_analysed, 0); // No fees for coinbase

    Ok(())
}

#[tokio::test]
async fn test_burn_pattern_statistics() -> Result<()> {
    let db_path = create_unique_test_db_path("burn_pattern_stats");
    let mut db = Database::new(&db_path)?;

    // Create transactions with different burn pattern counts
    let transactions = [
        (1, vec!["STAMPS_22"]),              // 1 pattern
        (2, vec!["STAMPS_22", "STAMPS_23"]), // 2 patterns
        (0, vec![]),                         // no patterns
        (1, vec!["STAMPS_20"]),              // 1 pattern
    ];

    for (i, (_pattern_count, pattern_types)) in transactions.iter().enumerate() {
        let mut tx = create_test_enriched_transaction();
        tx.txid = format!("tx_{}", i);

        tx.burn_patterns_detected = pattern_types
            .iter()
            .enumerate()
            .map(|(i, pattern_type)| BurnPattern {
                pattern_type: match *pattern_type {
                    "STAMPS_22" => BurnPatternType::Stamps22Pattern,
                    "STAMPS_23" => BurnPatternType::Stamps33Pattern,
                    "STAMPS_20" => BurnPatternType::Stamps0202Pattern,
                    _ => BurnPatternType::Stamps22Pattern,
                },
                vout: 0,
                pubkey_index: i as u8,
                pattern_data: format!("pubkey_for_{}", pattern_type),
            })
            .collect();

        let inputs: Vec<TransactionInput> = vec![];
        let outputs =
            seed_stage1_outputs_for_tx(&mut db, &tx.txid, tx.height, tx.p2ms_outputs_count)?;
        db.insert_enriched_transactions_batch(&[(tx.clone(), inputs.clone(), outputs)])?;
    }

    // Check statistics
    let stats = db.get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 4);
    assert_eq!(stats.transactions_with_burn_patterns, 3); // 3 have patterns
    assert_eq!(stats.total_burn_patterns_detected, 4); // Total of 1+2+0+1

    // Test percentage calculations
    assert_eq!(stats.burn_pattern_percentage(), 75.0); // 3/4 * 100
    assert!((stats.average_patterns_per_transaction() - 1.33).abs() < 0.01); // 4/3 ≈ 1.33

    Ok(())
}

#[tokio::test]
async fn test_fee_analysis_statistics() -> Result<()> {
    let db_path = create_unique_test_db_path("fee_analysis_stats");
    let mut db = Database::new(&db_path)?;

    let test_fees = [1000u64, 2000, 3000, 4000, 5000];

    // Insert transactions with different fees
    for (i, fee) in test_fees.iter().enumerate() {
        let mut tx = create_test_enriched_transaction();
        tx.txid = format!("fee_tx_{}", i);
        tx.transaction_fee = *fee;
        tx.fee_per_byte = *fee as f64 / tx.transaction_size_bytes as f64;

        let inputs: Vec<TransactionInput> = vec![];
        let outputs =
            seed_stage1_outputs_for_tx(&mut db, &tx.txid, tx.height, tx.p2ms_outputs_count)?;
        db.insert_enriched_transactions_batch(&[(tx.clone(), inputs.clone(), outputs)])?;
    }

    // Check fee statistics
    let stats = db.get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 5);
    assert_eq!(stats.total_fees_analysed, 15000); // Sum of all fees
    assert_eq!(stats.average_fee_per_transaction(), 3000.0); // 15000/5

    Ok(())
}

#[tokio::test]
async fn test_database_performance_batch_operations() -> Result<()> {
    let db_path = create_unique_test_db_path("batch_performance");
    let mut db = Database::new(&db_path)?;

    use std::time::Instant;

    // Insert a large number of enriched transactions
    let start = Instant::now();

    for i in 0..1000 {
        let mut tx = create_test_enriched_transaction();
        tx.txid = format!("perf_tx_{}", i);
        tx.transaction_fee = 1000 + (i as u64);

        if i % 10 == 0 {
            // Every 10th has burn patterns
            tx.burn_patterns_detected = vec![BurnPattern {
                pattern_type: BurnPatternType::Stamps22Pattern,
                vout: 0,
                pubkey_index: 0,
                pattern_data: "burn_key".to_string(),
            }];
        } else {
            tx.burn_patterns_detected = vec![];
        }

        let inputs: Vec<TransactionInput> = vec![];
        let outputs =
            seed_stage1_outputs_for_tx(&mut db, &tx.txid, tx.height, tx.p2ms_outputs_count)?;
        db.insert_enriched_transactions_batch(&[(tx.clone(), inputs.clone(), outputs)])?;
    }

    let insertion_time = start.elapsed();
    println!("Inserted 1000 transactions in {:?}", insertion_time);

    // Verify all data was inserted correctly
    let stats = db.get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 1000);
    assert_eq!(stats.transactions_with_burn_patterns, 100); // Every 10th

    // Performance check - should complete in reasonable time
    assert!(insertion_time.as_secs() < 20); // Less than 20 seconds (increased for slower systems)

    Ok(())
}

#[tokio::test]
async fn test_transaction_input_storage() -> Result<()> {
    let db_path = create_unique_test_db_path("input_storage");
    let mut db = Database::new(&db_path)?;

    // Create enriched transaction with transaction inputs
    let mut tx = create_test_enriched_transaction();
    tx.txid = "tx_with_inputs".to_string();

    // The transaction inputs are stored as part of the enriched transaction insertion
    let inputs: Vec<TransactionInput> = vec![];
    let outputs = seed_stage1_outputs_for_tx(&mut db, &tx.txid, tx.height, tx.p2ms_outputs_count)?;
    db.insert_enriched_transactions_batch(&[(tx.clone(), inputs.clone(), outputs)])?;

    // Verify transaction was inserted
    let stats = db.get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 1);

    // Indirect check: stats call should still succeed
    let _ = db.get_enriched_transaction_stats()?;

    Ok(())
}

#[tokio::test]
async fn test_database_error_handling() -> Result<()> {
    let db_path = create_unique_test_db_path("error_handling");
    let mut db = Database::new(&db_path)?;

    // Test duplicate transaction insertion (should handle gracefully)
    let tx = create_test_enriched_transaction();

    // First insertion should succeed
    let inputs: Vec<TransactionInput> = vec![];
    let outputs = seed_stage1_outputs_for_tx(&mut db, &tx.txid, tx.height, tx.p2ms_outputs_count)?;
    db.insert_enriched_transactions_batch(&[(tx.clone(), inputs.clone(), outputs.clone())])?;

    // Second insertion of same txid should either succeed (update) or be handled gracefully
    let _result = db.insert_enriched_transactions_batch(&[(tx.clone(), inputs.clone(), outputs)]);
    // We expect this to either succeed or fail gracefully
    // The exact behaviour depends on the database constraints

    let stats = db.get_enriched_transaction_stats()?;
    // Should still have at least 1 transaction
    assert!(stats.total_enriched_transactions >= 1);

    Ok(())
}

/// Helper function to create a test enriched transaction
fn create_test_enriched_transaction() -> EnrichedTransaction {
    EnrichedTransaction {
        txid: "test_txid".to_string(),
        height: 0,
        total_input_value: 5000,
        total_output_value: 3000,
        transaction_fee: 2000,
        fee_per_byte: 10.0,
        transaction_size_bytes: 200,
        fee_per_kb: 10000.0,
        total_p2ms_amount: 1000,
        data_storage_fee_rate: 20.0,
        p2ms_outputs_count: 2,
        burn_patterns_detected: vec![
            BurnPattern {
                pattern_type: BurnPatternType::Stamps22Pattern,
                vout: 0,
                pubkey_index: 0,
                pattern_data: "022222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            BurnPattern {
                pattern_type: BurnPatternType::Stamps33Pattern,
                vout: 1,
                pubkey_index: 0,
                pattern_data: "023333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        ],
        input_count: 1,
        output_count: 2,
        is_coinbase: false,
        outputs: vec![create_test_p2ms(
            "test_txid",
            0,
            1000,
            vec![
                "022222222222222222222222222222222222222222222222222222222222222222".to_string(),
                "normal_key".to_string(),
            ],
        )],
    }
}
