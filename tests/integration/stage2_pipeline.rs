use anyhow::Result;
use data_carry_research::analysis::{analyse_fees, detect_burn_patterns};
use data_carry_research::config::BitcoinRpcConfig;
use data_carry_research::database::traits::{
    Stage1Operations, Stage2Operations, StatisticsOperations,
};
use data_carry_research::database::Database;
use data_carry_research::types::burn_patterns::{BurnPattern, BurnPatternType};
use data_carry_research::types::statistics::StatisticsCollector;
use data_carry_research::types::*;
use std::collections::HashMap;

// Import common test utilities
use crate::common::create_unique_test_db_path;

/// Integration tests for Stage 2 components
///
/// These tests verify the complete Stage 2 pipeline functionality
/// without requiring a live Bitcoin node (uses mock data).

#[tokio::test]
async fn test_stage2_database_schema_creation() -> Result<()> {
    let db_path = create_unique_test_db_path("stage2");

    // Initialise database - this should create all Stage 2 tables
    let db = Database::new(&db_path)?;

    // Indirect verification: stats query should succeed on empty DB
    let stats = db.get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 0);

    Ok(())
}

// Helper function to create test TransactionOutput
fn create_test_p2ms(
    txid: &str,
    vout: u32,
    pubkeys: Vec<String>,
    required_sigs: u32,
    total_pubkeys: u32,
) -> TransactionOutput {
    create_test_p2ms_with_amount(txid, vout, pubkeys, required_sigs, total_pubkeys, 1000)
}

// Helper function to create test TransactionOutput with specified amount
fn create_test_p2ms_with_amount(
    txid: &str,
    vout: u32,
    pubkeys: Vec<String>,
    required_sigs: u32,
    total_pubkeys: u32,
    amount: u64,
) -> TransactionOutput {
    use data_carry_research::types::script_metadata::MultisigInfo;
    let info = MultisigInfo {
        pubkeys,
        required_sigs,
        total_pubkeys,
    };
    TransactionOutput {
        txid: txid.to_string(),
        vout,
        height: 100000,
        amount,
        script_hex: "test".to_string(),
        script_type: "multisig".to_string(),
        is_coinbase: false,
        script_size: 100,
        metadata: serde_json::to_value(info).unwrap(),
        address: None,
    }
}

#[test]
fn test_burn_pattern_detection_comprehensive() {
    // Test all Bitcoin Stamps burn patterns
    let test_cases = vec![
        // Bitcoin Stamps Type 22
        create_test_p2ms(
            "test_tx_22",
            0,
            vec![
                "022222222222222222222222222222222222222222222222222222222222222222".to_string(),
                "normal_key".to_string(),
            ],
            1,
            2,
        ),
        // Bitcoin Stamps Type 33
        create_test_p2ms(
            "test_tx_23",
            0,
            vec![
                "033333333333333333333333333333333333333333333333333333333333333333".to_string(),
                "normal_key".to_string(),
            ],
            1,
            2,
        ),
        // Bitcoin Stamps Type 0202
        create_test_p2ms(
            "test_tx_20",
            0,
            vec![
                "020202020202020202020202020202020202020202020202020202020202020202".to_string(),
                "normal_key".to_string(),
            ],
            1,
            2,
        ),
        // Bitcoin Stamps Type 0303
        create_test_p2ms(
            "test_tx_2f",
            0,
            vec![
                "030303030303030303030303030303030303030303030303030303030303030303".to_string(),
                "normal_key".to_string(),
            ],
            1,
            2,
        ),
        // No burn pattern
        create_test_p2ms(
            "test_tx_normal",
            0,
            vec![
                "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2".to_string(),
                "03c5946b3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db".to_string(),
            ],
            1,
            2,
        ),
    ];

    // Test burn pattern detection
    let patterns = detect_burn_patterns(&test_cases);

    // Should detect 4 burn patterns (one for each type)
    assert_eq!(patterns.len(), 4);

    // Verify specific patterns detected
    let pattern_types: HashMap<BurnPatternType, usize> =
        patterns.iter().fold(HashMap::new(), |mut acc, pattern| {
            *acc.entry(pattern.pattern_type.clone()).or_insert(0) += 1;
            acc
        });

    assert_eq!(
        pattern_types.get(&BurnPatternType::Stamps22Pattern),
        Some(&1)
    );
    assert_eq!(
        pattern_types.get(&BurnPatternType::Stamps33Pattern),
        Some(&1)
    );
    assert_eq!(
        pattern_types.get(&BurnPatternType::Stamps0202Pattern),
        Some(&1)
    );
    assert_eq!(
        pattern_types.get(&BurnPatternType::Stamps0303Pattern),
        Some(&1)
    );
}

#[test]
fn test_fee_analysis_comprehensive() {
    use corepc_client::bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
    use std::str::FromStr;

    // Create a mock transaction
    let outputs = vec![
        TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        },
        TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: ScriptBuf::new(),
        },
    ];

    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: corepc_client::bitcoin::Sequence::ZERO,
        witness: corepc_client::bitcoin::Witness::new(),
    }];

    let transaction = Transaction {
        version: corepc_client::bitcoin::transaction::Version(1),
        lock_time: corepc_client::bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // Create mock transaction inputs for fee calculation
    let tx_inputs = vec![TransactionInput {
        txid: "input_tx".to_string(),
        vout: 0,
        value: 5000, // 5000 in, 3000 out = 2000 fee
        script_sig: "script".to_string(),
        sequence: 0xffffffff,
        source_address: Some("1TestStage2Address123456789".to_string()),
    }];

    // Create mock P2MS outputs
    let p2ms_outputs = vec![create_test_p2ms(
        "test",
        0,
        vec!["key1".to_string(), "key2".to_string()],
        1,
        2,
    )];

    let analysis = analyse_fees(&transaction, &tx_inputs, &p2ms_outputs);

    // Verify fee calculations
    assert_eq!(analysis.total_input_value, 5000);
    assert_eq!(analysis.total_output_value, 3000);
    assert_eq!(analysis.transaction_fee, 2000);
    assert_eq!(analysis.total_p2ms_amount, 1000);
    assert_eq!(analysis.p2ms_outputs_count, 1);
    assert!(analysis.fee_per_byte > 0.0);
    assert!(analysis.data_storage_fee_rate > 0.0);
}

#[tokio::test]
async fn test_stage2_database_operations() -> Result<()> {
    let db_path = create_unique_test_db_path("stage2");
    let mut db = Database::new(&db_path)?;

    // Create test enriched transaction
    let enriched_tx = EnrichedTransaction {
        txid: "test_txid".to_string(),
        height: 100000,
        total_input_value: 5000,
        total_output_value: 3000,
        transaction_fee: 2000,
        fee_per_byte: 10.0,
        transaction_size_bytes: 200,
        fee_per_kb: 10000.0,
        total_p2ms_amount: 1000,
        data_storage_fee_rate: 20.0,
        p2ms_outputs_count: 2,
        burn_patterns_detected: vec![BurnPattern {
            pattern_type: BurnPatternType::Stamps22Pattern,
            vout: 0,
            pubkey_index: 0,
            pattern_data: "022222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
        }],
        input_count: 1,
        output_count: 2,
        is_coinbase: false,
        outputs: vec![create_test_p2ms(
            "test_txid",
            0,
            vec![
                "022222222222222222222222222222222222222222222222222222222222222222".to_string(),
                "normal_key".to_string(),
            ],
            1,
            2,
        )],
    };

    // Stage 1 seed: insert P2MS outputs before Stage 2 burn pattern processing
    let stage1_outputs = enriched_tx.outputs.clone();
    db.insert_p2ms_batch(&stage1_outputs)?;

    // Insert enriched transaction (Stage 2)
    db.insert_enriched_transactions_batch(&[(enriched_tx, Vec::new(), stage1_outputs)])?;

    // Verify insertion by getting stats
    let stats = db.get_enriched_transaction_stats()?;
    assert_eq!(stats.total_enriched_transactions, 1);
    assert_eq!(stats.transactions_with_burn_patterns, 1);
    assert_eq!(stats.total_burn_patterns_detected, 1);
    assert_eq!(stats.total_fees_analysed, 2000);

    Ok(())
}

#[test]
fn test_stage2_config_validation() {
    // Test default RPC config creation
    let default_config = BitcoinRpcConfig::default();
    assert_eq!(default_config.url, "http://localhost:8332");
    assert_eq!(default_config.username, "bitcoin");
    assert_eq!(default_config.password, "password");
    assert_eq!(default_config.timeout_seconds, 60);
    assert_eq!(default_config.max_retries, 10);

    // Test config validation
    assert!(default_config.max_retries > 0);
    assert!(default_config.timeout_seconds > 0);
    assert!(default_config.concurrent_requests > 0);
}

#[test]
fn test_stage2_stats_calculations() {
    let mut stats = Stage2Stats::new();

    // Simulate processing
    stats.transactions_processed = 100;
    stats.rpc_calls_made = 200;
    stats.rpc_errors_encountered = 5;
    stats.burn_patterns_found = 25;
    stats.total_fees_analysed = 50000;
    stats.total_p2ms_value = 25000;

    // Test calculations
    assert_eq!(stats.rpc_success_rate(), 97.5); // (200-5)/200 * 100
    assert_eq!(stats.average_fee_per_transaction(), 500.0); // 50000/100

    // Test with no data
    let empty_stats = Stage2Stats::new();
    assert_eq!(empty_stats.rpc_success_rate(), 0.0);
    assert_eq!(empty_stats.processing_rate(), 0.0);
}

#[test]
fn test_burn_pattern_edge_cases() {
    // Test empty P2MS outputs
    let empty_outputs: Vec<TransactionOutput> = vec![];
    let patterns = detect_burn_patterns(&empty_outputs);
    assert!(patterns.is_empty());

    // Test P2MS output with no pubkeys
    let no_pubkey_output = create_test_p2ms("test", 0, vec![], 1, 0);

    let patterns = detect_burn_patterns(&[no_pubkey_output]);
    assert!(patterns.is_empty());

    // Test P2MS output with invalid pubkey length
    let invalid_pubkey_output = create_test_p2ms("test", 0, vec!["short".to_string()], 1, 1);

    let patterns = detect_burn_patterns(&[invalid_pubkey_output]);
    assert!(patterns.is_empty());
}

#[test]
fn test_fee_analysis_edge_cases() {
    use corepc_client::bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

    // Test coinbase transaction (no inputs, no fee)
    let outputs = vec![TxOut {
        value: Amount::from_sat(5000000000),
        script_pubkey: ScriptBuf::new(),
    }];

    let coinbase_tx = Transaction {
        version: corepc_client::bitcoin::transaction::Version(1),
        lock_time: corepc_client::bitcoin::absolute::LockTime::ZERO,
        input: vec![], // Coinbase has no real inputs
        output: outputs,
    };

    let inputs: Vec<TransactionInput> = vec![];
    let p2ms_outputs = vec![create_test_p2ms_with_amount(
        "coinbase",
        0,
        vec!["key1".to_string()],
        1,
        1,
        5000000000,
    )];

    let analysis = analyse_fees(&coinbase_tx, &inputs, &p2ms_outputs);

    // Coinbase should have zero fee
    assert_eq!(analysis.transaction_fee, 0);
    assert_eq!(analysis.fee_per_byte, 0.0);
    assert_eq!(analysis.data_storage_fee_rate, 0.0);
    assert_eq!(analysis.total_p2ms_amount, 5000000000);
}

/// Performance test to ensure Stage 2 components can handle reasonable loads
#[test]
fn test_stage2_performance() {
    use std::time::Instant;

    // Create a large batch of P2MS outputs for burn pattern detection
    let mut outputs = Vec::new();
    for i in 0..1000 {
        use data_carry_research::types::script_metadata::MultisigInfo;
        let pubkeys = vec![
            if i % 4 == 0 {
                "022222222222222222222222222222222222222222222222222222222222222222".to_string()
            } else {
                format!("02{:062x}", i)
            },
            "normal_key".to_string(),
        ];
        let info = MultisigInfo {
            pubkeys: pubkeys.clone(),
            required_sigs: 1,
            total_pubkeys: 2,
        };
        outputs.push(TransactionOutput {
            txid: format!("test_tx_{}", i),
            vout: 0,
            height: 100000 + i as u32,
            amount: 1000,
            script_hex: "test".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(info).unwrap(),
            address: None,
        });
    }

    // Time burn pattern detection
    let start = Instant::now();
    let patterns = detect_burn_patterns(&outputs);
    let detection_time = start.elapsed();

    // Should complete in reasonable time (less than 1 second for 1000 outputs)
    assert!(detection_time.as_secs() < 1);

    // Should detect Stamps22 burn patterns (every 4th output has a Stamps22 key)
    let stamps22 = patterns
        .iter()
        .filter(|p| matches!(p.pattern_type, BurnPatternType::Stamps22Pattern))
        .count();
    assert_eq!(stamps22, 250); // 1000 / 4

    println!(
        "Burn pattern detection for 1000 outputs took: {:?}",
        detection_time
    );
    println!("Detected {} burn patterns", patterns.len());
}
