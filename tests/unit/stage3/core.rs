//! Stage 3 Core Functionality Tests
//!
//! This test suite validates the core Stage 3 processor functionality including:
//! - Database schema operations
//! - Classification insertion and retrieval
//! - Batch processing operations  
//! - Processor initialisation and configuration
//! - Protocol height threshold enforcement
//! - Classification statistics calculations
//!
//! These tests focus on the underlying infrastructure and processing logic,
//! while protocol-specific tests are handled in separate files.

use data_carry_research::database::traits::{
    Stage2Operations, Stage3Operations, StatisticsOperations,
};
use data_carry_research::database::Database;
use data_carry_research::processor::stage3::Stage3Processor;
use data_carry_research::types::burn_patterns::{BurnPattern, BurnPatternType};
use data_carry_research::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, ProtocolType,
    ProtocolVariant, Stage3Config, TransactionInput,
};

// Import common test utilities
use crate::common::create_unique_test_db_path;

/// Create a test Stage 3 configuration
fn create_test_config(db_path: &str) -> Stage3Config {
    Stage3Config {
        database_path: db_path.into(),
        batch_size: 10,
        progress_interval: 1000,
    }
}

/// Create a test enriched transaction with burn patterns
fn create_test_enriched_transaction(
    txid: &str,

    burn_patterns: Vec<BurnPattern>,
) -> EnrichedTransaction {
    EnrichedTransaction {
        txid: txid.to_string(),
        height: 0,
        total_input_value: 10000,
        total_output_value: 9000,
        transaction_fee: 1000,
        fee_per_byte: 10.0,
        transaction_size_bytes: 100,
        fee_per_kb: 10000.0,
        total_p2ms_amount: 1000,
        data_storage_fee_rate: 10.0,
        p2ms_outputs_count: 1,
        input_count: 1,
        output_count: 2,
        is_coinbase: false,
        burn_patterns_detected: burn_patterns,
        outputs: Vec::new(),
    }
}

/// Create a test enriched transaction in the database
fn insert_test_enriched_transaction(
    db: &mut Database,
    txid: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let enriched_tx = create_test_enriched_transaction(txid, vec![]);
    // Create empty inputs vector since we're just testing Stage 3 functionality
    let inputs: Vec<TransactionInput> = vec![];
    db.insert_enriched_transactions_batch(&[(enriched_tx, inputs, Vec::new())])?;
    Ok(())
}
// ================================================================================================
// CORE FUNCTIONALITY TESTS
// ================================================================================================

#[tokio::test]
async fn test_stage3_database_schema_creation() {
    let db_path = create_unique_test_db_path("schema_creation");

    let db = Database::new_v2(&db_path).unwrap();

    // Verify database file was created
    assert!(std::path::Path::new(&db_path).exists());

    // Basic database operation should work
    let stats = db.get_classification_stats().unwrap();
    assert_eq!(stats.total_classified, 0);
}

#[tokio::test]
async fn test_stage3_classification_insertion_and_retrieval() {
    let db_path = create_unique_test_db_path("classification_insertion");
    let mut db = Database::new_v2(&db_path).unwrap();

    // Insert a test transaction
    insert_test_enriched_transaction(&mut db, "test_txid_1").unwrap();

    // Create a test classification result
    let classification_result = ClassificationResult {
        txid: "test_txid_1".to_string(),
        protocol: ProtocolType::Counterparty,
        variant: Some(ProtocolVariant::CounterpartyTransfer),
        classification_details: ClassificationDetails {
            burn_patterns_detected: vec![], // Counterparty uses protocol identifiers, not burn patterns
            height_check_passed: true,
            protocol_signature_found: true,
            classification_method: "CNTRPRTY identifier".to_string(),
            additional_metadata: Some("Test counterparty classification".to_string()),
            content_type: None,
        },
        classification_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Insert classification
    db.insert_classification_results_batch(&[classification_result])
        .unwrap();

    // Retrieve and verify via stats (individual classification retrieval not exposed in DB API)
    // This is appropriate since core tests should test the infrastructure, not the classification logic

    // Verify statistics
    let stats = db.get_classification_stats().unwrap();
    assert_eq!(stats.total_classified, 1);
    assert_eq!(stats.counterparty, 1);
    assert_eq!(stats.bitcoin_stamps, 0);
    assert_eq!(stats.omni_layer, 0);
    assert_eq!(stats.unknown, 0);
    assert_eq!(stats.definitive_signatures, 1);
}

#[tokio::test]
async fn test_stage3_batch_classification_insertion() {
    let db_path = create_unique_test_db_path("batch_insertion");
    let mut db = Database::new_v2(&db_path).unwrap();

    // Insert multiple test transactions
    let txids = vec!["batch_tx_1", "batch_tx_2", "batch_tx_3"];
    for txid in &txids {
        insert_test_enriched_transaction(&mut db, txid).unwrap();
    }

    // Create multiple classification results
    let mut results = Vec::new();
    for (i, txid) in txids.iter().enumerate() {
        let classification_result = ClassificationResult {
            txid: txid.to_string(),
            protocol: if i % 2 == 0 {
                ProtocolType::Counterparty
            } else {
                ProtocolType::BitcoinStamps
            },
            variant: if i % 2 == 0 {
                Some(ProtocolVariant::CounterpartyTransfer)
            } else {
                Some(ProtocolVariant::StampsClassic)
            },
            classification_details: ClassificationDetails {
                burn_patterns_detected: if i % 2 == 0 {
                    vec![] // Counterparty uses protocol identifiers, not burn patterns
                } else {
                    vec![BurnPatternType::Stamps22Pattern]
                },
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: if i % 2 == 0 {
                    "CNTRPRTY identifier".to_string()
                } else {
                    "Burn pattern match".to_string()
                },
                additional_metadata: Some(format!("Test batch classification {}", i)),
                content_type: None,
            },
            classification_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        results.push(classification_result);
    }

    // Batch insert classifications
    db.insert_classification_results_batch(&results).unwrap();

    // Verify all classifications were inserted
    let stats = db.get_classification_stats().unwrap();
    assert_eq!(stats.total_classified, 3);
    assert_eq!(stats.counterparty, 2); // txids 0, 2
    assert_eq!(stats.bitcoin_stamps, 1); // txid 1
    assert_eq!(stats.omni_layer, 0);
    assert_eq!(stats.unknown, 0);
    assert_eq!(stats.definitive_signatures, 3);
}

#[tokio::test]
async fn test_stage3_processor_creation() {
    let db_path = create_unique_test_db_path("processor_creation");

    let config = create_test_config(&db_path);
    let processor = Stage3Processor::new(&db_path, config);
    assert!(processor.is_ok());
}

#[tokio::test]
async fn test_stage3_classification_stats_calculations() {
    let db_path = create_unique_test_db_path("stats_calculations");
    let mut db = Database::new_v2(&db_path).unwrap();

    // Insert test transactions
    let test_data = vec![
        ("counterparty_1", ProtocolType::Counterparty, true),
        ("counterparty_2", ProtocolType::Counterparty, false),
        ("stamps_1", ProtocolType::BitcoinStamps, true),
        ("omni_1", ProtocolType::OmniLayer, true),
        ("unknown_1", ProtocolType::Unknown, false),
        ("protocol47930_1", ProtocolType::OpReturnSignalled, true),
    ];

    for (txid, protocol_type, definitive) in &test_data {
        insert_test_enriched_transaction(&mut db, txid).unwrap();

        let classification_result = ClassificationResult {
            txid: txid.to_string(),
            protocol: protocol_type.clone(),
            variant: match protocol_type {
                ProtocolType::Counterparty => Some(ProtocolVariant::CounterpartyTransfer),
                ProtocolType::AsciiIdentifierProtocols => {
                    Some(ProtocolVariant::AsciiIdentifierTB0001)
                }
                ProtocolType::BitcoinStamps => Some(ProtocolVariant::StampsClassic),
                ProtocolType::OmniLayer => Some(ProtocolVariant::OmniTransfer),
                ProtocolType::Chancecoin => Some(ProtocolVariant::ChancecoinUnknown),
                ProtocolType::PPk => Some(ProtocolVariant::PPkProfile),
                ProtocolType::OpReturnSignalled => Some(ProtocolVariant::OpReturnProtocol47930),
                ProtocolType::DataStorage => None,
                ProtocolType::LikelyDataStorage => Some(ProtocolVariant::InvalidECPoint),
                ProtocolType::LikelyLegitimateMultisig => Some(ProtocolVariant::LegitimateMultisig),
                ProtocolType::Unknown => None,
            },
            classification_details: ClassificationDetails {
                burn_patterns_detected: match protocol_type {
                    ProtocolType::Counterparty => vec![], // Counterparty uses protocol identifiers, not burn patterns
                    ProtocolType::AsciiIdentifierProtocols => vec![], // AsciiIdentifierProtocols uses protocol identifiers, not burn patterns
                    ProtocolType::BitcoinStamps => vec![BurnPatternType::Stamps22Pattern],
                    ProtocolType::OmniLayer => vec![], // OmniLayer uses protocol identifiers, not burn patterns
                    ProtocolType::Chancecoin => vec![], // Chancecoin uses signature, not burn patterns
                    ProtocolType::PPk => vec![],        // PPk uses marker pubkey, not burn patterns
                    ProtocolType::OpReturnSignalled => vec![],
                    ProtocolType::DataStorage => vec![],
                    ProtocolType::LikelyDataStorage => vec![], // LikelyDataStorage uses pattern detection, not burn patterns
                    ProtocolType::LikelyLegitimateMultisig => vec![],
                    ProtocolType::Unknown => vec![],
                },
                height_check_passed: true,
                protocol_signature_found: *definitive,
                classification_method: match protocol_type {
                    ProtocolType::Counterparty => "CNTRPRTY identifier".to_string(),
                    ProtocolType::AsciiIdentifierProtocols => {
                        "TB0001/METROXMN signature".to_string()
                    }
                    ProtocolType::BitcoinStamps => "Burn pattern match".to_string(),
                    ProtocolType::OmniLayer => "Omni Layer signature".to_string(),
                    ProtocolType::Chancecoin => "CHANCECO signature".to_string(),
                    ProtocolType::PPk => "PPk marker pubkey".to_string(),
                    ProtocolType::OpReturnSignalled => "OP_RETURN 0xbb3a signature".to_string(),
                    ProtocolType::DataStorage => "Data storage pattern".to_string(),
                    ProtocolType::LikelyDataStorage => {
                        "Invalid EC points/high output count/dust amounts".to_string()
                    }
                    ProtocolType::LikelyLegitimateMultisig => "EC point validation".to_string(),
                    ProtocolType::Unknown => "No definitive signature found".to_string(),
                },
                additional_metadata: Some(format!("Test {:?} classification", protocol_type)),
                content_type: None,
            },
            classification_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        db.insert_classification_results_batch(&[classification_result])
            .unwrap();
    }

    // Verify statistics calculations
    let stats = db.get_classification_stats().unwrap();
    assert_eq!(stats.total_classified, 6);
    assert_eq!(stats.counterparty, 2);
    assert_eq!(stats.bitcoin_stamps, 1);
    assert_eq!(stats.omni_layer, 1);
    assert_eq!(stats.opreturn_signalled, 1);
    assert_eq!(stats.unknown, 1);
    assert_eq!(stats.definitive_signatures, 4); // counterparty_1, stamps_1, omni_1, protocol47930_1

    println!("Classification stats test results:");
    println!("  Total: {}", stats.total_classified);
    println!("  Bitcoin Stamps: {}", stats.bitcoin_stamps);
    println!("  Counterparty: {}", stats.counterparty);
    println!("  Omni Layer: {}", stats.omni_layer);
    println!("  Chancecoin: {}", stats.chancecoin);
    println!("  OP_RETURN Signalled: {}", stats.opreturn_signalled);
    println!("  Data Storage: {}", stats.data_storage);
    println!("  Unknown: {}", stats.unknown);
    println!("  Definitive: {}", stats.definitive_signatures);
}

#[tokio::test]
async fn test_stage3_unclassified_transaction_counting() {
    let db_path = create_unique_test_db_path("unclassified_counting");
    let mut db = Database::new_v2(&db_path).unwrap();

    // Insert enriched transactions
    let txids = vec!["unclassified_1", "unclassified_2", "classified_1"];
    for txid in &txids {
        insert_test_enriched_transaction(&mut db, txid).unwrap();
    }

    // Only classify one transaction
    let classification_result = ClassificationResult {
        txid: "classified_1".to_string(),
        protocol: ProtocolType::Counterparty,
        variant: Some(ProtocolVariant::CounterpartyTransfer),
        classification_details: ClassificationDetails {
            burn_patterns_detected: vec![], // Counterparty uses protocol identifiers, not burn patterns
            height_check_passed: true,
            protocol_signature_found: true,
            classification_method: "CNTRPRTY identifier".to_string(),
            additional_metadata: Some("Test unclassified counting".to_string()),
            content_type: None,
        },
        classification_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    db.insert_classification_results_batch(&[classification_result])
        .unwrap();

    // Check unclassified count by calculating total enriched minus classified
    let enriched_stats = db.get_enriched_transaction_stats().unwrap();
    let classification_stats = db.get_classification_stats().unwrap();
    let unclassified_count =
        enriched_stats.total_enriched_transactions - classification_stats.total_classified;
    assert_eq!(unclassified_count, 2); // unclassified_1 and unclassified_2

    // Verify overall stats
    let stats = db.get_classification_stats().unwrap();
    assert_eq!(stats.total_classified, 1);
    assert_eq!(stats.counterparty, 1);

    println!("Unclassified transaction counting test results:");
    println!("  Total enriched transactions: {}", txids.len());
    println!("  Classified transactions: {}", stats.total_classified);
    println!("  Unclassified transactions: {}", unclassified_count);
}
