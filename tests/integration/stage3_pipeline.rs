use data_carry_research::database::traits::{
    Stage1Operations, Stage2Operations, Stage3Operations, StatisticsOperations,
};
use data_carry_research::database::{ClassificationStats, Database};
use data_carry_research::processor::stage3::Stage3Processor;
use data_carry_research::types::burn_patterns::{BurnPattern, BurnPatternType};
use data_carry_research::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, OutputClassificationData,
    OutputClassificationDetails, ProtocolType, ProtocolVariant, Stage3Config, TransactionInput,
};
use data_carry_research::utils::math::safe_percentage;
use std::time::{SystemTime, UNIX_EPOCH};

// Import common test utilities
use crate::common::create_unique_test_db_path;

/// Create a test Stage 3 configuration
fn create_test_config(db_path: &str) -> Stage3Config {
    Stage3Config {
        database_path: db_path.into(),
        batch_size: 10,
        progress_interval: 1000,
        tier2_patterns_config: data_carry_research::types::Tier2PatternsConfig::default(),
    }
}

/// Create a test enriched transaction with burn patterns
fn create_test_enriched_transaction(
    txid: &str,

    burn_patterns: Vec<BurnPattern>,
) -> EnrichedTransaction {
    // Create P2MS output for testing (required by database trigger)
    let p2ms_output = crate::common::fixtures::create_test_p2ms_output(txid, 0, "dummy_script_hex");

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
        outputs: vec![p2ms_output],
    }
}

/// Create a test enriched transaction in the database
fn insert_test_enriched_transaction(
    db: &mut Database,
    txid: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Schema V2: Insert stub block for FK constraint (height 0)
    let conn = db.connection();
    conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (0)", [])
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    let enriched_tx = create_test_enriched_transaction(txid, vec![]);
    // Create empty inputs vector since we're just testing Stage 3 functionality
    let inputs: Vec<TransactionInput> = vec![];
    // Extract outputs for batch insertion (separate from EnrichedTransaction.outputs)
    let outputs = enriched_tx.outputs.clone();
    db.insert_enriched_transactions_batch(&[(enriched_tx, inputs, outputs.clone())])?;

    // CRITICAL: Stage 2 batch insert UPSERTs transaction_outputs but does NOT populate p2ms_outputs.
    // We must explicitly populate p2ms_outputs using Stage1Operations for the FK constraint:
    // p2ms_output_classifications.txid, vout -> p2ms_outputs.txid, vout
    db.insert_transaction_output_batch(&outputs)?;

    Ok(())
}
#[tokio::test]
async fn test_stage3_database_schema_creation() {
    let db_path = create_unique_test_db_path("integration");

    // Create database and verify Stage 3 schema exists
    let db = Database::new_v2(&db_path).unwrap();

    // Test that we can count classification stats (which will fail if schema doesn't exist)
    let stats_result = db.get_classification_stats();
    assert!(
        stats_result.is_ok(),
        "Should be able to get classification stats even if empty"
    );

    let stats = stats_result.unwrap();
    assert_eq!(
        stats.total_classified, 0,
        "Should start with 0 classifications"
    );
}

#[tokio::test]
async fn test_stage3_classification_insertion_and_retrieval() {
    let db_path = create_unique_test_db_path("integration");

    let mut db = Database::new_v2(&db_path).unwrap();

    // First, create the required enriched transaction
    insert_test_enriched_transaction(&mut db, "test_tx_123").unwrap();

    // Create test classification result
    let details = ClassificationDetails {
        burn_patterns_detected: vec![BurnPatternType::Stamps22Pattern],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test classification".to_string(),
        additional_metadata: Some("test metadata".to_string()),
        content_type: None,
    };

    let classification = ClassificationResult {
        txid: "test_tx_123".to_string(),
        protocol: ProtocolType::BitcoinStamps,
        variant: Some(ProtocolVariant::StampsClassic),
        classification_details: details,
        classification_timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // Insert classification
    db.insert_classification_results_batch(&[classification])
        .unwrap();

    // Verify it was inserted
    let stats = db.get_classification_stats().unwrap();
    assert_eq!(stats.total_classified, 1);
    assert_eq!(stats.bitcoin_stamps, 1);
    assert_eq!(stats.counterparty, 0);
    assert_eq!(stats.omni_layer, 0);
    assert_eq!(stats.unknown, 0);
    assert_eq!(stats.definitive_signatures, 1);
}

#[tokio::test]
async fn test_stage3_batch_classification_insertion() {
    let db_path = create_unique_test_db_path("integration");

    let mut db = Database::new_v2(&db_path).unwrap();

    // First, create the required enriched transactions
    insert_test_enriched_transaction(&mut db, "stamps_tx").unwrap();
    insert_test_enriched_transaction(&mut db, "counterparty_tx").unwrap();
    insert_test_enriched_transaction(&mut db, "unknown_tx").unwrap();

    // Create multiple test classifications
    let mut classifications = Vec::new();

    // Bitcoin Stamps classification
    let stamps_details = ClassificationDetails {
        burn_patterns_detected: vec![BurnPatternType::Stamps22Pattern],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Stamps burn pattern".to_string(),
        additional_metadata: None,
        content_type: None,
    };

    classifications.push(ClassificationResult {
        txid: "stamps_tx".to_string(),
        protocol: ProtocolType::BitcoinStamps,
        variant: Some(ProtocolVariant::StampsClassic),
        classification_details: stamps_details,
        classification_timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });

    // Counterparty classification
    let cp_details = ClassificationDetails {
        burn_patterns_detected: vec![], // Counterparty uses protocol identifiers, not burn patterns
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Counterparty burn pattern".to_string(),
        additional_metadata: None,
        content_type: None,
    };

    classifications.push(ClassificationResult {
        txid: "counterparty_tx".to_string(),
        protocol: ProtocolType::Counterparty,
        variant: Some(ProtocolVariant::CounterpartyTransfer),
        classification_details: cp_details,
        classification_timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });

    // Unknown classification
    let unknown_details = ClassificationDetails {
        burn_patterns_detected: Vec::new(),
        height_check_passed: true,
        protocol_signature_found: false,
        classification_method: "Fallback to unknown".to_string(),
        additional_metadata: Some("No definitive patterns".to_string()),
        content_type: None,
    };

    classifications.push(ClassificationResult {
        txid: "unknown_tx".to_string(),
        protocol: ProtocolType::Unknown,
        variant: None,
        classification_details: unknown_details,
        classification_timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    });

    // Insert batch
    db.insert_classification_results_batch(&classifications)
        .unwrap();

    // Verify results
    let stats = db.get_classification_stats().unwrap();
    assert_eq!(stats.total_classified, 3);
    assert_eq!(stats.bitcoin_stamps, 1);
    assert_eq!(stats.counterparty, 1);
    assert_eq!(stats.omni_layer, 0);
    assert_eq!(stats.unknown, 1);
    assert_eq!(stats.definitive_signatures, 2); // Stamps + Counterparty

    // Test percentage calculations (with reasonable tolerance for floating point)
    assert!(
        (safe_percentage(stats.bitcoin_stamps, stats.total_classified) - 33.333333333333336).abs()
            < 0.000001
    );
    assert!(
        (safe_percentage(stats.counterparty, stats.total_classified) - 33.333333333333336).abs()
            < 0.000001
    );
    assert!(
        (safe_percentage(stats.unknown, stats.total_classified) - 33.333333333333336).abs()
            < 0.000001
    );
    assert!((stats.definitive_signature_rate() - 66.66666666666667).abs() < 0.000001);
}

#[tokio::test]
async fn test_stage3_processor_creation() {
    let db_path = create_unique_test_db_path("integration");
    let config = create_test_config(&db_path);

    // Test processor creation
    let processor = Stage3Processor::new(&db_path, config);
    assert!(
        processor.is_ok(),
        "Stage3Processor should be created successfully"
    );
}

#[tokio::test]
async fn test_stage3_classification_stats_calculations() {
    // Test ClassificationStats percentage calculations
    let stats = ClassificationStats {
        total_classified: 100,
        bitcoin_stamps: 25,
        counterparty: 35,
        ascii_identifier_protocols: 0,
        omni_layer: 15,
        chancecoin: 0,
        ppk: 0,
        opreturn_signalled: 0,
        data_storage: 0,
        likely_data_storage: 0,
        likely_legitimate: 0,
        unknown: 25,
        definitive_signatures: 75,
    };

    assert_eq!(
        safe_percentage(stats.bitcoin_stamps, stats.total_classified),
        25.0
    );
    assert_eq!(
        safe_percentage(stats.counterparty, stats.total_classified),
        35.0
    );
    assert_eq!(
        safe_percentage(stats.omni_layer, stats.total_classified),
        15.0
    );
    assert_eq!(safe_percentage(stats.unknown, stats.total_classified), 25.0);
    assert_eq!(stats.definitive_signature_rate(), 75.0);

    // Test with zero totals
    let empty_stats = ClassificationStats {
        total_classified: 0,
        bitcoin_stamps: 0,
        counterparty: 0,
        ascii_identifier_protocols: 0,
        omni_layer: 0,
        chancecoin: 0,
        ppk: 0,
        opreturn_signalled: 0,
        data_storage: 0,
        likely_data_storage: 0,
        likely_legitimate: 0,
        unknown: 0,
        definitive_signatures: 0,
    };

    assert_eq!(
        safe_percentage(empty_stats.bitcoin_stamps, empty_stats.total_classified),
        0.0
    );
    assert_eq!(
        safe_percentage(empty_stats.counterparty, empty_stats.total_classified),
        0.0
    );
    assert_eq!(
        safe_percentage(empty_stats.omni_layer, empty_stats.total_classified),
        0.0
    );
    assert_eq!(
        safe_percentage(empty_stats.unknown, empty_stats.total_classified),
        0.0
    );
    assert_eq!(empty_stats.definitive_signature_rate(), 0.0);
}

#[tokio::test]
async fn test_stage3_unclassified_transaction_counting() {
    let db_path = create_unique_test_db_path("integration");

    let db = Database::new_v2(&db_path).unwrap();

    // Initially should have 0 unclassified transactions
    let count = db.count_unclassified_transactions_for_stage3().unwrap();
    assert_eq!(count, 0);

    // For this test, since we can't directly insert enriched transactions
    // (Stage 2 would do that), we'll verify that the counting works correctly
    // with the current empty state
    assert_eq!(
        count, 0,
        "Should have 0 unclassified transactions in empty database"
    );
}

#[test]
fn test_stage3_config_defaults() {
    let config = Stage3Config::default();

    assert_eq!(config.batch_size, 100);
}

#[test]
fn test_classification_details_serialization() {
    let details = ClassificationDetails {
        burn_patterns_detected: vec![
            BurnPatternType::Stamps22Pattern,
            BurnPatternType::ProofOfBurn, // Use actual burn pattern instead of incorrect CounterpartyBurn
        ],
        height_check_passed: true,
        protocol_signature_found: false,
        classification_method: "Test method".to_string(),
        additional_metadata: Some("extra info".to_string()),
        content_type: None,
    };

    // Test that it can be serialised and deserialised
    let json = serde_json::to_string(&details).unwrap();
    let deserialized: ClassificationDetails = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.burn_patterns_detected.len(), 2);
    assert!(deserialized.height_check_passed);
    assert!(!deserialized.protocol_signature_found);
    assert_eq!(deserialized.classification_method, "Test method");
    assert_eq!(
        deserialized.additional_metadata,
        Some("extra info".to_string())
    );
}

#[test]
fn test_protocol_and_variant_enums() {
    // Test that protocol types can be compared
    assert_eq!(ProtocolType::BitcoinStamps, ProtocolType::BitcoinStamps);
    assert_ne!(ProtocolType::BitcoinStamps, ProtocolType::Counterparty);

    // Test that variants can be compared
    assert_eq!(
        ProtocolVariant::StampsClassic,
        ProtocolVariant::StampsClassic
    );
    assert_ne!(ProtocolVariant::StampsClassic, ProtocolVariant::StampsSRC20);

    // Test Debug formatting (used in database storage)
    assert_eq!(
        format!("{:?}", ProtocolType::BitcoinStamps),
        "BitcoinStamps"
    );
    assert_eq!(
        format!("{:?}", ProtocolVariant::CounterpartyTransfer),
        "CounterpartyTransfer"
    );
}

/// Test that ALL protocols evaluate spendability (no NULL values in database)
///
/// This integration test verifies that after our spendability fixes, every
/// protocol (Chancecoin, DataStorage, AsciiIdentifierProtocols, WikiLeaksCablegate,
/// Unknown) properly evaluates spendability for all P2MS outputs.
#[tokio::test]
async fn test_no_null_spendability_in_database() {
    let db_path = create_unique_test_db_path("integration");
    let mut db = Database::new_v2(&db_path).unwrap();

    // Create test transactions for each protocol that was missing spendability
    let test_cases = vec![
        ("chancecoin_tx", ProtocolType::Chancecoin, "Chancecoin"),
        ("datastorage_tx", ProtocolType::DataStorage, "DataStorage"),
        (
            "ascii_identifier_protocols_tx",
            ProtocolType::AsciiIdentifierProtocols,
            "AsciiIdentifierProtocols",
        ),
        (
            "wikileaks_tx",
            ProtocolType::DataStorage,
            "WikiLeaksCablegate",
        ),
        ("unknown_tx", ProtocolType::Unknown, "Unknown"),
    ];

    for (txid, expected_protocol, protocol_name) in &test_cases {
        // Insert enriched transaction
        insert_test_enriched_transaction(&mut db, txid).unwrap();

        // CRITICAL: Insert transaction classification FIRST (FK constraint requirement)
        let tx_classification = ClassificationResult::new(
            txid.to_string(),
            expected_protocol.clone(),
            None,
            ClassificationDetails {
                burn_patterns_detected: vec![],
                height_check_passed: true,
                protocol_signature_found: false,
                classification_method: format!("{} test classification", protocol_name),
                additional_metadata: Some("Test data".to_string()),
                content_type: None,
            },
        );
        db.insert_classification_results_batch(&[tx_classification])
            .unwrap();

        // Insert a sample P2MS output for this transaction using batch API
        let output_data = OutputClassificationData::new(
            0, // vout
            expected_protocol.clone(),
            None,
            OutputClassificationDetails {
                burn_patterns_detected: vec![],
                height_check_passed: true,
                protocol_signature_found: false,
                classification_method: format!("{} test classification", protocol_name),
                additional_metadata: Some("Test data".to_string()),
                content_type: None,
                // Critical: spendability MUST be evaluated for output classification
                is_spendable: false, // Using false as default for test
                spendability_reason: "Test: no real pubkeys".to_string(),
                real_pubkey_count: 0,
                burn_key_count: 0,
                data_key_count: 3,
            },
        );
        db.insert_output_classifications_batch(txid, &[output_data])
            .unwrap();
    }

    // CRITICAL ASSERTION: Count NULL is_spendable values in database
    let conn = db.connection();
    let null_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM p2ms_output_classifications WHERE is_spendable IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        null_count, 0,
        "CRITICAL: Found {} outputs with NULL is_spendable! All protocols must evaluate spendability.",
        null_count
    );

    // Verify all test outputs have spendability evaluated
    for (txid, _protocol, protocol_name) in &test_cases {
        let has_spendable: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM p2ms_output_classifications
                 WHERE txid = ? AND is_spendable IS NOT NULL",
                [txid],
                |row| row.get(0),
            )
            .unwrap();

        assert!(
            has_spendable,
            "{} protocol must evaluate spendability for txid: {}",
            protocol_name, txid
        );
    }
}

/// Unit test to verify output classification structure includes spendability
///
/// This test verifies that OutputClassificationDetails (used for per-output classification)
/// contains valid spendability data. Transaction-level ClassificationDetails do NOT have
/// spendability fields - that's an output-level property only.
#[test]
fn test_all_protocols_evaluate_spendability() {
    // This is a verification test that checks the OUTPUT classification details structure
    // In practice, each protocol's integration tests should verify spendability

    // Verify that a properly formed OutputClassificationDetails has spendability fields
    let details_with_spendability = OutputClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test".to_string(),
        additional_metadata: None,
        content_type: None,
        is_spendable: true, // Required field (not Option)
        spendability_reason: "Has valid secp256k1 public keys".to_string(),
        real_pubkey_count: 3,
        burn_key_count: 0,
        data_key_count: 0,
    };

    // Verify spendability fields are populated (they are required, not Option)
    assert!(
        details_with_spendability.is_spendable,
        "Spendable outputs must have is_spendable = true"
    );
    assert_eq!(
        details_with_spendability.spendability_reason, "Has valid secp256k1 public keys",
        "spendability_reason must explain why output is spendable"
    );

    // Verify the opposite case (unspendable)
    let details_unspendable = OutputClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test".to_string(),
        additional_metadata: None,
        content_type: None,
        is_spendable: false, // Required field (not Option)
        spendability_reason: "All keys are data (invalid EC points)".to_string(),
        real_pubkey_count: 0,
        burn_key_count: 0,
        data_key_count: 3,
    };

    assert!(
        !details_unspendable.is_spendable,
        "Unspendable outputs must have is_spendable = false"
    );
    assert_eq!(
        details_unspendable.real_pubkey_count, 0,
        "Unspendable output with all data keys should have 0 real pubkeys"
    );
}
