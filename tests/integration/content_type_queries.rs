//! Integration tests for content-type database schema and queries
//!
//! This test suite validates that the content-type field is properly
//! supported in the database schema and can be queried effectively.
//!
//! NOTE: Current tests use raw SQL queries to validate schema support.
//! Future enhancement: Add tests using public Stage3Operations API when
//! content-type query helpers are added to the trait.

use data_carry_research::database::traits::{Stage2Operations, Stage3Operations};
use data_carry_research::database::Database;
use data_carry_research::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, ProtocolType,
    ProtocolVariant, TransactionInput,
};
use std::time::{SystemTime, UNIX_EPOCH};

// Import common test utilities
use crate::common::create_unique_test_db_path;

#[test]
fn test_content_type_schema_and_queries() {
    // Create a unique test database
    let db_path = create_unique_test_db_path("content_type");
    let mut db = Database::new_v2(&db_path).unwrap();

    // First, insert enriched transactions (required for foreign key)
    let tx1 = EnrichedTransaction {
        txid: "txid1".to_string(),
        height: 290000,
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
        burn_patterns_detected: vec![],
        outputs: vec![],
    };

    let tx2 = EnrichedTransaction {
        txid: "txid2".to_string(),
        height: 780000,
        ..tx1.clone()
    };

    let tx3 = EnrichedTransaction {
        txid: "txid3".to_string(),
        height: 300000,
        ..tx1.clone()
    };

    let inputs: Vec<TransactionInput> = vec![];
    db.insert_enriched_transactions_batch(&[
        (tx1, inputs.clone(), Vec::new()),
        (tx2, inputs.clone(), Vec::new()),
        (tx3, inputs, Vec::new()),
    ])
    .unwrap();

    // Insert test classifications with different content types
    let details1 = ClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test method".to_string(),
        additional_metadata: None,
        content_type: Some("application/octet-stream".to_string()),
    };

    let details2 = ClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test method".to_string(),
        additional_metadata: None,
        content_type: Some("text/plain".to_string()),
    };

    let details3 = ClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test method".to_string(),
        additional_metadata: None,
        content_type: None, // Test NULL content_type
    };

    // Create classification results
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let result1 = ClassificationResult {
        txid: "txid1".to_string(),
        protocol: ProtocolType::Counterparty,
        variant: Some(ProtocolVariant::CounterpartySend),
        classification_details: details1,
        classification_timestamp: timestamp,
    };

    let result2 = ClassificationResult {
        txid: "txid2".to_string(),
        protocol: ProtocolType::BitcoinStamps,
        variant: Some(ProtocolVariant::StampsSRC20),
        classification_details: details2,
        classification_timestamp: timestamp,
    };

    let result3 = ClassificationResult {
        txid: "txid3".to_string(),
        protocol: ProtocolType::OmniLayer,
        variant: Some(ProtocolVariant::OmniSimpleSend),
        classification_details: details3,
        classification_timestamp: timestamp,
    };

    // Insert classifications
    db.insert_classification_results_batch(&[result1, result2, result3])
        .unwrap();

    // Query 1: Find all transactions with binary content type
    let conn = db.connection();
    let binary_txids: Vec<String> = conn
        .prepare("SELECT txid FROM transaction_classifications WHERE content_type = 'application/octet-stream'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(binary_txids.len(), 1);
    assert_eq!(binary_txids[0], "txid1");

    // Query 2: Find all transactions with text content type
    let text_txids: Vec<String> = conn
        .prepare("SELECT txid FROM transaction_classifications WHERE content_type = 'text/plain'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(text_txids.len(), 1);
    assert_eq!(text_txids[0], "txid2");

    // Query 3: Find all transactions with NULL content type
    let null_content_txids: Vec<String> = conn
        .prepare("SELECT txid FROM transaction_classifications WHERE content_type IS NULL")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(null_content_txids.len(), 1);
    assert_eq!(null_content_txids[0], "txid3");

    // Query 4: Count transactions by content type
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transaction_classifications WHERE content_type IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(count, 2);

    println!("✅ Content-type schema and queries test passed");
}
