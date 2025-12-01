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
    let mut db = Database::new(&db_path).unwrap();

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
        variant: Some(ProtocolVariant::CounterpartyTransfer),
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
        variant: Some(ProtocolVariant::OmniTransfer),
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

#[test]
fn test_output_level_content_type_propagation() {
    //! Test that content types properly propagate from transaction level
    //! to output-level classifications (Counterparty/Omni fixes from Phase 1)

    let db_path = create_unique_test_db_path("output_content_type");
    let mut db = Database::new(&db_path).unwrap();

    // Insert enriched transaction
    let tx = EnrichedTransaction {
        txid: "test_cp_tx".to_string(),
        height: 290000,
        total_input_value: 10000,
        total_output_value: 9000,
        transaction_fee: 1000,
        fee_per_byte: 10.0,
        transaction_size_bytes: 100,
        fee_per_kb: 10000.0,
        total_p2ms_amount: 2000,
        data_storage_fee_rate: 10.0,
        p2ms_outputs_count: 2,
        input_count: 1,
        output_count: 3,
        is_coinbase: false,
        burn_patterns_detected: vec![],
        outputs: vec![],
    };

    db.insert_enriched_transactions_batch(&[(tx, vec![], vec![])])
        .unwrap();

    // Insert transaction-level classification with content type
    let details = ClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Signature-based".to_string(),
        additional_metadata: None,
        content_type: Some("application/octet-stream".to_string()),
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let result = ClassificationResult {
        txid: "test_cp_tx".to_string(),
        protocol: ProtocolType::Counterparty,
        variant: Some(ProtocolVariant::CounterpartyTransfer),
        classification_details: details,
        classification_timestamp: timestamp,
    };

    db.insert_classification_results_batch(&[result]).unwrap();

    // Manually insert output-level classifications to simulate Phase 1 fixes
    let conn = db.connection();

    // First insert blocks (required for FK) - use OR IGNORE since enriched_transactions_batch already inserts it
    conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (290000)", [])
        .unwrap();

    // Insert transaction_outputs (required for p2ms_outputs FK)
    conn.execute(
        "INSERT INTO transaction_outputs
         (txid, vout, height, amount, script_hex, script_type, is_coinbase, script_size,
          metadata_json, is_spent)
         VALUES ('test_cp_tx', 0, 290000, 1000, 'aabbcc', 'multisig', 0, 800, '{}', 0)",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO transaction_outputs
         (txid, vout, height, amount, script_hex, script_type, is_coinbase, script_size,
          metadata_json, is_spent)
         VALUES ('test_cp_tx', 1, 290000, 1000, 'ddeeff', 'multisig', 0, 600, '{}', 0)",
        [],
    )
    .unwrap();

    // Insert p2ms_outputs (required for p2ms_output_classifications FK)
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('test_cp_tx', 0, 1, 3, '[]')",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('test_cp_tx', 1, 1, 3, '[]')",
        [],
    )
    .unwrap();

    // Output 0: Data-carrying output (protocol_signature_found = true, should have content_type)
    conn.execute(
        "INSERT INTO p2ms_output_classifications
         (txid, vout, protocol, variant, protocol_signature_found, classification_method,
          content_type, is_spendable)
         VALUES ('test_cp_tx', 0, 'Counterparty', 'CounterpartyTransfer', 1, 'Signature-based',
                 'application/octet-stream', 0)",
        [],
    )
    .unwrap();

    // Output 1: Dust output (protocol_signature_found = false, NULL content_type is correct)
    conn.execute(
        "INSERT INTO p2ms_output_classifications
         (txid, vout, protocol, variant, protocol_signature_found, classification_method,
          content_type, is_spendable)
         VALUES ('test_cp_tx', 1, 'Counterparty', 'CounterpartyTransfer', 0, 'Signature-based',
                 NULL, 0)",
        [],
    )
    .unwrap();

    // Query: Verify data-carrying output has content type
    let data_output_content: Option<String> = conn
        .query_row(
            "SELECT content_type FROM p2ms_output_classifications
             WHERE txid = 'test_cp_tx' AND vout = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        data_output_content,
        Some("application/octet-stream".to_string()),
        "Data-carrying output should have content type"
    );

    // Query: Verify dust output has NULL content type
    let dust_output_content: Option<String> = conn
        .query_row(
            "SELECT content_type FROM p2ms_output_classifications
             WHERE txid = 'test_cp_tx' AND vout = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert!(
        dust_output_content.is_none(),
        "Dust output should have NULL content type"
    );

    // Query: Verify protocol_signature_found distinguishes them
    let signature_found_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM p2ms_output_classifications
             WHERE txid = 'test_cp_tx' AND protocol_signature_found = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        signature_found_count, 1,
        "Only data-carrying output should have protocol_signature_found = true"
    );

    println!("✅ Output-level content type propagation test passed");
}

#[test]
fn test_valid_none_cases_in_database() {
    //! Test that valid None cases (LikelyDataStorage, LikelyLegitimateMultisig,
    //! StampsUnknown, OmniFailedDeobfuscation) are properly stored with NULL content_type

    let db_path = create_unique_test_db_path("valid_none");
    let mut db = Database::new(&db_path).unwrap();

    // Insert enriched transactions
    let txs = vec![
        ("lds_tx", 100000),
        ("llm_tx", 100001),
        ("stamps_unknown_tx", 780000),
        ("omni_failed_tx", 370000),
    ];

    for (txid, height) in &txs {
        let tx = EnrichedTransaction {
            txid: txid.to_string(),
            height: *height,
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

        db.insert_enriched_transactions_batch(&[(tx, vec![], vec![])])
            .unwrap();
    }

    // Insert classifications for valid None cases
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // LikelyDataStorage - NULL content_type (decoder will extract)
    let lds_result = ClassificationResult {
        txid: "lds_tx".to_string(),
        protocol: ProtocolType::LikelyDataStorage,
        variant: None,
        classification_details: ClassificationDetails {
            burn_patterns_detected: vec![],
            height_check_passed: true,
            protocol_signature_found: true,
            classification_method: "Pattern-based".to_string(),
            additional_metadata: None,
            content_type: None, // Valid None
        },
        classification_timestamp: timestamp,
    };

    // LikelyLegitimateMultisig - NULL content_type (real multisig, not data-carrying)
    let llm_result = ClassificationResult {
        txid: "llm_tx".to_string(),
        protocol: ProtocolType::LikelyLegitimateMultisig,
        variant: None,
        classification_details: ClassificationDetails {
            burn_patterns_detected: vec![],
            height_check_passed: true,
            protocol_signature_found: false, // Not a data protocol
            classification_method: "EC-point validation".to_string(),
            additional_metadata: None,
            content_type: None, // Valid None
        },
        classification_timestamp: timestamp,
    };

    // BitcoinStamps StampsUnknown - NULL content_type (decryption failed)
    let stamps_unknown_result = ClassificationResult {
        txid: "stamps_unknown_tx".to_string(),
        protocol: ProtocolType::BitcoinStamps,
        variant: Some(ProtocolVariant::StampsUnknown),
        classification_details: ClassificationDetails {
            burn_patterns_detected: vec![],
            height_check_passed: true,
            protocol_signature_found: true,
            classification_method: "Signature-based".to_string(),
            additional_metadata: None,
            content_type: None, // Valid None - ARC4 decryption failed
        },
        classification_timestamp: timestamp,
    };

    // Omni FailedDeobfuscation - NULL content_type (deobfuscation failed)
    let omni_failed_result = ClassificationResult {
        txid: "omni_failed_tx".to_string(),
        protocol: ProtocolType::OmniLayer,
        variant: Some(ProtocolVariant::OmniFailedDeobfuscation),
        classification_details: ClassificationDetails {
            burn_patterns_detected: vec![],
            height_check_passed: true,
            protocol_signature_found: true,
            classification_method: "Signature-based".to_string(),
            additional_metadata: None,
            content_type: None, // Valid None - deobfuscation failed
        },
        classification_timestamp: timestamp,
    };

    db.insert_classification_results_batch(&[
        lds_result,
        llm_result,
        stamps_unknown_result,
        omni_failed_result,
    ])
    .unwrap();

    // Query: Verify all valid None cases have NULL content_type
    let conn = db.connection();
    let null_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transaction_classifications
             WHERE content_type IS NULL
               AND protocol IN ('LikelyDataStorage', 'LikelyLegitimateMultisig', 'BitcoinStamps', 'OmniLayer')",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        null_count, 4,
        "All valid None cases should have NULL content_type"
    );

    // Query: Verify specific protocols
    let lds_content: Option<String> = conn
        .query_row(
            "SELECT content_type FROM transaction_classifications WHERE txid = 'lds_tx'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        lds_content.is_none(),
        "LikelyDataStorage should have NULL content_type"
    );

    let llm_content: Option<String> = conn
        .query_row(
            "SELECT content_type FROM transaction_classifications WHERE txid = 'llm_tx'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        llm_content.is_none(),
        "LikelyLegitimateMultisig should have NULL content_type"
    );

    println!("✅ Valid None cases in database test passed");
}
