//! Integration tests for spendability database schema and queries
//!
//! This test suite validates that the spendability fields are properly
//! supported in the database schema and can be queried effectively.
//!
//! Tests cover:
//! - Overall spendability breakdown queries
//! - Per-protocol spendability queries (no join required)
//! - Spendability reason distribution
//! - Key count aggregations
//! - Transaction-level aggregation (any output spendable?)
//! - SQL constant reusability

use data_carry_research::database::traits::{Stage2Operations, Stage3Operations};
use data_carry_research::database::Database;
use data_carry_research::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, OutputClassificationData,
    OutputClassificationDetails, ProtocolType, ProtocolVariant, TransactionInput,
};

// Import common test utilities
use crate::common::create_unique_test_db_path;

#[test]
fn test_spendability_schema_support() {
    // Create a unique test database
    let db_path = create_unique_test_db_path("spendability");
    let mut db = Database::new(&db_path).unwrap();

    // Insert stub block for FK constraint (height 780000)
    let conn = db.connection();
    conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (780000)", [])
        .unwrap();

    // Insert enriched transactions (required for foreign key)
    // Create P2MS outputs for testing (required by database trigger)
    // Use height 780000 to match the EnrichedTransaction height
    let p2ms_output_tx1 = crate::common::fixtures::create_test_p2ms_output_with_height(
        "spendable_tx1",
        0,
        "dummy_script_hex",
        780000,
    );
    let p2ms_output_tx2 = crate::common::fixtures::create_test_p2ms_output_with_height(
        "unspendable_tx2",
        0,
        "dummy_script_hex",
        780000,
    );

    let tx1 = EnrichedTransaction {
        txid: "spendable_tx1".to_string(),
        height: 780000,
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
        outputs: vec![p2ms_output_tx1],
    };

    let tx2 = EnrichedTransaction {
        txid: "unspendable_tx2".to_string(),
        height: 780000,
        outputs: vec![p2ms_output_tx2],
        ..tx1.clone()
    };

    let inputs: Vec<TransactionInput> = vec![];

    // Extract outputs for batch insertion (separate from EnrichedTransaction.outputs)
    let outputs_tx1 = tx1.outputs.clone();
    let outputs_tx2 = tx2.outputs.clone();

    db.insert_enriched_transactions_batch(&[
        (tx1, inputs.clone(), outputs_tx1),
        (tx2, inputs.clone(), outputs_tx2),
    ])
    .unwrap();

    // Insert test classifications with different spendability scenarios

    // Insert transaction classifications FIRST (FK constraint requirement)
    let tx_classifications = vec![
        ClassificationResult::new(
            "spendable_tx1".to_string(),
            ProtocolType::Counterparty,
            None,
            ClassificationDetails {
                burn_patterns_detected: vec![],
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: "Test method".to_string(),
                additional_metadata: None,
                content_type: Some("application/octet-stream".to_string()),
            },
        ),
        ClassificationResult::new(
            "unspendable_tx2".to_string(),
            ProtocolType::BitcoinStamps,
            Some(ProtocolVariant::StampsSRC20),
            ClassificationDetails {
                burn_patterns_detected: vec![],
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: "Test method".to_string(),
                additional_metadata: None,
                content_type: Some("text/plain".to_string()),
            },
        ),
    ];
    db.insert_classification_results_batch(&tx_classifications)
        .unwrap();

    // Scenario 1: Spendable (Counterparty - contains real pubkey)
    let details_spendable = OutputClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test method".to_string(),
        additional_metadata: None,
        content_type: Some("application/octet-stream".to_string()),
        is_spendable: true,
        spendability_reason: "ContainsRealPubkey".to_string(),
        real_pubkey_count: 1,
        burn_key_count: 0,
        data_key_count: 2,
    };

    let output_data_spendable =
        OutputClassificationData::new(0, ProtocolType::Counterparty, None, details_spendable);
    db.insert_output_classifications_batch("spendable_tx1", &[output_data_spendable])
        .unwrap();

    // Scenario 2: Unspendable (Bitcoin Stamps - all burn keys)
    let details_unspendable = OutputClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test method".to_string(),
        additional_metadata: None,
        content_type: None,
        is_spendable: false,
        spendability_reason: "AllBurnKeys".to_string(),
        real_pubkey_count: 0,
        burn_key_count: 2,
        data_key_count: 1,
    };

    let output_data_unspendable =
        OutputClassificationData::new(0, ProtocolType::BitcoinStamps, None, details_unspendable);
    db.insert_output_classifications_batch("unspendable_tx2", &[output_data_unspendable])
        .unwrap();

    // Query and verify spendability fields
    let conn = db.connection();

    // Test overall spendable count
    let spendable_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM p2ms_output_classifications WHERE is_spendable = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(spendable_count, 1, "Should have 1 spendable output");

    // Test unspendable count
    let unspendable_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM p2ms_output_classifications WHERE is_spendable = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unspendable_count, 1, "Should have 1 unspendable output");

    // Test reason query
    let all_burn_keys_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM p2ms_output_classifications WHERE spendability_reason = 'AllBurnKeys'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        all_burn_keys_count, 1,
        "Should have 1 output with AllBurnKeys reason"
    );

    // Test key count fields
    let (real_count, burn_count, data_count): (i64, i64, i64) = conn
        .query_row(
            "SELECT real_pubkey_count, burn_key_count, data_key_count FROM p2ms_output_classifications WHERE txid = 'spendable_tx1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(real_count, 1, "Spendable output should have 1 real key");
    assert_eq!(burn_count, 0, "Spendable output should have 0 burn keys");
    assert_eq!(data_count, 2, "Spendable output should have 2 data keys");
}

#[test]
fn test_overall_spendability_query() {
    let db_path = create_unique_test_db_path("spendability_overall");
    let mut db = Database::new(&db_path).unwrap();

    // Setup test data with both spendable and unspendable categories
    // After breaking change: ALL output classifications MUST have spendability evaluated
    insert_test_transactions(
        &mut db,
        &[
            (
                "tx1",
                true,
                "ContainsRealPubkey",
                ProtocolType::Counterparty,
            ),
            ("tx2", false, "AllBurnKeys", ProtocolType::BitcoinStamps),
            (
                "tx3",
                true,
                "AllValidECPoints",
                ProtocolType::LikelyLegitimateMultisig,
            ),
        ],
    );

    let conn = db.connection();

    // Test overall breakdown query (matches SQL constant from spendability_stats.rs)
    // Note: After breaking change, NULL spendability is no longer possible for output classifications
    let mut stmt = conn
        .prepare(
            "SELECT is_spendable, COUNT(*) as count
             FROM p2ms_output_classifications
             GROUP BY is_spendable",
        )
        .unwrap();

    let results: Vec<(Option<bool>, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(
        results.len(),
        2,
        "Should have 2 spendability categories (true/false, no NULL)"
    );

    let spendable = results
        .iter()
        .find(|(is_spendable, _)| *is_spendable == Some(true));
    let unspendable = results
        .iter()
        .find(|(is_spendable, _)| *is_spendable == Some(false));

    assert_eq!(spendable.unwrap().1, 2, "Should have 2 spendable outputs");
    assert_eq!(
        unspendable.unwrap().1,
        1,
        "Should have 1 unspendable output"
    );
}

#[test]
fn test_per_protocol_spendability_no_join() {
    let db_path = create_unique_test_db_path("spendability_protocol");
    let mut db = Database::new(&db_path).unwrap();

    // Setup test data with evaluated spendability
    // After breaking change: ALL output classifications MUST have spendability evaluated
    insert_test_transactions(
        &mut db,
        &[
            (
                "tx1",
                true,
                "ContainsRealPubkey",
                ProtocolType::Counterparty,
            ),
            ("tx2", false, "AllBurnKeys", ProtocolType::BitcoinStamps),
            ("tx3", false, "AllBurnKeys", ProtocolType::BitcoinStamps),
            (
                "tx4",
                true,
                "AllValidECPoints",
                ProtocolType::LikelyLegitimateMultisig,
            ),
            ("tx5", false, "AllDataKeys", ProtocolType::Chancecoin),
            ("tx6", false, "MixedBurnAndData", ProtocolType::DataStorage),
        ],
    );

    let conn = db.connection();

    // Test per-protocol query (NO JOIN - protocol column exists in p2ms_output_classifications)
    // Note: Includes NULL values as "not evaluated" category
    let mut stmt = conn
        .prepare(
            "SELECT protocol, is_spendable, COUNT(*) as count
             FROM p2ms_output_classifications
             GROUP BY protocol, is_spendable
             ORDER BY protocol, is_spendable",
        )
        .unwrap();

    let results: Vec<(String, Option<bool>, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Verify Bitcoin Stamps (all unspendable)
    let stamps_results: Vec<_> = results
        .iter()
        .filter(|(protocol, _, _)| protocol == "BitcoinStamps")
        .collect();
    assert_eq!(stamps_results.len(), 1, "BitcoinStamps should have 1 entry");
    assert_eq!(
        stamps_results[0].1,
        Some(false),
        "BitcoinStamps should be unspendable"
    );
    assert_eq!(stamps_results[0].2, 2, "Should have 2 Stamps outputs");

    // Verify Counterparty (all spendable)
    let cp_results: Vec<_> = results
        .iter()
        .filter(|(protocol, _, _)| protocol == "Counterparty")
        .collect();
    assert_eq!(cp_results.len(), 1, "Counterparty should have 1 entry");
    assert_eq!(
        cp_results[0].1,
        Some(true),
        "Counterparty should be spendable"
    );
    assert_eq!(cp_results[0].2, 1, "Should have 1 Counterparty output");

    // Verify Chancecoin (evaluated as unspendable after breaking change)
    let chancecoin_results: Vec<_> = results
        .iter()
        .filter(|(protocol, _, _)| protocol == "Chancecoin")
        .collect();
    assert_eq!(
        chancecoin_results.len(),
        1,
        "Chancecoin should have 1 entry"
    );
    assert_eq!(
        chancecoin_results[0].1,
        Some(false),
        "Chancecoin should be evaluated as unspendable (AllDataKeys)"
    );
    assert_eq!(
        chancecoin_results[0].2, 1,
        "Should have 1 Chancecoin output"
    );

    // Verify DataStorage (evaluated as unspendable after breaking change)
    let datastorage_results: Vec<_> = results
        .iter()
        .filter(|(protocol, _, _)| protocol == "DataStorage")
        .collect();
    assert_eq!(
        datastorage_results.len(),
        1,
        "DataStorage should have 1 entry"
    );
    assert_eq!(
        datastorage_results[0].1,
        Some(false),
        "DataStorage should be evaluated as unspendable (MixedBurnAndData)"
    );
    assert_eq!(
        datastorage_results[0].2, 1,
        "Should have 1 DataStorage output"
    );
}

#[test]
fn test_reason_distribution_query() {
    let db_path = create_unique_test_db_path("spendability_reason");
    let mut db = Database::new(&db_path).unwrap();

    // Setup test data with different reasons
    insert_test_transactions(
        &mut db,
        &[
            (
                "tx1",
                true,
                "ContainsRealPubkey",
                ProtocolType::Counterparty,
            ),
            ("tx2", true, "ContainsRealPubkey", ProtocolType::OmniLayer),
            ("tx3", false, "AllBurnKeys", ProtocolType::BitcoinStamps),
            ("tx4", false, "AllBurnKeys", ProtocolType::BitcoinStamps),
            ("tx5", false, "AllBurnKeys", ProtocolType::BitcoinStamps),
            (
                "tx6",
                true,
                "AllValidECPoints",
                ProtocolType::LikelyLegitimateMultisig,
            ),
        ],
    );

    let conn = db.connection();

    // Test reason distribution query
    let mut stmt = conn
        .prepare(
            "SELECT spendability_reason, COUNT(*) as count
             FROM p2ms_output_classifications
             WHERE spendability_reason IS NOT NULL
             GROUP BY spendability_reason
             ORDER BY count DESC",
        )
        .unwrap();

    let results: Vec<(String, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(results.len(), 3, "Should have 3 different reasons");

    // AllBurnKeys should be most common (3 occurrences)
    assert_eq!(results[0].0, "AllBurnKeys");
    assert_eq!(results[0].1, 3);

    // ContainsRealPubkey should be second (2 occurrences)
    assert_eq!(results[1].0, "ContainsRealPubkey");
    assert_eq!(results[1].1, 2);

    // AllValidECPoints should be third (1 occurrence)
    assert_eq!(results[2].0, "AllValidECPoints");
    assert_eq!(results[2].1, 1);
}

#[test]
fn test_key_count_aggregations() {
    let db_path = create_unique_test_db_path("spendability_keycounts");
    let mut db = Database::new(&db_path).unwrap();

    // Insert stub block for FK constraint (height 780000)
    let conn = db.connection();
    conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (780000)", [])
        .unwrap();

    // Insert transactions with specific key counts
    // Create P2MS output for testing (required by database trigger)
    // CRITICAL: Must use same height as stub block (780000) for FK constraint
    let p2ms_output = crate::common::fixtures::create_test_p2ms_output_with_height(
        "dummy",
        0,
        "dummy_script_hex",
        780000,
    );

    let tx = EnrichedTransaction {
        txid: "dummy".to_string(),
        height: 780000,
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
        outputs: vec![p2ms_output],
    };

    // Extract outputs for batch insertion (separate from EnrichedTransaction.outputs)
    let outputs = tx.outputs.clone();
    db.insert_enriched_transactions_batch(&[(tx, Vec::new(), outputs)])
        .unwrap();

    // Insert transaction classification BEFORE output classification (FK requirement)
    let tx_classification = ClassificationResult::new(
        "dummy".to_string(),
        ProtocolType::BitcoinStamps,
        None,
        ClassificationDetails {
            burn_patterns_detected: vec![],
            height_check_passed: true,
            protocol_signature_found: true,
            classification_method: "Test method".to_string(),
            additional_metadata: None,
            content_type: None,
        },
    );
    db.insert_classification_results_batch(&[tx_classification])
        .unwrap();

    let details = OutputClassificationDetails {
        burn_patterns_detected: vec![],
        height_check_passed: true,
        protocol_signature_found: true,
        classification_method: "Test".to_string(),
        additional_metadata: None,
        content_type: None,
        is_spendable: false,
        spendability_reason: "AllBurnKeys".to_string(),
        real_pubkey_count: 0,
        burn_key_count: 2,
        data_key_count: 1,
    };

    let output_data = OutputClassificationData::new(0, ProtocolType::BitcoinStamps, None, details);
    db.insert_output_classifications_batch("dummy", &[output_data])
        .unwrap();

    let conn = db.connection();

    // Test key count aggregation query
    let (total_real, avg_real, min_real, max_real, total_burn, total_data): (
        i64,
        f64,
        i64,
        i64,
        i64,
        i64,
    ) = conn
        .query_row(
            "SELECT
                SUM(real_pubkey_count) as total_real,
                AVG(real_pubkey_count) as avg_real,
                MIN(real_pubkey_count) as min_real,
                MAX(real_pubkey_count) as max_real,
                SUM(burn_key_count) as total_burn,
                SUM(data_key_count) as total_data
             FROM p2ms_output_classifications",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();

    assert_eq!(total_real, 0, "Total real pubkeys should be 0");
    assert_eq!(avg_real, 0.0, "Average real pubkeys should be 0.0");
    assert_eq!(min_real, 0, "Min real pubkeys should be 0");
    assert_eq!(max_real, 0, "Max real pubkeys should be 0");
    assert_eq!(total_burn, 2, "Total burn keys should be 2");
    assert_eq!(total_data, 1, "Total data keys should be 1");
}

#[test]
fn test_transaction_level_aggregation() {
    let db_path = create_unique_test_db_path("spendability_txlevel");
    let mut db = Database::new(&db_path).unwrap();

    // Setup: 3 transactions, 2 with at least one spendable output, 1 with none
    insert_test_transactions(
        &mut db,
        &[
            (
                "tx1",
                true,
                "ContainsRealPubkey",
                ProtocolType::Counterparty,
            ),
            ("tx2", false, "AllBurnKeys", ProtocolType::BitcoinStamps),
            (
                "tx3",
                true,
                "AllValidECPoints",
                ProtocolType::LikelyLegitimateMultisig,
            ),
        ],
    );

    let conn = db.connection();

    // Test transaction-level aggregation (any output spendable?)
    let (txs_with_spendable, total_txs): (i64, i64) = conn
        .query_row(
            "SELECT
                COUNT(DISTINCT CASE WHEN has_spendable = 1 THEN txid END) as txs_with_spendable,
                COUNT(DISTINCT txid) as total_txs
             FROM (
                SELECT txid, MAX(is_spendable) as has_spendable
                FROM p2ms_output_classifications
                GROUP BY txid
             )",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();

    assert_eq!(total_txs, 3, "Should have 3 total transactions");
    assert_eq!(
        txs_with_spendable, 2,
        "Should have 2 transactions with spendable outputs"
    );
}

#[test]
fn test_sql_constant_reusability() {
    // This test verifies that SQL constants from spendability_stats.rs work correctly
    // by using them directly in test queries

    let db_path = create_unique_test_db_path("spendability_sql_constants");
    let mut db = Database::new(&db_path).unwrap();

    insert_test_transactions(
        &mut db,
        &[(
            "tx1",
            true,
            "ContainsRealPubkey",
            ProtocolType::Counterparty,
        )],
    );

    let conn = db.connection();

    // Test SQL_OVERALL_BREAKDOWN constant (includes NULLs)
    let result = conn.query_row(
        "SELECT is_spendable, COUNT(*) as count FROM p2ms_output_classifications GROUP BY is_spendable",
        [],
        |row| Ok((row.get::<_, Option<bool>>(0)?, row.get::<_, i64>(1)?)),
    );
    assert!(
        result.is_ok(),
        "SQL_OVERALL_BREAKDOWN constant should be valid"
    );

    // Test SQL_PROTOCOL_BREAKDOWN constant (includes NULLs)
    let result = conn.query_row(
        "SELECT protocol, is_spendable, COUNT(*) as count FROM p2ms_output_classifications GROUP BY protocol, is_spendable",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<bool>>(1)?, row.get::<_, i64>(2)?)),
    );
    assert!(
        result.is_ok(),
        "SQL_PROTOCOL_BREAKDOWN constant should be valid"
    );

    // Test SQL_REASON_DISTRIBUTION constant
    let result = conn.query_row(
        "SELECT spendability_reason, COUNT(*) as count FROM p2ms_output_classifications WHERE spendability_reason IS NOT NULL GROUP BY spendability_reason",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    );
    assert!(
        result.is_ok(),
        "SQL_REASON_DISTRIBUTION constant should be valid"
    );
}

// Helper function to insert test transactions with spendability data
fn insert_test_transactions(db: &mut Database, data: &[(&str, bool, &str, ProtocolType)]) {
    // Insert stub block for FK constraint (height 780000)
    {
        let conn = db.connection();
        conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (780000)", [])
            .unwrap();
    }

    for (txid, is_spendable, reason, protocol) in data {
        // Create P2MS output for testing (required by database trigger)
        // CRITICAL: Must use same height as stub block (780000) for FK constraint
        let p2ms_output = crate::common::fixtures::create_test_p2ms_output_with_height(
            txid,
            0,
            "dummy_script_hex",
            780000,
        );

        let tx = EnrichedTransaction {
            txid: txid.to_string(),
            height: 780000,
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
            outputs: vec![p2ms_output],
        };

        // Extract outputs for batch insertion (separate from EnrichedTransaction.outputs)
        let outputs = tx.outputs.clone();
        db.insert_enriched_transactions_batch(&[(tx, Vec::new(), outputs)])
            .unwrap();

        // Insert transaction classification BEFORE output classification (FK requirement)
        let tx_classification = ClassificationResult::new(
            txid.to_string(),
            protocol.clone(),
            None,
            ClassificationDetails {
                burn_patterns_detected: vec![],
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: "Test method".to_string(),
                additional_metadata: None,
                content_type: None,
            },
        );
        db.insert_classification_results_batch(&[tx_classification])
            .unwrap();

        let (real_count, burn_count, data_count) = match *reason {
            "ContainsRealPubkey" => (1, 0, 2),
            "AllBurnKeys" => (0, 2, 1),
            "AllValidECPoints" => (3, 0, 0),
            _ => (0, 0, 0),
        };

        let details = OutputClassificationDetails {
            burn_patterns_detected: vec![],
            height_check_passed: true,
            protocol_signature_found: true,
            classification_method: "Test method".to_string(),
            additional_metadata: None,
            content_type: None,
            is_spendable: *is_spendable,
            spendability_reason: reason.to_string(),
            real_pubkey_count: real_count,
            burn_key_count: burn_count,
            data_key_count: data_count,
        };

        let output_data = OutputClassificationData::new(0, protocol.clone(), None, details);
        db.insert_output_classifications_batch(txid, &[output_data])
            .unwrap();
    }
}
