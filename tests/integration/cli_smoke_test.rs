//! CLI Smoke Test for Schema V2
//!
//! This integration test verifies that all CLI analysis commands work correctly
//! with Schema V2 databases. It creates a fully seeded test database and runs
//! each analysis command to ensure they produce valid output without errors.

use data_carry_research::analysis::{AnalysisEngine, OutputFormat, ReportFormatter};
use data_carry_research::database::traits::{Stage2Operations, Stage3Operations};
use data_carry_research::database::Database;
use data_carry_research::types::burn_patterns::{BurnConfidence, BurnPattern, BurnPatternType};
use data_carry_research::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, OutputClassificationData,
    OutputClassificationDetails, ProtocolType, ProtocolVariant,
};

use crate::common::create_unique_test_db_path;

/// Create a fully populated test database for CLI smoke testing
fn create_populated_test_db() -> (Database, String) {
    let db_path = create_unique_test_db_path("cli_smoke");
    let mut db = Database::new_v2(&db_path).unwrap();

    // Insert stub blocks for various heights
    let conn = db.connection();
    for height in [280000, 290000, 300000, 780000] {
        conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (?)", [height])
            .unwrap();
    }

    // Create test transactions with different protocols and characteristics
    let test_cases = vec![
        (
            "stamps_tx_1",
            280000,
            ProtocolType::BitcoinStamps,
            Some(ProtocolVariant::StampsClassic),
            vec![BurnPattern {
                pattern_type: BurnPatternType::Stamps22Pattern,
                vout: 0,
                pubkey_index: 0,
                pattern_data: "022222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                confidence: BurnConfidence::High,
            }],
            true, // is_spendable
            "AllValidECPoints",
            1, // real_pubkey_count
            1, // burn_key_count
            1, // data_key_count
            Some("image/png".to_string()),
        ),
        (
            "counterparty_tx_1",
            290000,
            ProtocolType::Counterparty,
            Some(ProtocolVariant::CounterpartyTransfer),
            vec![],
            true,
            "ContainsRealPubkey",
            2,
            0,
            1,
            Some("application/octet-stream".to_string()),
        ),
        (
            "omni_tx_1",
            300000,
            ProtocolType::OmniLayer,
            Some(ProtocolVariant::OmniTransfer),
            vec![],
            true,
            "ContainsRealPubkey",
            1,
            0,
            2,
            Some("application/octet-stream".to_string()),
        ),
        (
            "stamps_tx_2",
            780000,
            ProtocolType::BitcoinStamps,
            Some(ProtocolVariant::StampsSRC20),
            vec![BurnPattern {
                pattern_type: BurnPatternType::Stamps33Pattern,
                vout: 0,
                pubkey_index: 0,
                pattern_data: "033333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
                confidence: BurnConfidence::High,
            }],
            false, // is_spendable
            "AllBurnKeys",
            0,
            2,
            1,
            Some("text/plain".to_string()),
        ),
        (
            "datastorage_tx_1",
            780000,
            ProtocolType::DataStorage,
            None,
            vec![],
            false,
            "AllDataKeys",
            0,
            0,
            3,
            Some("application/json".to_string()),
        ),
    ];

    for (
        txid,
        height,
        protocol,
        variant,
        burn_patterns,
        is_spendable,
        spendability_reason,
        real_count,
        burn_count,
        data_count,
        content_type,
    ) in test_cases
    {
        // Create P2MS output
        let p2ms_output =
            crate::common::fixtures::create_test_p2ms_output_with_height(txid, 0, "dummy", height);

        // CRITICAL Schema V2 seeding order:
        // 1. Insert into transaction_outputs (enables p2ms_outputs trigger)
        // 2. Insert into p2ms_outputs (enables burn_patterns FK)
        // 3. Insert enriched_transactions (can now insert burn_patterns)
        {
            let conn = db.connection();
            // Step 1: Insert into transaction_outputs
            conn.execute(
                "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, metadata_json, is_coinbase, is_spent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                [txid, "0", &height.to_string(), "1000", "dummy", "multisig", "100", "{}", "0"],
            )
            .unwrap();

            // Step 2: Insert into p2ms_outputs (trigger verifies transaction_outputs exists)
            conn.execute(
                "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                [txid, "0", "1", "3", "[]"],
            )
            .unwrap();
        }

        // Create enriched transaction
        let tx = EnrichedTransaction {
            txid: txid.to_string(),
            height,
            total_input_value: 100000,
            total_output_value: 98000,
            transaction_fee: 2000,
            fee_per_byte: 10.0,
            transaction_size_bytes: 200,
            fee_per_kb: 10000.0,
            total_p2ms_amount: 1000,
            data_storage_fee_rate: 20.0,
            p2ms_outputs_count: 1,
            input_count: 1,
            output_count: 2,
            is_coinbase: false,
            burn_patterns_detected: burn_patterns.clone(),
            outputs: vec![p2ms_output.clone()],
        };

        let inputs = vec![];
        let outputs = vec![p2ms_output];

        // Insert enriched transaction (includes burn patterns)
        db.insert_enriched_transactions_batch(&[(tx, inputs, outputs)])
            .unwrap();

        // Insert transaction classification
        let tx_classification = ClassificationResult::new(
            txid.to_string(),
            protocol.clone(),
            variant.clone(),
            ClassificationDetails {
                burn_patterns_detected: burn_patterns
                    .iter()
                    .map(|bp| bp.pattern_type.clone())
                    .collect(),
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: "Test classification".to_string(),
                additional_metadata: None,
                content_type: content_type.clone(),
            },
        );
        db.insert_classification_results_batch(&[tx_classification])
            .unwrap();

        // Insert output classification with spendability
        let output_data = OutputClassificationData::new(
            0,
            protocol.clone(),
            variant.clone(),
            OutputClassificationDetails {
                burn_patterns_detected: burn_patterns
                    .iter()
                    .map(|bp| bp.pattern_type.clone())
                    .collect(),
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: "Test classification".to_string(),
                additional_metadata: None,
                content_type: content_type.clone(),
                is_spendable,
                spendability_reason: spendability_reason.to_string(),
                real_pubkey_count: real_count,
                burn_key_count: burn_count,
                data_key_count: data_count,
            },
        );
        db.insert_output_classifications_batch(txid, &[output_data])
            .unwrap();
    }

    (db, db_path)
}

#[test]
fn test_cli_burn_patterns_analysis() {
    let (db, db_path) = create_populated_test_db();

    // Run burn patterns analysis
    let engine = AnalysisEngine::new(&db_path).unwrap();
    let analysis = engine.analyse_burn_patterns();

    // Verify analysis runs without error
    assert!(analysis.is_ok(), "Burn pattern analysis should not crash");
    let analysis = analysis.unwrap();

    // Test console output formatting (should work even with 0 patterns)
    let console_output = ReportFormatter::format_burn_patterns(&analysis, &OutputFormat::Console);
    assert!(
        console_output.is_ok(),
        "Console formatting should not crash"
    );

    // Test JSON output formatting
    let json_output = ReportFormatter::format_burn_patterns(&analysis, &OutputFormat::Json);
    assert!(json_output.is_ok(), "JSON formatting should not crash");
    let json_output = json_output.unwrap();
    assert!(
        json_output.contains("total_patterns"),
        "JSON output should be valid"
    );

    drop(db);
}

#[test]
fn test_cli_value_analysis() {
    let (db, db_path) = create_populated_test_db();

    let engine = AnalysisEngine::new(&db_path).unwrap();
    let analysis = engine.analyse_value();

    // Verify analysis runs without error
    assert!(analysis.is_ok(), "Value analysis should not crash");
    let analysis = analysis.unwrap();

    // Test console output
    let console_output = ReportFormatter::format_value_analysis(&analysis, &OutputFormat::Console);
    assert!(
        console_output.is_ok(),
        "Console formatting should not crash"
    );

    // Test JSON output
    let json_output = ReportFormatter::format_value_analysis(&analysis, &OutputFormat::Json);
    assert!(json_output.is_ok(), "JSON formatting should not crash");
    let json_output = json_output.unwrap();
    assert!(
        json_output.contains("total_btc_locked_in_p2ms"),
        "JSON output should be valid"
    );

    drop(db);
}

#[test]
fn test_cli_spendability_analysis() {
    let (db, db_path) = create_populated_test_db();

    let engine = AnalysisEngine::new(&db_path).unwrap();
    let analysis = engine.analyse_spendability().unwrap();

    // Verify results
    assert_eq!(
        analysis.overall.total_outputs,
        analysis.overall.spendable_count + analysis.overall.unspendable_count,
        "Total should equal spendable + unspendable"
    );
    assert!(
        analysis.overall.spendable_count > 0,
        "Should have spendable outputs"
    );
    assert!(
        analysis.overall.unspendable_count > 0,
        "Should have unspendable outputs"
    );

    // Test console output
    let console_output =
        ReportFormatter::format_spendability_report(&analysis, &OutputFormat::Console).unwrap();
    assert!(
        console_output.contains("Spendability"),
        "Console output should have header"
    );

    // Test JSON output
    let json_output =
        ReportFormatter::format_spendability_report(&analysis, &OutputFormat::Json).unwrap();
    assert!(
        json_output.contains("total_outputs"),
        "JSON output should be valid"
    );

    drop(db);
}

#[test]
fn test_cli_signatures_analysis() {
    let (db, db_path) = create_populated_test_db();

    let engine = AnalysisEngine::new(&db_path).unwrap();
    let analysis = engine.analyse_signatures();

    // Verify analysis runs without error
    assert!(analysis.is_ok(), "Signature analysis should not crash");
    let analysis = analysis.unwrap();

    // Test console output
    let console_output =
        ReportFormatter::format_signature_analysis(&analysis, &OutputFormat::Console);
    assert!(
        console_output.is_ok(),
        "Console formatting should not crash"
    );

    // Test JSON output
    let json_output = ReportFormatter::format_signature_analysis(&analysis, &OutputFormat::Json);
    assert!(json_output.is_ok(), "JSON formatting should not crash");
    let json_output = json_output.unwrap();
    assert!(
        json_output.contains("classification_methods"),
        "JSON output should be valid"
    );

    drop(db);
}

#[test]
fn test_cli_content_types_analysis() {
    let (db, _db_path) = create_populated_test_db();

    // Content types are part of classification analysis
    // We verify they are properly stored in classifications
    let conn = db.connection();
    let content_type_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transaction_classifications WHERE content_type IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert!(
        content_type_count > 0,
        "Should have content types in classifications"
    );

    // Verify specific content types exist
    let image_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transaction_classifications WHERE content_type LIKE 'image/%'",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert!(image_count > 0, "Should have image content types");

    drop(db);
}

#[test]
fn test_cli_stamps_signatures_analysis() {
    let (db, db_path) = create_populated_test_db();

    let engine = AnalysisEngine::new(&db_path).unwrap();
    let analysis = engine.analyse_stamps_signatures();

    // Verify analysis runs without error (may have 0 stamps, which is fine for smoke test)
    assert!(
        analysis.is_ok(),
        "Stamps signature analysis should not crash"
    );
    let analysis = analysis.unwrap();

    // Test console output
    let console_output =
        ReportFormatter::format_stamps_signatures(&analysis, &OutputFormat::Console);
    assert!(
        console_output.is_ok(),
        "Console formatting should not crash"
    );

    // Test JSON output
    let json_output = ReportFormatter::format_stamps_signatures(&analysis, &OutputFormat::Json);
    assert!(json_output.is_ok(), "JSON formatting should not crash");
    let json_output = json_output.unwrap();
    assert!(
        json_output.contains("total_stamps"),
        "JSON output should be valid"
    );

    drop(db);
}

#[test]
fn test_cli_full_report() {
    let (db, db_path) = create_populated_test_db();

    let engine = AnalysisEngine::new(&db_path).unwrap();
    let report = engine.generate_full_report();

    // Verify report generation runs without error
    assert!(report.is_ok(), "Full report generation should not crash");
    let report = report.unwrap();

    // Test console output
    let console_output = ReportFormatter::format_full_report(&report, &OutputFormat::Console);
    assert!(
        console_output.is_ok(),
        "Console formatting should not crash"
    );

    // Test JSON output
    let json_output = ReportFormatter::format_full_report(&report, &OutputFormat::Json);
    assert!(json_output.is_ok(), "JSON formatting should not crash");
    let json_output = json_output.unwrap();
    assert!(
        json_output.contains("burn_patterns"),
        "JSON output should be valid"
    );

    drop(db);
}

#[test]
fn test_cli_error_handling_nonexistent_db() {
    // Test that CLI commands handle missing database gracefully
    let result = AnalysisEngine::new("/nonexistent/path/to/database.db");
    assert!(
        result.is_err(),
        "Should fail gracefully for nonexistent database"
    );
}

#[test]
fn test_cli_error_handling_empty_db() {
    // Test that CLI commands handle empty database gracefully
    let db_path = create_unique_test_db_path("cli_empty");
    let _db = Database::new_v2(&db_path).unwrap();

    let engine = AnalysisEngine::new(&db_path).unwrap();

    // All analyses should succeed even with empty database
    let burn_analysis = engine.analyse_burn_patterns();
    assert!(
        burn_analysis.is_ok(),
        "Burn analysis should handle empty DB"
    );

    let value_analysis = engine.analyse_value();
    assert!(
        value_analysis.is_ok(),
        "Value analysis should handle empty DB"
    );

    let spendability_analysis = engine.analyse_spendability();
    assert!(
        spendability_analysis.is_ok(),
        "Spendability analysis should handle empty DB"
    );
}
