//! Unit tests for data size analysis functionality

use data_carry_research::analysis::DataSizeAnalyser;
use data_carry_research::database::Database;
use data_carry_research::errors::AppResult;

/// Helper to create test database with Schema V2
fn create_test_db() -> AppResult<Database> {
    Database::new_v2(":memory:")
}

/// Helper to seed test data with proper FK relationships
fn seed_test_data(db: &Database) -> AppResult<()> {
    let conn = db.connection();

    // Insert stub blocks
    conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])?;
    conn.execute("INSERT INTO blocks (height) VALUES (100001)", [])?;
    conn.execute("INSERT INTO blocks (height) VALUES (100002)", [])?;

    // Insert transaction outputs (P2MS, unspent)
    // BitcoinStamps - 2 outputs, 500 + 600 = 1100 bytes, spendable
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('stamps_tx1', 0, 100000, 1000, 'aabbcc', 'multisig', 0, 500, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('stamps_tx1', 1, 100000, 1000, 'ddeeff', 'multisig', 0, 600, '{}', 0)",
        [],
    )?;

    // Counterparty - 1 output, 800 bytes, unspendable
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('cp_tx1', 0, 100001, 1000, 'aabbcc', 'multisig', 0, 800, '{}', 0)",
        [],
    )?;

    // Omni - 2 outputs, 300 + 400 = 700 bytes, mixed spendability
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('omni_tx1', 0, 100002, 1000, 'aabbcc', 'multisig', 0, 300, '{}', 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('omni_tx1', 1, 100002, 1000, 'ddeeff', 'multisig', 0, 400, '{}', 0)",
        [],
    )?;

    // Insert into p2ms_outputs (Schema V2 requirement)
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('stamps_tx1', 0, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('stamps_tx1', 1, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('cp_tx1', 0, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('omni_tx1', 0, 1, 3, '[]')",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('omni_tx1', 1, 1, 3, '[]')",
        [],
    )?;

    // Insert enriched transactions (Schema V2 fields)
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('stamps_tx1', 100000, 2000, 1000, 1000, 1.0, 500, 2.0, 1000, 2.0, 2, 1, 2, 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('cp_tx1', 100001, 2000, 1000, 1000, 1.0, 500, 2.0, 1000, 2.0, 1, 1, 1, 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('omni_tx1', 100002, 2000, 1000, 1000, 1.0, 500, 2.0, 1000, 2.0, 2, 1, 2, 0)",
        [],
    )?;

    // Insert transaction classifications (parent - Schema V2 fields)
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('stamps_tx1', 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'image/png')",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('cp_tx1', 'Counterparty', NULL, 1, 'SignatureBased', 'application/octet-stream')",
        [],
    )?;
    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('omni_tx1', 'OmniLayer', NULL, 1, 'SignatureBased', 'text/plain')",
        [],
    )?;

    // Insert output classifications (child, with FK to transaction_outputs)
    // BitcoinStamps - both spendable
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('stamps_tx1', 0, 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'image/png', 1, NULL)",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('stamps_tx1', 1, 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'image/png', 1, NULL)",
        [],
    )?;

    // Counterparty - unspendable (invalid EC points)
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('cp_tx1', 0, 'Counterparty', NULL, 1, 'SignatureBased', 'application/octet-stream', 0, 'InvalidECPoints')",
        [],
    )?;

    // Omni - mixed (one spendable, one unspendable)
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('omni_tx1', 0, 'OmniLayer', NULL, 1, 'SignatureBased', 'text/plain', 1, NULL)",
        [],
    )?;
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('omni_tx1', 1, 'OmniLayer', NULL, 1, 'SignatureBased', 'text/plain', 0, 'InvalidECPoints')",
        [],
    )?;

    Ok(())
}

#[test]
fn test_analyse_protocol_data_sizes() -> AppResult<()> {
    let db = create_test_db()?;
    seed_test_data(&db)?;

    let report = DataSizeAnalyser::analyse_protocol_data_sizes(&db)?;

    // Verify overall totals
    assert_eq!(report.total_outputs, 5, "Should have 5 total outputs");
    assert_eq!(
        report.total_transactions, 3,
        "Should have 3 total transactions"
    );
    assert_eq!(
        report.total_bytes,
        500 + 600 + 800 + 300 + 400,
        "Total bytes should sum correctly"
    );

    // Verify protocol breakdown
    assert_eq!(report.protocols.len(), 3, "Should have 3 protocols");

    // Find BitcoinStamps entry
    let stamps = report
        .protocols
        .iter()
        .find(|p| p.protocol == "BitcoinStamps")
        .expect("Should have BitcoinStamps");
    assert_eq!(stamps.total_bytes, 1100, "BitcoinStamps total bytes");
    assert_eq!(stamps.output_count, 2, "BitcoinStamps output count");
    assert_eq!(
        stamps.transaction_count, 1,
        "BitcoinStamps transaction count"
    );
    assert_eq!(
        stamps.spendable_bytes, 1100,
        "All BitcoinStamps bytes are spendable"
    );
    assert_eq!(stamps.unspendable_bytes, 0);

    // Find Counterparty entry
    let cp = report
        .protocols
        .iter()
        .find(|p| p.protocol == "Counterparty")
        .expect("Should have Counterparty");
    assert_eq!(cp.total_bytes, 800, "Counterparty total bytes");
    assert_eq!(cp.output_count, 1, "Counterparty output count");
    assert_eq!(cp.spendable_bytes, 0);
    assert_eq!(
        cp.unspendable_bytes, 800,
        "All Counterparty bytes are unspendable"
    );

    // Find Omni entry
    let omni = report
        .protocols
        .iter()
        .find(|p| p.protocol == "OmniLayer")
        .expect("Should have OmniLayer");
    assert_eq!(omni.total_bytes, 700, "OmniLayer total bytes");
    assert_eq!(omni.output_count, 2, "OmniLayer output count");
    assert_eq!(omni.spendable_bytes, 300, "OmniLayer spendable bytes");
    assert_eq!(omni.unspendable_bytes, 400, "OmniLayer unspendable bytes");

    Ok(())
}

#[test]
fn test_analyse_spendability_data_sizes() -> AppResult<()> {
    let db = create_test_db()?;
    seed_test_data(&db)?;

    let report = DataSizeAnalyser::analyse_spendability_data_sizes(&db)?;

    // Verify overall metrics
    assert_eq!(
        report.overall.total_bytes,
        500 + 600 + 800 + 300 + 400,
        "Total bytes"
    );
    assert_eq!(report.overall.spendable_bytes, 1400, "Spendable bytes");
    assert_eq!(report.overall.unspendable_bytes, 1200, "Unspendable bytes");
    assert_eq!(
        report.overall.spendable_output_count, 3,
        "Spendable output count"
    );
    assert_eq!(
        report.overall.unspendable_output_count, 2,
        "Unspendable output count"
    );

    // Verify spendable percentage calculation
    let expected_percentage = (1400.0 / 2600.0) * 100.0;
    assert!(
        (report.overall.spendable_percentage - expected_percentage).abs() < 0.01,
        "Spendable percentage should be ~53.85%"
    );

    // Verify by protocol breakdown
    assert_eq!(report.by_protocol.len(), 3, "Should have 3 protocols");

    // Verify by reason (unspendable only)
    assert_eq!(
        report.by_reason.len(),
        1,
        "Should have 1 spendability reason"
    );
    let reason = &report.by_reason[0];
    assert_eq!(reason.reason, "InvalidECPoints");
    assert_eq!(reason.output_count, 2, "Two outputs with InvalidECPoints");
    assert_eq!(reason.total_bytes, 1200, "Total bytes for InvalidECPoints");

    Ok(())
}

#[test]
fn test_analyse_content_type_spendability() -> AppResult<()> {
    let db = create_test_db()?;
    seed_test_data(&db)?;

    let report = DataSizeAnalyser::analyse_content_type_spendability(&db)?;

    // Verify overall totals
    assert_eq!(report.total_bytes, 2600, "Total bytes");
    assert_eq!(report.total_transactions, 3, "Total transactions");

    // Verify categories
    assert_eq!(report.categories.len(), 3, "Should have 3 categories");

    // Find Images category (from image/png)
    let images = report
        .categories
        .iter()
        .find(|c| c.category == "Images")
        .expect("Should have Images category");
    assert_eq!(
        images.category_totals.transaction_count, 1,
        "Images category transaction count"
    );
    assert_eq!(
        images.category_totals.total_bytes, 1100,
        "Images total bytes"
    );
    assert_eq!(
        images.category_totals.spendable_bytes, 1100,
        "Images spendable bytes"
    );
    assert_eq!(images.category_totals.unspendable_bytes, 0);

    // Verify content types within Images category
    assert_eq!(
        images.content_types.len(),
        1,
        "Should have 1 content type in Images"
    );
    let png = &images.content_types[0];
    assert_eq!(png.mime_type, "image/png");
    assert_eq!(png.extension, ".png"); // Extensions include the dot
    assert_eq!(png.total_bytes, 1100);

    Ok(())
}

#[test]
fn test_analyse_comprehensive_data_sizes() -> AppResult<()> {
    let db = create_test_db()?;
    seed_test_data(&db)?;

    let report = DataSizeAnalyser::analyse_comprehensive_data_sizes(&db)?;

    // Verify overall summary
    assert_eq!(
        report.overall_summary.total_p2ms_bytes, 2600,
        "Overall total bytes"
    );
    assert_eq!(
        report.overall_summary.total_outputs, 5,
        "Overall total outputs"
    );
    assert_eq!(
        report.overall_summary.total_transactions, 3,
        "Overall total transactions"
    );

    // Verify protocol breakdown exists
    assert_eq!(
        report.protocol_breakdown.total_bytes, 2600,
        "Protocol breakdown total"
    );
    assert_eq!(
        report.protocol_breakdown.protocols.len(),
        3,
        "Protocol breakdown count"
    );

    // Verify spendability breakdown exists
    assert_eq!(
        report.spendability_breakdown.overall.total_bytes, 2600,
        "Spendability breakdown total"
    );

    // Verify content type breakdown exists
    assert_eq!(
        report.content_type_breakdown.total_bytes, 2600,
        "Content type breakdown total"
    );

    // Verify consistency: all totals should match
    assert_eq!(
        report.overall_summary.total_p2ms_bytes, report.protocol_breakdown.total_bytes,
        "Protocol totals should match overall"
    );
    assert_eq!(
        report.overall_summary.total_p2ms_bytes, report.spendability_breakdown.overall.total_bytes,
        "Spendability totals should match overall"
    );
    assert_eq!(
        report.overall_summary.total_p2ms_bytes, report.content_type_breakdown.total_bytes,
        "Content type totals should match overall"
    );

    Ok(())
}

#[test]
fn test_empty_database() -> AppResult<()> {
    let db = create_test_db()?;

    // Don't seed any data - test with empty database

    let protocol_report = DataSizeAnalyser::analyse_protocol_data_sizes(&db)?;
    assert_eq!(
        protocol_report.total_bytes, 0,
        "Empty DB should have 0 bytes"
    );
    assert_eq!(
        protocol_report.total_outputs, 0,
        "Empty DB should have 0 outputs"
    );
    assert_eq!(
        protocol_report.protocols.len(),
        0,
        "Empty DB should have no protocols"
    );

    let spendability_report = DataSizeAnalyser::analyse_spendability_data_sizes(&db)?;
    assert_eq!(
        spendability_report.overall.total_bytes, 0,
        "Empty DB spendability total"
    );

    let content_report = DataSizeAnalyser::analyse_content_type_spendability(&db)?;
    assert_eq!(content_report.total_bytes, 0, "Empty DB content type total");

    Ok(())
}

#[test]
fn test_null_content_types() -> AppResult<()> {
    let db = create_test_db()?;
    let conn = db.connection();

    // Seed minimal data with NULL content_type
    conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])?;

    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('unknown_tx1', 0, 100000, 1000, 'aabbcc', 'multisig', 0, 500, '{}', 0)",
        [],
    )?;

    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('unknown_tx1', 0, 1, 3, '[]')",
        [],
    )?;

    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('unknown_tx1', 100000, 2000, 1000, 1000, 1.0, 500, 2.0, 1000, 2.0, 1, 1, 1, 0)",
        [],
    )?;

    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('unknown_tx1', 'Unknown', NULL, 0, 'Fallback', NULL)",
        [],
    )?;

    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('unknown_tx1', 0, 'Unknown', NULL, 0, 'Fallback', NULL, 1, NULL)",
        [],
    )?;

    let report = DataSizeAnalyser::analyse_content_type_spendability(&db)?;

    // Should have "Unclassified" category for NULL content_type
    let unclassified = report
        .categories
        .iter()
        .find(|c| c.category == "Unclassified")
        .expect("Should have Unclassified category for NULL content_type");

    assert_eq!(unclassified.category_totals.total_bytes, 500);
    assert_eq!(unclassified.category_totals.transaction_count, 1);

    Ok(())
}

#[test]
fn test_spent_outputs_excluded() -> AppResult<()> {
    let db = create_test_db()?;
    let conn = db.connection();

    // Seed data with both spent and unspent outputs
    conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])?;

    // Unspent output (should be included)
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('test_tx1', 0, 100000, 1000, 'aabbcc', 'multisig', 0, 500, '{}', 0)",
        [],
    )?;

    // Spent output (should be excluded)
    conn.execute(
        "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type,
         is_coinbase, script_size, metadata_json, is_spent)
         VALUES ('test_tx1', 1, 100000, 1000, 'ddeeff', 'multisig', 0, 600, '{}', 1)",
        [],
    )?;

    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES ('test_tx1', 0, 1, 3, '[]')",
        [],
    )?;

    conn.execute(
        "INSERT INTO enriched_transactions (txid, height, total_input_value, total_output_value,
         transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
         data_storage_fee_rate, p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES ('test_tx1', 100000, 2000, 1000, 1000, 1.0, 500, 2.0, 1000, 2.0, 1, 1, 2, 0)",
        [],
    )?;

    conn.execute(
        "INSERT INTO transaction_classifications (txid, protocol, variant, protocol_signature_found,
         classification_method, content_type)
         VALUES ('test_tx1', 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'image/png')",
        [],
    )?;

    // Only classify the unspent output
    conn.execute(
        "INSERT INTO p2ms_output_classifications (txid, vout, protocol, variant, protocol_signature_found,
         classification_method, content_type, is_spendable, spendability_reason)
         VALUES ('test_tx1', 0, 'BitcoinStamps', 'StampsClassic', 1, 'SignatureBased', 'image/png', 1, NULL)",
        [],
    )?;

    let report = DataSizeAnalyser::analyse_protocol_data_sizes(&db)?;

    // Should only count the unspent output (500 bytes, not 1100)
    assert_eq!(report.total_bytes, 500, "Should only count unspent outputs");
    assert_eq!(report.total_outputs, 1, "Should only count unspent outputs");

    Ok(())
}
