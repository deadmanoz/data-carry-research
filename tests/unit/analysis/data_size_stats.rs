//! Unit tests for data size analysis functionality

use crate::common::analysis_test_setup::{
    create_analysis_test_db, insert_complete_p2ms_output, insert_test_enriched_transaction,
    insert_test_output, insert_test_output_classification, insert_test_p2ms_output,
    insert_test_tx_classification, seed_analysis_blocks, TestClassificationParams,
    TestOutputClassificationParams, TestOutputParams, TestP2msOutputParams,
};
use data_carry_research::analysis::{
    analyse_comprehensive_data_sizes, analyse_content_type_spendability,
    analyse_protocol_data_sizes, analyse_spendability_data_sizes,
};
use data_carry_research::database::Database;
use data_carry_research::errors::AppResult;
use data_carry_research::types::ProtocolType;

/// Helper to seed test data with proper FK relationships
fn seed_test_data(db: &Database) -> AppResult<()> {
    seed_analysis_blocks(db, &[100000, 100001, 100002])?;

    // BitcoinStamps - 2 outputs, 500 + 600 = 1100 bytes, spendable
    insert_test_output(
        db,
        &TestOutputParams::multisig("stamps_tx1", 0, 100000, 1000, 500),
    )?;
    insert_test_p2ms_output(db, &TestP2msOutputParams::standard("stamps_tx1", 0))?;
    insert_test_output(
        db,
        &TestOutputParams::multisig("stamps_tx1", 1, 100000, 1000, 600),
    )?;
    insert_test_p2ms_output(db, &TestP2msOutputParams::standard("stamps_tx1", 1))?;

    // Counterparty - 1 output, 800 bytes, unspendable
    insert_complete_p2ms_output(db, "cp_tx1", 0, 100001, 1000, 800)?;

    // Omni - 2 outputs, 300 + 400 = 700 bytes, mixed spendability
    insert_complete_p2ms_output(db, "omni_tx1", 0, 100002, 1000, 300)?;
    insert_complete_p2ms_output(db, "omni_tx1", 1, 100002, 1000, 400)?;

    // Insert enriched transactions
    insert_test_enriched_transaction(db, "stamps_tx1", 100000)?;
    insert_test_enriched_transaction(db, "cp_tx1", 100001)?;
    insert_test_enriched_transaction(db, "omni_tx1", 100002)?;

    // Transaction classifications
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("stamps_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("cp_tx1", "Counterparty")
            .with_content_type("application/octet-stream"),
    )?;
    insert_test_tx_classification(
        db,
        &TestClassificationParams::new("omni_tx1", "OmniLayer").with_content_type("text/plain"),
    )?;

    // Output classifications
    // BitcoinStamps - both spendable
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::spendable("stamps_tx1", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::spendable("stamps_tx1", 1, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    // Counterparty - unspendable
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::unspendable("cp_tx1", 0, "Counterparty")
            .with_content_type("application/octet-stream"),
    )?;

    // Omni - mixed (one spendable, one unspendable)
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::spendable("omni_tx1", 0, "OmniLayer")
            .with_content_type("text/plain"),
    )?;
    insert_test_output_classification(
        db,
        &TestOutputClassificationParams::unspendable("omni_tx1", 1, "OmniLayer")
            .with_content_type("text/plain"),
    )?;

    Ok(())
}

#[test]
fn test_analyse_protocol_data_sizes() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_test_data(&db)?;

    let report = analyse_protocol_data_sizes(&db)?;

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
        .find(|p| p.protocol == ProtocolType::BitcoinStamps)
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
        .find(|p| p.protocol == ProtocolType::Counterparty)
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
        .find(|p| p.protocol == ProtocolType::OmniLayer)
        .expect("Should have OmniLayer");
    assert_eq!(omni.total_bytes, 700, "OmniLayer total bytes");
    assert_eq!(omni.output_count, 2, "OmniLayer output count");
    assert_eq!(omni.spendable_bytes, 300, "OmniLayer spendable bytes");
    assert_eq!(omni.unspendable_bytes, 400, "OmniLayer unspendable bytes");

    Ok(())
}

#[test]
fn test_analyse_spendability_data_sizes() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_test_data(&db)?;

    let report = analyse_spendability_data_sizes(&db)?;

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
    assert_eq!(reason.reason, "AllDataKeys");
    assert_eq!(reason.output_count, 2, "Two outputs with AllDataKeys");
    assert_eq!(reason.total_bytes, 1200, "Total bytes for AllDataKeys");

    Ok(())
}

#[test]
fn test_analyse_content_type_spendability() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_test_data(&db)?;

    let report = analyse_content_type_spendability(&db)?;

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
    let db = create_analysis_test_db()?;
    seed_test_data(&db)?;

    let report = analyse_comprehensive_data_sizes(&db)?;

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
    let db = create_analysis_test_db()?;

    // Don't seed any data - test with empty database

    let protocol_report = analyse_protocol_data_sizes(&db)?;
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

    let spendability_report = analyse_spendability_data_sizes(&db)?;
    assert_eq!(
        spendability_report.overall.total_bytes, 0,
        "Empty DB spendability total"
    );

    let content_report = analyse_content_type_spendability(&db)?;
    assert_eq!(content_report.total_bytes, 0, "Empty DB content type total");

    Ok(())
}

#[test]
fn test_null_content_types() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Seed minimal data with NULL content_type (Unknown protocol with no content_type)
    insert_complete_p2ms_output(&db, "unknown_tx1", 0, 100000, 1000, 500)?;
    insert_test_enriched_transaction(&db, "unknown_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("unknown_tx1", "Unknown").without_content_type(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("unknown_tx1", 0, "Unknown")
            .without_content_type(),
    )?;

    let report = analyse_content_type_spendability(&db)?;

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
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Unspent output (should be included)
    insert_test_output(
        &db,
        &TestOutputParams::multisig("test_tx1", 0, 100000, 1000, 500),
    )?;
    insert_test_p2ms_output(&db, &TestP2msOutputParams::standard("test_tx1", 0))?;

    // Spent output (should be excluded)
    insert_test_output(
        &db,
        &TestOutputParams::multisig("test_tx1", 1, 100000, 1000, 600).spent(),
    )?;

    insert_test_enriched_transaction(&db, "test_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("test_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    // Only classify the unspent output
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("test_tx1", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    let report = analyse_protocol_data_sizes(&db)?;

    // Should only count the unspent output (500 bytes, not 1100)
    assert_eq!(report.total_bytes, 500, "Should only count unspent outputs");
    assert_eq!(report.total_outputs, 1, "Should only count unspent outputs");

    Ok(())
}
