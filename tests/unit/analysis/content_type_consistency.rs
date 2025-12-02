//! Unit tests for content type consistency and propagation
//!
//! These tests verify that content types are correctly propagated from transaction-level
//! detection to output-level classifications, and that valid None cases are properly excluded
//! from error detection.

use crate::common::analysis_test_setup::{
    create_analysis_test_db, insert_complete_p2ms_output, insert_test_enriched_transaction,
    insert_test_output, insert_test_output_classification, insert_test_tx_classification,
    seed_analysis_blocks, TestClassificationParams, TestOutputClassificationParams,
    TestOutputParams,
};
use data_carry_research::analysis::analyse_content_types;
use data_carry_research::errors::AppResult;
use data_carry_research::types::ProtocolType;

#[test]
fn test_counterparty_data_carrying_outputs_have_content_type() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert Counterparty data-carrying output (protocol_signature_found = true)
    insert_complete_p2ms_output(&db, "cp_tx1", 0, 100000, 1000, 800)?;
    insert_test_enriched_transaction(&db, "cp_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("cp_tx1", "Counterparty")
            .with_variant("Send")
            .with_content_type("application/octet-stream"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("cp_tx1", 0, "Counterparty")
            .with_variant("Send")
            .with_content_type("application/octet-stream"),
    )?;

    // Verify content type is present
    let report = analyse_content_types(&db)?;
    assert_eq!(report.outputs_with_content_type, 1);
    assert!(report
        .content_type_breakdown
        .iter()
        .any(|m| m.mime_type == "application/octet-stream" && m.count == 1));

    Ok(())
}

#[test]
fn test_counterparty_dust_outputs_excluded_from_invalid_none() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert Counterparty dust output (protocol_signature_found = false)
    insert_complete_p2ms_output(&db, "cp_tx2", 1, 100000, 1000, 600)?;
    insert_test_enriched_transaction(&db, "cp_tx2", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("cp_tx2", "Counterparty")
            .with_variant("Send")
            .without_content_type()
            .without_protocol_signature(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("cp_tx2", 1, "Counterparty")
            .with_variant("Send")
            .without_content_type()
            .without_protocol_signature(),
    )?;

    // Verify dust output is NOT counted as invalid None
    let report = analyse_content_types(&db)?;

    // Check invalid None stats for Counterparty
    let cp_invalid = report
        .invalid_none_stats
        .iter()
        .find(|s| s.protocol == ProtocolType::Counterparty);

    if let Some(stats) = cp_invalid {
        assert_eq!(
            stats.without_content_type, 0,
            "Counterparty dust outputs should not be flagged as invalid None"
        );
    }

    Ok(())
}

#[test]
fn test_omni_successful_deobfuscation_has_content_type() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert Omni output with successful deobfuscation
    insert_complete_p2ms_output(&db, "omni_tx1", 0, 100000, 1000, 300)?;
    insert_test_enriched_transaction(&db, "omni_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("omni_tx1", "OmniLayer")
            .with_variant("SimpleSend")
            .with_content_type("application/octet-stream"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("omni_tx1", 0, "OmniLayer")
            .with_variant("SimpleSend")
            .with_content_type("application/octet-stream"),
    )?;

    // Verify content type is present
    let report = analyse_content_types(&db)?;
    assert_eq!(report.outputs_with_content_type, 1);
    assert!(report
        .content_type_breakdown
        .iter()
        .any(|m| m.mime_type == "application/octet-stream" && m.count == 1));

    Ok(())
}

#[test]
fn test_omni_failed_deobfuscation_excluded_from_invalid_none() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert Omni output with failed deobfuscation (valid None case)
    insert_complete_p2ms_output(&db, "omni_tx2", 0, 100000, 1000, 400)?;
    insert_test_enriched_transaction(&db, "omni_tx2", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("omni_tx2", "OmniLayer")
            .with_variant("OmniFailedDeobfuscation")
            .without_content_type(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("omni_tx2", 0, "OmniLayer")
            .with_variant("OmniFailedDeobfuscation")
            .without_content_type(),
    )?;

    // Verify NOT counted as invalid None
    let report = analyse_content_types(&db)?;

    let omni_invalid = report
        .invalid_none_stats
        .iter()
        .find(|s| s.protocol == ProtocolType::OmniLayer);

    if let Some(stats) = omni_invalid {
        assert_eq!(
            stats.without_content_type, 0,
            "OmniFailedDeobfuscation should not be flagged as invalid None"
        );
    }

    Ok(())
}

#[test]
fn test_stamps_unknown_excluded_from_invalid_none() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert Bitcoin Stamps output with unknown variant (valid None case)
    insert_complete_p2ms_output(&db, "stamps_tx1", 0, 100000, 1000, 500)?;
    insert_test_enriched_transaction(&db, "stamps_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("stamps_tx1", "BitcoinStamps")
            .with_variant("StampsUnknown")
            .without_content_type(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("stamps_tx1", 0, "BitcoinStamps")
            .with_variant("StampsUnknown")
            .without_content_type(),
    )?;

    // Verify NOT counted as invalid None
    let report = analyse_content_types(&db)?;

    let stamps_invalid = report
        .invalid_none_stats
        .iter()
        .find(|s| s.protocol == ProtocolType::BitcoinStamps);

    if let Some(stats) = stamps_invalid {
        assert_eq!(
            stats.without_content_type, 0,
            "StampsUnknown should not be flagged as invalid None"
        );
    }

    Ok(())
}

#[test]
fn test_likely_data_storage_has_valid_none() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert LikelyDataStorage output (valid None case - pattern detection only)
    insert_complete_p2ms_output(&db, "lds_tx1", 0, 100000, 1000, 600)?;
    insert_test_enriched_transaction(&db, "lds_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("lds_tx1", "LikelyDataStorage").without_content_type(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("lds_tx1", 0, "LikelyDataStorage")
            .without_content_type(),
    )?;

    // Verify it's in valid None cases
    let report = analyse_content_types(&db)?;
    assert_eq!(report.valid_none_stats.likely_data_storage, 1);
    assert_eq!(report.valid_none_stats.total_valid_none, 1);

    Ok(())
}

#[test]
fn test_likely_legitimate_multisig_has_valid_none() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert LikelyLegitimateMultisig output (valid None case - real multisig)
    insert_complete_p2ms_output(&db, "llm_tx1", 0, 100000, 1000, 400)?;
    insert_test_enriched_transaction(&db, "llm_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("llm_tx1", "LikelyLegitimateMultisig")
            .without_content_type()
            .without_protocol_signature(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("llm_tx1", 0, "LikelyLegitimateMultisig")
            .without_content_type()
            .without_protocol_signature(),
    )?;

    // Verify it's in valid None cases
    let report = analyse_content_types(&db)?;
    assert_eq!(report.valid_none_stats.likely_legitimate_multisig, 1);
    assert_eq!(report.valid_none_stats.total_valid_none, 1);

    Ok(())
}

#[test]
fn test_invalid_none_detection_only_flags_signature_found() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert Counterparty output with protocol_signature_found=true but missing content_type
    // (This is a BUG that should be detected)
    insert_complete_p2ms_output(&db, "bug_tx1", 0, 100000, 1000, 800)?;
    insert_test_enriched_transaction(&db, "bug_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("bug_tx1", "Counterparty")
            .with_variant("Send")
            .without_content_type(), // BUG: Should have content_type but doesn't
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("bug_tx1", 0, "Counterparty")
            .with_variant("Send")
            .without_content_type(), // protocol_signature_found = true by default
    )?;

    // Verify this IS flagged as invalid None
    let report = analyse_content_types(&db)?;

    let cp_invalid = report
        .invalid_none_stats
        .iter()
        .find(|s| s.protocol == ProtocolType::Counterparty);

    assert!(
        cp_invalid.is_some(),
        "Missing content_type should be detected"
    );
    if let Some(stats) = cp_invalid {
        assert_eq!(
            stats.without_content_type, 1,
            "Should detect 1 invalid None"
        );
    }

    Ok(())
}

#[test]
fn test_is_spent_filter_excludes_spent_outputs() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000])?;

    // Insert SPENT output with content type
    insert_test_output(
        &db,
        &TestOutputParams::multisig("spent_tx1", 0, 100000, 1000, 500).spent(),
    )?;
    insert_test_enriched_transaction(&db, "spent_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("spent_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    // Note: spent outputs typically don't have p2ms_outputs or classifications in real data,
    // but we insert them here to test the is_spent filter

    // Insert UNSPENT output with content type
    insert_complete_p2ms_output(&db, "unspent_tx1", 0, 100000, 1000, 600)?;
    insert_test_enriched_transaction(&db, "unspent_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("unspent_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("unspent_tx1", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    // Verify only unspent output is counted
    let report = analyse_content_types(&db)?;
    assert_eq!(
        report.outputs_with_content_type, 1,
        "Should only count unspent outputs"
    );
    assert_eq!(
        report.total_outputs, 1,
        "Should only count unspent outputs in total"
    );

    Ok(())
}

#[test]
fn test_protocol_breakdown_structure() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000, 100001])?;

    // Insert BitcoinStamps output
    insert_complete_p2ms_output(&db, "stamps_tx1", 0, 100000, 1000, 500)?;
    insert_test_enriched_transaction(&db, "stamps_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("stamps_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("stamps_tx1", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    // Insert Counterparty output
    insert_complete_p2ms_output(&db, "cp_tx1", 0, 100001, 1000, 800)?;
    insert_test_enriched_transaction(&db, "cp_tx1", 100001)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("cp_tx1", "Counterparty")
            .with_variant("Send")
            .with_content_type("application/octet-stream"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("cp_tx1", 0, "Counterparty")
            .with_variant("Send")
            .with_content_type("application/octet-stream"),
    )?;

    // Analyse
    let report = analyse_content_types(&db)?;

    // Verify protocol breakdown exists
    assert!(
        report.protocol_breakdown.len() >= 2,
        "Should have at least 2 protocols"
    );

    // Verify BitcoinStamps
    let stamps_stats = report
        .protocol_breakdown
        .iter()
        .find(|p| p.protocol == ProtocolType::BitcoinStamps);
    assert!(stamps_stats.is_some(), "Should have BitcoinStamps stats");
    if let Some(stats) = stamps_stats {
        assert_eq!(stats.with_content_type, 1);
        assert_eq!(stats.coverage_percentage, 100.0);
    }

    // Verify Counterparty
    let cp_stats = report
        .protocol_breakdown
        .iter()
        .find(|p| p.protocol == ProtocolType::Counterparty);
    assert!(cp_stats.is_some(), "Should have Counterparty stats");
    if let Some(stats) = cp_stats {
        assert_eq!(stats.with_content_type, 1);
        assert_eq!(stats.coverage_percentage, 100.0);
    }

    Ok(())
}

#[test]
fn test_category_breakdown_groups_mime_types() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000, 100001])?;

    // Insert 2 image outputs with different MIME types
    insert_complete_p2ms_output(&db, "png_tx1", 0, 100000, 1000, 500)?;
    insert_test_enriched_transaction(&db, "png_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("png_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("png_tx1", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    insert_complete_p2ms_output(&db, "gif_tx1", 0, 100001, 1000, 600)?;
    insert_test_enriched_transaction(&db, "gif_tx1", 100001)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("gif_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/gif"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("gif_tx1", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/gif"),
    )?;

    // Analyse
    let report = analyse_content_types(&db)?;

    // Find image category
    let image_cat = report
        .category_breakdown
        .iter()
        .find(|c| c.category == "image");

    assert!(image_cat.is_some(), "Should have image category");
    if let Some(cat) = image_cat {
        assert_eq!(cat.count, 2, "Should have 2 image outputs");
        assert_eq!(cat.percentage, 100.0); // 2 out of 2 total

        // Check specific types exist
        assert!(
            cat.specific_types
                .iter()
                .any(|t| t.mime_type == "image/png"),
            "Should have PNG type"
        );
        assert!(
            cat.specific_types
                .iter()
                .any(|t| t.mime_type == "image/gif"),
            "Should have GIF type"
        );
    }

    Ok(())
}

#[test]
fn test_comprehensive_content_type_coverage() -> AppResult<()> {
    let db = create_analysis_test_db()?;
    seed_analysis_blocks(&db, &[100000, 100001, 100002, 100003, 100004])?;

    // Scenario: Mix of valid and invalid outputs
    // 1. BitcoinStamps with content type (VALID)
    insert_complete_p2ms_output(&db, "stamps_tx1", 0, 100000, 1000, 500)?;
    insert_test_enriched_transaction(&db, "stamps_tx1", 100000)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("stamps_tx1", "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("stamps_tx1", 0, "BitcoinStamps")
            .with_variant("StampsClassic")
            .with_content_type("image/png"),
    )?;

    // 2. StampsUnknown without content type (VALID None)
    insert_complete_p2ms_output(&db, "stamps_tx2", 0, 100001, 1000, 600)?;
    insert_test_enriched_transaction(&db, "stamps_tx2", 100001)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("stamps_tx2", "BitcoinStamps")
            .with_variant("StampsUnknown")
            .without_content_type(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("stamps_tx2", 0, "BitcoinStamps")
            .with_variant("StampsUnknown")
            .without_content_type(),
    )?;

    // 3. Counterparty data-carrying with content type (VALID)
    insert_complete_p2ms_output(&db, "cp_tx1", 0, 100002, 1000, 800)?;
    insert_test_enriched_transaction(&db, "cp_tx1", 100002)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("cp_tx1", "Counterparty")
            .with_variant("Send")
            .with_content_type("application/octet-stream"),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("cp_tx1", 0, "Counterparty")
            .with_variant("Send")
            .with_content_type("application/octet-stream"),
    )?;

    // 4. Counterparty dust without content type (VALID - protocol_signature_found=false)
    insert_complete_p2ms_output(&db, "cp_tx2", 1, 100002, 1000, 600)?;
    insert_test_enriched_transaction(&db, "cp_tx2", 100002)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("cp_tx2", "Counterparty")
            .with_variant("Send")
            .without_content_type()
            .without_protocol_signature(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("cp_tx2", 1, "Counterparty")
            .with_variant("Send")
            .without_content_type()
            .without_protocol_signature(),
    )?;

    // 5. LikelyDataStorage without content type (VALID None)
    insert_complete_p2ms_output(&db, "lds_tx1", 0, 100003, 1000, 700)?;
    insert_test_enriched_transaction(&db, "lds_tx1", 100003)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("lds_tx1", "LikelyDataStorage").without_content_type(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("lds_tx1", 0, "LikelyDataStorage")
            .without_content_type(),
    )?;

    // 6. LikelyLegitimateMultisig without content type (VALID None)
    insert_complete_p2ms_output(&db, "llm_tx1", 0, 100004, 1000, 400)?;
    insert_test_enriched_transaction(&db, "llm_tx1", 100004)?;
    insert_test_tx_classification(
        &db,
        &TestClassificationParams::new("llm_tx1", "LikelyLegitimateMultisig")
            .without_content_type()
            .without_protocol_signature(),
    )?;
    insert_test_output_classification(
        &db,
        &TestOutputClassificationParams::spendable("llm_tx1", 0, "LikelyLegitimateMultisig")
            .without_content_type()
            .without_protocol_signature(),
    )?;

    // Analyse
    let report = analyse_content_types(&db)?;

    // Verify totals
    assert_eq!(report.total_outputs, 6, "Should have 6 total outputs");
    assert_eq!(
        report.outputs_with_content_type, 2,
        "Should have 2 with content types (stamps_tx1, cp_tx1)"
    );

    // Verify valid None cases
    assert_eq!(
        report.valid_none_stats.stamps_unknown, 1,
        "Should have 1 StampsUnknown"
    );
    assert_eq!(
        report.valid_none_stats.likely_data_storage, 1,
        "Should have 1 LikelyDataStorage"
    );
    assert_eq!(
        report.valid_none_stats.likely_legitimate_multisig, 1,
        "Should have 1 LikelyLegitimateMultisig"
    );
    assert_eq!(
        report.valid_none_stats.total_valid_none, 3,
        "Should have 3 total valid None cases"
    );

    // Verify NO invalid None cases (dust output correctly excluded)
    for protocol_stats in &report.invalid_none_stats {
        assert_eq!(
            protocol_stats.without_content_type, 0,
            "Protocol {} should have no invalid None cases",
            protocol_stats.protocol
        );
    }

    Ok(())
}
