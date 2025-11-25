//! Unit tests for content type consistency and propagation
//!
//! These tests verify that content types are correctly propagated from transaction-level
//! detection to output-level classifications, and that valid None cases are properly excluded
//! from error detection.

use data_carry_research::analysis::ContentTypeAnalyser;
use data_carry_research::database::Database;
use data_carry_research::errors::AppResult;

/// Helper to create test database with Schema V2
fn create_test_db() -> AppResult<Database> {
    Database::new_v2(":memory:")
}

/// Helper to seed blocks (required for FK constraints)
fn seed_blocks(db: &Database, heights: &[i64]) -> AppResult<()> {
    let conn = db.connection();
    for height in heights {
        conn.execute("INSERT INTO blocks (height) VALUES (?)", [height])?;
    }
    Ok(())
}

/// Helper to insert transaction output
#[allow(clippy::too_many_arguments)]
fn insert_output(
    db: &Database,
    txid: &str,
    vout: i64,
    height: i64,
    script_size: i64,
    is_spent: bool,
) -> AppResult<()> {
    let conn = db.connection();

    // Insert into transaction_outputs
    conn.execute(
        "INSERT INTO transaction_outputs
         (txid, vout, height, amount, script_hex, script_type, is_coinbase, script_size,
          metadata_json, is_spent)
         VALUES (?, ?, ?, 1000, 'aabbcc', 'multisig', 0, ?, '{}', ?)",
        rusqlite::params![txid, vout, height, script_size, is_spent as i64],
    )?;

    // Insert into p2ms_outputs (required for FK constraint)
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES (?, ?, 1, 3, '[]')",
        rusqlite::params![txid, vout],
    )?;

    Ok(())
}

/// Helper to insert classification with content type
#[allow(clippy::too_many_arguments)]
fn insert_classification(
    db: &Database,
    txid: &str,
    vout: i64,
    protocol: &str,
    variant: Option<&str>,
    content_type: Option<&str>,
    protocol_signature_found: bool,
) -> AppResult<()> {
    let conn = db.connection();

    // Insert enriched_transactions (required for FK from transaction_classifications)
    conn.execute(
        "INSERT OR IGNORE INTO enriched_transactions
         (txid, height, total_input_value, total_output_value, transaction_fee, fee_per_byte,
          transaction_size_bytes, fee_per_kb, total_p2ms_amount, data_storage_fee_rate,
          p2ms_outputs_count, input_count, output_count, is_coinbase)
         VALUES (?, 100000, 2000, 1000, 1000, 1.0, 500, 2.0, 1000, 2.0, 1, 1, 1, 0)",
        [txid],
    )?;

    // Insert parent classification
    conn.execute(
        "INSERT OR IGNORE INTO transaction_classifications
         (txid, protocol, variant, classification_method, protocol_signature_found, content_type)
         VALUES (?, ?, ?, 'SignatureBased', ?, ?)",
        rusqlite::params![
            txid,
            protocol,
            variant,
            protocol_signature_found as i64,
            content_type
        ],
    )?;

    // Insert output classification
    conn.execute(
        "INSERT INTO p2ms_output_classifications
         (txid, vout, protocol, variant, protocol_signature_found, classification_method,
          content_type, is_spendable, spendability_reason)
         VALUES (?, ?, ?, ?, ?, 'SignatureBased', ?, 1, NULL)",
        rusqlite::params![
            txid,
            vout,
            protocol,
            variant,
            protocol_signature_found as i64,
            content_type,
        ],
    )?;
    Ok(())
}

#[test]
fn test_counterparty_data_carrying_outputs_have_content_type() -> AppResult<()> {
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert Counterparty data-carrying output (protocol_signature_found = true)
    insert_output(&db, "cp_tx1", 0, 100000, 800, false)?;
    insert_classification(
        &db,
        "cp_tx1",
        0,
        "Counterparty",
        Some("Send"),
        Some("application/octet-stream"),
        true, // protocol_signature_found = true
    )?;

    // Verify content type is present
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;
    assert_eq!(report.outputs_with_content_type, 1);
    assert!(report
        .content_type_breakdown
        .iter()
        .any(|m| m.mime_type == "application/octet-stream" && m.count == 1));

    Ok(())
}

#[test]
fn test_counterparty_dust_outputs_excluded_from_invalid_none() -> AppResult<()> {
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert Counterparty dust output (protocol_signature_found = false)
    insert_output(&db, "cp_tx2", 1, 100000, 600, false)?;
    insert_classification(
        &db,
        "cp_tx2",
        1,
        "Counterparty",
        Some("Send"),
        None,  // Correctly NULL for dust outputs
        false, // protocol_signature_found = false
    )?;

    // Verify dust output is NOT counted as invalid None
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;

    // Check invalid None stats for Counterparty
    let cp_invalid = report
        .invalid_none_stats
        .iter()
        .find(|s| s.protocol == "Counterparty");

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
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert Omni output with successful deobfuscation
    insert_output(&db, "omni_tx1", 0, 100000, 300, false)?;
    insert_classification(
        &db,
        "omni_tx1",
        0,
        "OmniLayer",
        Some("SimpleSend"),
        Some("application/octet-stream"),
        true, // protocol_signature_found = true
    )?;

    // Verify content type is present
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;
    assert_eq!(report.outputs_with_content_type, 1);
    assert!(report
        .content_type_breakdown
        .iter()
        .any(|m| m.mime_type == "application/octet-stream" && m.count == 1));

    Ok(())
}

#[test]
fn test_omni_failed_deobfuscation_excluded_from_invalid_none() -> AppResult<()> {
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert Omni output with failed deobfuscation (valid None case)
    insert_output(&db, "omni_tx2", 0, 100000, 400, false)?;
    insert_classification(
        &db,
        "omni_tx2",
        0,
        "OmniLayer",
        Some("OmniFailedDeobfuscation"),
        None, // Correctly NULL for failed deobfuscation
        true, // Still has protocol signature
    )?;

    // Verify NOT counted as invalid None
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;

    let omni_invalid = report
        .invalid_none_stats
        .iter()
        .find(|s| s.protocol == "OmniLayer");

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
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert Bitcoin Stamps output with unknown variant (valid None case)
    insert_output(&db, "stamps_tx1", 0, 100000, 500, false)?;
    insert_classification(
        &db,
        "stamps_tx1",
        0,
        "BitcoinStamps",
        Some("StampsUnknown"),
        None, // Correctly NULL for unknown stamps
        true, // Has protocol signature
    )?;

    // Verify NOT counted as invalid None
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;

    let stamps_invalid = report
        .invalid_none_stats
        .iter()
        .find(|s| s.protocol == "BitcoinStamps");

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
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert LikelyDataStorage output (valid None case - pattern detection only)
    insert_output(&db, "lds_tx1", 0, 100000, 600, false)?;
    insert_classification(
        &db,
        "lds_tx1",
        0,
        "LikelyDataStorage",
        None,
        None, // Correctly NULL - Stage 4 decoder will extract content
        true, // Has pattern signature
    )?;

    // Verify it's in valid None cases
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;
    assert_eq!(report.valid_none_stats.likely_data_storage, 1);
    assert_eq!(report.valid_none_stats.total_valid_none, 1);

    Ok(())
}

#[test]
fn test_likely_legitimate_multisig_has_valid_none() -> AppResult<()> {
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert LikelyLegitimateMultisig output (valid None case - real multisig)
    insert_output(&db, "llm_tx1", 0, 100000, 400, false)?;
    insert_classification(
        &db,
        "llm_tx1",
        0,
        "LikelyLegitimateMultisig",
        None,
        None,  // Correctly NULL - not data-carrying
        false, // No protocol signature (not a data protocol)
    )?;

    // Verify it's in valid None cases
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;
    assert_eq!(report.valid_none_stats.likely_legitimate_multisig, 1);
    assert_eq!(report.valid_none_stats.total_valid_none, 1);

    Ok(())
}

#[test]
fn test_invalid_none_detection_only_flags_signature_found() -> AppResult<()> {
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert Counterparty output with protocol_signature_found=true but missing content_type
    // (This is a BUG that should be detected)
    insert_output(&db, "bug_tx1", 0, 100000, 800, false)?;
    insert_classification(
        &db,
        "bug_tx1",
        0,
        "Counterparty",
        Some("Send"),
        None, // BUG: Should have content_type but doesn't
        true, // protocol_signature_found = true
    )?;

    // Verify this IS flagged as invalid None
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;

    let cp_invalid = report
        .invalid_none_stats
        .iter()
        .find(|s| s.protocol == "Counterparty");

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
    let db = create_test_db()?;
    seed_blocks(&db, &[100000])?;

    // Insert SPENT output with content type
    insert_output(&db, "spent_tx1", 0, 100000, 500, true)?; // is_spent = true
    insert_classification(
        &db,
        "spent_tx1",
        0,
        "BitcoinStamps",
        Some("StampsClassic"),
        Some("image/png"),
        true,
    )?;

    // Insert UNSPENT output with content type
    insert_output(&db, "unspent_tx1", 0, 100000, 600, false)?; // is_spent = false
    insert_classification(
        &db,
        "unspent_tx1",
        0,
        "BitcoinStamps",
        Some("StampsClassic"),
        Some("image/png"),
        true,
    )?;

    // Verify only unspent output is counted
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;
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
    let db = create_test_db()?;
    seed_blocks(&db, &[100000, 100001])?;

    // Insert BitcoinStamps output
    insert_output(&db, "stamps_tx1", 0, 100000, 500, false)?;
    insert_classification(
        &db,
        "stamps_tx1",
        0,
        "BitcoinStamps",
        Some("StampsClassic"),
        Some("image/png"),
        true,
    )?;

    // Insert Counterparty output
    insert_output(&db, "cp_tx1", 0, 100001, 800, false)?;
    insert_classification(
        &db,
        "cp_tx1",
        0,
        "Counterparty",
        Some("Send"),
        Some("application/octet-stream"),
        true,
    )?;

    // Analyse
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;

    // Verify protocol breakdown exists
    assert!(
        report.protocol_breakdown.len() >= 2,
        "Should have at least 2 protocols"
    );

    // Verify BitcoinStamps
    let stamps_stats = report
        .protocol_breakdown
        .iter()
        .find(|p| p.protocol == "BitcoinStamps");
    assert!(stamps_stats.is_some(), "Should have BitcoinStamps stats");
    if let Some(stats) = stamps_stats {
        assert_eq!(stats.with_content_type, 1);
        assert_eq!(stats.coverage_percentage, 100.0);
    }

    // Verify Counterparty
    let cp_stats = report
        .protocol_breakdown
        .iter()
        .find(|p| p.protocol == "Counterparty");
    assert!(cp_stats.is_some(), "Should have Counterparty stats");
    if let Some(stats) = cp_stats {
        assert_eq!(stats.with_content_type, 1);
        assert_eq!(stats.coverage_percentage, 100.0);
    }

    Ok(())
}

#[test]
fn test_category_breakdown_groups_mime_types() -> AppResult<()> {
    let db = create_test_db()?;
    seed_blocks(&db, &[100000, 100001])?;

    // Insert 2 image outputs with different MIME types
    insert_output(&db, "png_tx1", 0, 100000, 500, false)?;
    insert_classification(
        &db,
        "png_tx1",
        0,
        "BitcoinStamps",
        Some("StampsClassic"),
        Some("image/png"),
        true,
    )?;

    insert_output(&db, "gif_tx1", 0, 100001, 600, false)?;
    insert_classification(
        &db,
        "gif_tx1",
        0,
        "BitcoinStamps",
        Some("StampsClassic"),
        Some("image/gif"),
        true,
    )?;

    // Analyse
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;

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
    let db = create_test_db()?;
    seed_blocks(&db, &[100000, 100001, 100002, 100003, 100004])?;

    // Scenario: Mix of valid and invalid outputs
    // 1. BitcoinStamps with content type (VALID)
    insert_output(&db, "stamps_tx1", 0, 100000, 500, false)?;
    insert_classification(
        &db,
        "stamps_tx1",
        0,
        "BitcoinStamps",
        Some("StampsClassic"),
        Some("image/png"),
        true,
    )?;

    // 2. StampsUnknown without content type (VALID None)
    insert_output(&db, "stamps_tx2", 0, 100001, 600, false)?;
    insert_classification(
        &db,
        "stamps_tx2",
        0,
        "BitcoinStamps",
        Some("StampsUnknown"),
        None,
        true,
    )?;

    // 3. Counterparty data-carrying with content type (VALID)
    insert_output(&db, "cp_tx1", 0, 100002, 800, false)?;
    insert_classification(
        &db,
        "cp_tx1",
        0,
        "Counterparty",
        Some("Send"),
        Some("application/octet-stream"),
        true,
    )?;

    // 4. Counterparty dust without content type (VALID - protocol_signature_found=false)
    insert_output(&db, "cp_tx2", 1, 100002, 600, false)?;
    insert_classification(&db, "cp_tx2", 1, "Counterparty", Some("Send"), None, false)?;

    // 5. LikelyDataStorage without content type (VALID None)
    insert_output(&db, "lds_tx1", 0, 100003, 700, false)?;
    insert_classification(&db, "lds_tx1", 0, "LikelyDataStorage", None, None, true)?;

    // 6. LikelyLegitimateMultisig without content type (VALID None)
    insert_output(&db, "llm_tx1", 0, 100004, 400, false)?;
    insert_classification(
        &db,
        "llm_tx1",
        0,
        "LikelyLegitimateMultisig",
        None,
        None,
        false,
    )?;

    // Analyse
    let report = ContentTypeAnalyser::analyse_content_types(&db)?;

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
