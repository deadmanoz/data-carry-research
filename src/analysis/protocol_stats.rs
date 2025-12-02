//! Protocol classification statistics
//!
//! This module provides comprehensive analysis of protocol classifications.

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    ClassificationStatsReport, ProtocolBreakdown, SignatureDetectionStats,
};
use crate::types::ProtocolType;
use std::str::FromStr;

/// Analyse protocol classifications comprehensively
pub fn analyse_classifications(db: &Database) -> AppResult<ClassificationStatsReport> {
    let conn = db.connection();

    // Get total classifications
    let total_classified: i64 = conn.query_row(
        "SELECT COUNT(*) FROM transaction_classifications",
        [],
        |row| row.get(0),
    )?;

    // Get protocol breakdown
    let protocol_breakdown = get_protocol_breakdown(db)?;

    // Get signature detection stats
    let signature_detection_rates = get_signature_detection_stats(db)?;

    // Get sample classifications
    let mut stmt = conn.prepare(
            "SELECT protocol, COALESCE(variant, '') as variant, classification_method, COUNT(*) as count
             FROM transaction_classifications
             GROUP BY protocol, variant, classification_method
             ORDER BY count DESC
             LIMIT 10",
        )?;

    let sample_classifications = stmt
        .query_map([], |row| {
            let protocol_str: String = row.get(0)?;
            // Parse protocol string to enum (parse once at DB boundary)
            let protocol = ProtocolType::from_str(&protocol_str).unwrap_or_default();

            Ok(crate::types::analysis_results::ClassificationSample {
                protocol,
                variant: row.get(1)?,
                classification_method: row.get(2)?,
                count: row.get::<_, i64>(3)? as usize,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ClassificationStatsReport {
        total_classified: total_classified as usize,
        protocol_breakdown,
        signature_detection_rates,
        sample_classifications,
    })
}

/// Get protocol breakdown statistics
pub fn get_protocol_breakdown(db: &Database) -> AppResult<ProtocolBreakdown> {
    let conn = db.connection();

    // Get total count for percentage calculation
    let total_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM transaction_classifications",
        [],
        |row| row.get(0),
    )?;

    if total_count == 0 {
        return Ok(ProtocolBreakdown::default());
    }

    // Helper function to get protocol stats
    let get_protocol_stats =
        |protocol: &str| -> AppResult<crate::types::analysis_results::ProtocolStats> {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = ?",
                [protocol],
                |row| row.get(0),
            )?;

            let percentage = (count as f64 * 100.0) / total_count as f64;

            // Get variants for this protocol
            let mut stmt = conn.prepare(
                "SELECT COALESCE(variant, '') as variant, classification_method, COUNT(*) as count
                 FROM transaction_classifications
                 WHERE protocol = ?
                 GROUP BY variant, classification_method",
            )?;

            let variants = stmt
                .query_map([protocol], |row| {
                    Ok(crate::types::analysis_results::VariantStats {
                        variant: row.get(0)?,
                        classification_method: row.get(1)?,
                        count: row.get::<_, i64>(2)? as usize,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(crate::types::analysis_results::ProtocolStats {
                count: count as usize,
                percentage,
                variants,
            })
        };

    Ok(ProtocolBreakdown {
        bitcoin_stamps: get_protocol_stats("BitcoinStamps")?,
        counterparty: get_protocol_stats("Counterparty")?,
        ascii_identifier_protocols: get_protocol_stats("AsciiIdentifierProtocols")?,
        omni_layer: get_protocol_stats("OmniLayer")?,
        chancecoin: get_protocol_stats("Chancecoin")?,
        ppk: get_protocol_stats("PPk")?,
        opreturn_signalled: get_protocol_stats("OpReturnSignalled")?,
        data_storage: get_protocol_stats("DataStorage")?,
        likely_data_storage: get_protocol_stats("LikelyDataStorage")?,
        likely_legitimate: get_protocol_stats("LikelyLegitimateMultisig")?,
        unknown: get_protocol_stats("Unknown")?,
    })
}

/// Get signature detection statistics
pub fn get_signature_detection_stats(db: &Database) -> AppResult<SignatureDetectionStats> {
    let conn = db.connection();

    // Total classifications
    let total_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM transaction_classifications",
        [],
        |row| row.get(0),
    )?;

    // Definitive signatures count
    let definitive_signatures: i64 = conn.query_row(
        "SELECT COUNT(*) FROM transaction_classifications WHERE protocol_signature_found = 1",
        [],
        |row| row.get(0),
    )?;

    let signature_percentage = if total_count > 0 {
        (definitive_signatures as f64 * 100.0) / total_count as f64
    } else {
        0.0
    };

    // Get method breakdown
    let mut stmt = conn.prepare(
        "SELECT classification_method, COUNT(*) as count
             FROM transaction_classifications
             GROUP BY classification_method
             ORDER BY count DESC",
    )?;

    let method_breakdown = stmt
        .query_map([], |row| {
            let count: i64 = row.get(1)?;
            let percentage = if total_count > 0 {
                (count as f64 * 100.0) / total_count as f64
            } else {
                0.0
            };

            Ok(crate::types::analysis_results::MethodStats {
                method: row.get(0)?,
                count: count as usize,
                percentage,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(SignatureDetectionStats {
        definitive_signatures: definitive_signatures as usize,
        signature_percentage,
        method_breakdown,
    })
}
