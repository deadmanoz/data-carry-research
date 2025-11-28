//! Content Type Analysis Module
//!
//! Provides comprehensive analysis of MIME/content types across all classified P2MS outputs.
//! Properly distinguishes between:
//! - Data-carrying outputs (have content types)
//! - Valid None cases (LikelyDataStorage, LikelyLegitimateMultisig, StampsUnknown, OmniFailedDeobfuscation)
//! - Invalid None cases (protocols that SHOULD have content types but don't)
//!
//! CRITICAL: All queries filter by `is_spent = 0 AND script_type = 'multisig'` to ensure
//! statistics reflect only unspent P2MS outputs (the true UTXO set).

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    ContentTypeAnalysisReport, ContentTypeCategoryStats, ContentTypeProtocolStats,
    ContentTypeStats, ValidNoneStats,
};

/// Content type analyser for MIME type distribution insights
pub struct ContentTypeAnalyser;

impl ContentTypeAnalyser {
    /// Analyse content type distribution across all unspent P2MS outputs
    ///
    /// Returns comprehensive report including:
    /// - Overall content type presence statistics
    /// - Breakdown by specific MIME type
    /// - Category grouping (image/*, text/*, application/*)
    /// - Protocol-specific content type distributions
    /// - Valid None cases (architecturally correct)
    /// - Invalid None cases (missing content types that should exist)
    pub fn analyse_content_types(db: &Database) -> AppResult<ContentTypeAnalysisReport> {
        let conn = db.connection();

        // Total unspent P2MS outputs
        let total_outputs: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0 AND txo.script_type = 'multisig'",
            [],
            |row| row.get(0),
        )?;

        // Outputs WITH content types
        let outputs_with_content_type: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.content_type IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        // Outputs with NULL content_type
        let outputs_without_content_type: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.content_type IS NULL",
            [],
            |row| row.get(0),
        )?;

        let content_type_percentage = if total_outputs > 0 {
            (outputs_with_content_type as f64 * 100.0) / total_outputs as f64
        } else {
            0.0
        };

        // Get specific content type breakdown
        let content_type_breakdown = Self::get_content_type_breakdown(db)?;

        // Get MIME category grouping
        let category_breakdown = Self::get_category_breakdown(db)?;

        // Get protocol-specific content type stats
        let protocol_breakdown = Self::get_protocol_content_types(db)?;

        // Get valid None stats (architecturally correct)
        let valid_none_stats = Self::get_valid_none_stats(db)?;

        // Get invalid None stats (missing content types)
        let invalid_none_stats = Self::get_invalid_none_stats(db)?;

        Ok(ContentTypeAnalysisReport {
            total_outputs: total_outputs as usize,
            outputs_with_content_type: outputs_with_content_type as usize,
            outputs_without_content_type: outputs_without_content_type as usize,
            content_type_percentage,
            content_type_breakdown,
            category_breakdown,
            protocol_breakdown,
            valid_none_stats,
            invalid_none_stats,
        })
    }

    /// Get breakdown of specific MIME types
    fn get_content_type_breakdown(db: &Database) -> AppResult<Vec<ContentTypeStats>> {
        let conn = db.connection();

        let mut stmt = conn.prepare(
            "SELECT
                poc.content_type,
                COUNT(*) as count
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.content_type IS NOT NULL
             GROUP BY poc.content_type
             ORDER BY count DESC",
        )?;

        let total_with_content: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.content_type IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let breakdown = stmt
            .query_map([], |row| {
                let count: i64 = row.get(1)?;
                let percentage = if total_with_content > 0 {
                    (count as f64 * 100.0) / total_with_content as f64
                } else {
                    0.0
                };

                Ok(ContentTypeStats {
                    mime_type: row.get(0)?,
                    count: count as usize,
                    percentage,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(breakdown)
    }

    /// Get MIME category grouping (image/*, text/*, application/*)
    fn get_category_breakdown(db: &Database) -> AppResult<Vec<ContentTypeCategoryStats>> {
        let conn = db.connection();

        // Define MIME categories
        let categories = vec![
            ("image", "image/%"),
            ("text", "text/%"),
            ("application", "application/%"),
            ("video", "video/%"),
            ("audio", "audio/%"),
        ];

        let total_with_content: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.content_type IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let mut breakdown = Vec::new();

        for (category_name, pattern) in categories {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*)
                 FROM p2ms_output_classifications poc
                 JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                 WHERE txo.is_spent = 0
                   AND txo.script_type = 'multisig'
                   AND poc.content_type LIKE ?",
                [pattern],
                |row| row.get(0),
            )?;

            // Get specific types within this category
            let mut stmt = conn.prepare(
                "SELECT poc.content_type, COUNT(*) as count
                 FROM p2ms_output_classifications poc
                 JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                 WHERE txo.is_spent = 0
                   AND txo.script_type = 'multisig'
                   AND poc.content_type LIKE ?
                 GROUP BY poc.content_type
                 ORDER BY count DESC",
            )?;

            let mut specific_types: Vec<ContentTypeStats> = stmt
                .query_map([pattern], |row| {
                    Ok(ContentTypeStats {
                        mime_type: row.get(0)?,
                        count: row.get::<_, i64>(1)? as usize,
                        percentage: 0.0, // Calculated below
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            // Calculate percentages for specific types within this category
            // NOTE: Percentages are normalized to GLOBAL total (total_with_content), not category total.
            // This design choice allows direct cross-category comparison of MIME types.
            // E.g., "PNG: 12% of all outputs" vs "PNG: 27% of image category".
            for specific_type in &mut specific_types {
                specific_type.percentage = if total_with_content > 0 {
                    (specific_type.count as f64 * 100.0) / total_with_content as f64
                } else {
                    0.0
                };
            }

            let percentage = if total_with_content > 0 {
                (count as f64 * 100.0) / total_with_content as f64
            } else {
                0.0
            };

            breakdown.push(ContentTypeCategoryStats {
                category: category_name.to_string(),
                count: count as usize,
                percentage,
                specific_types,
            });
        }

        Ok(breakdown)
    }

    /// Get protocol-specific content type distributions
    fn get_protocol_content_types(db: &Database) -> AppResult<Vec<ContentTypeProtocolStats>> {
        let conn = db.connection();

        let protocols = vec![
            "BitcoinStamps",
            "Counterparty",
            "OmniLayer",
            "AsciiIdentifierProtocols",
            "Chancecoin",
            "PPk",
            "OpReturnSignalled",
            "DataStorage",
        ];

        let mut breakdown = Vec::new();

        for protocol in protocols {
            // Total outputs for this protocol
            let total_outputs: i64 = conn.query_row(
                "SELECT COUNT(*)
                 FROM p2ms_output_classifications poc
                 JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                 WHERE txo.is_spent = 0
                   AND txo.script_type = 'multisig'
                   AND poc.protocol = ?",
                [protocol],
                |row| row.get(0),
            )?;

            if total_outputs == 0 {
                continue; // Skip protocols with no outputs
            }

            // Outputs with content types
            let with_content_type: i64 = conn.query_row(
                "SELECT COUNT(*)
                 FROM p2ms_output_classifications poc
                 JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                 WHERE txo.is_spent = 0
                   AND txo.script_type = 'multisig'
                   AND poc.protocol = ?
                   AND poc.content_type IS NOT NULL",
                [protocol],
                |row| row.get(0),
            )?;

            // Outputs without content types
            let without_content_type: i64 = conn.query_row(
                "SELECT COUNT(*)
                 FROM p2ms_output_classifications poc
                 JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                 WHERE txo.is_spent = 0
                   AND txo.script_type = 'multisig'
                   AND poc.protocol = ?
                   AND poc.content_type IS NULL",
                [protocol],
                |row| row.get(0),
            )?;

            // Get specific content types for this protocol
            let mut stmt = conn.prepare(
                "SELECT poc.content_type, COUNT(*) as count
                 FROM p2ms_output_classifications poc
                 JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                 WHERE txo.is_spent = 0
                   AND txo.script_type = 'multisig'
                   AND poc.protocol = ?
                   AND poc.content_type IS NOT NULL
                 GROUP BY poc.content_type
                 ORDER BY count DESC",
            )?;

            let content_types = stmt
                .query_map([protocol], |row| {
                    let count: i64 = row.get(1)?;
                    let percentage = if total_outputs > 0 {
                        (count as f64 * 100.0) / total_outputs as f64
                    } else {
                        0.0
                    };

                    Ok(ContentTypeStats {
                        mime_type: row.get(0)?,
                        count: count as usize,
                        percentage,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let coverage_percentage = if total_outputs > 0 {
                (with_content_type as f64 * 100.0) / total_outputs as f64
            } else {
                0.0
            };

            breakdown.push(ContentTypeProtocolStats {
                protocol: protocol.to_string(),
                total_outputs: total_outputs as usize,
                with_content_type: with_content_type as usize,
                without_content_type: without_content_type as usize,
                coverage_percentage,
                content_types,
            });
        }

        Ok(breakdown)
    }

    /// Get statistics for valid None cases (architecturally correct)
    ///
    /// Protocols where content_type = NULL is expected:
    /// - LikelyDataStorage: Pattern detection only, decoder extracts content
    /// - LikelyLegitimateMultisig: Real multisig, not data-carrying
    /// - StampsUnknown: ARC4 decryption failed, no payload accessible
    /// - OmniFailedDeobfuscation: Deobfuscation failed, no payload accessible
    fn get_valid_none_stats(db: &Database) -> AppResult<ValidNoneStats> {
        let conn = db.connection();

        // LikelyDataStorage
        let likely_data_storage: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.protocol = 'LikelyDataStorage'
               AND poc.content_type IS NULL",
            [],
            |row| row.get(0),
        )?;

        // LikelyLegitimateMultisig
        let likely_legitimate: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.protocol = 'LikelyLegitimateMultisig'
               AND poc.content_type IS NULL",
            [],
            |row| row.get(0),
        )?;

        // StampsUnknown variant
        let stamps_unknown: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.protocol = 'BitcoinStamps'
               AND poc.variant = 'StampsUnknown'
               AND poc.content_type IS NULL",
            [],
            |row| row.get(0),
        )?;

        // OmniFailedDeobfuscation variant
        let omni_failed: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.protocol = 'OmniLayer'
               AND poc.variant = 'OmniFailedDeobfuscation'
               AND poc.content_type IS NULL",
            [],
            |row| row.get(0),
        )?;

        let total_valid_none =
            likely_data_storage + likely_legitimate + stamps_unknown + omni_failed;

        Ok(ValidNoneStats {
            total_valid_none: total_valid_none as usize,
            likely_data_storage: likely_data_storage as usize,
            likely_legitimate_multisig: likely_legitimate as usize,
            stamps_unknown: stamps_unknown as usize,
            omni_failed_deobfuscation: omni_failed as usize,
        })
    }

    /// Get statistics for invalid None cases (missing content types)
    ///
    /// These are outputs from data-carrying protocols that SHOULD have content types
    /// but don't (before the fix, this was 599,372 outputs).
    fn get_invalid_none_stats(db: &Database) -> AppResult<Vec<ContentTypeProtocolStats>> {
        let conn = db.connection();

        // Protocols that should ALWAYS have content types when protocol_signature_found=true
        let protocols = vec![
            "BitcoinStamps",            // Except StampsUnknown
            "Counterparty",             // Should always have content type
            "OmniLayer",                // Except FailedDeobfuscation
            "AsciiIdentifierProtocols", // Should have content type
            "Chancecoin",               // Should have content type
            "PPk",                      // Should have content type
            "OpReturnSignalled",        // Should have content type
            "DataStorage",              // Should have content type
        ];

        let mut breakdown = Vec::new();

        for protocol in protocols {
            let query = match protocol {
                "BitcoinStamps" => {
                    // Exclude StampsUnknown (valid None case)
                    // Only flag outputs with protocol_signature_found=true (exclude dust outputs)
                    "SELECT COUNT(*)
                     FROM p2ms_output_classifications poc
                     JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                     WHERE txo.is_spent = 0
                       AND txo.script_type = 'multisig'
                       AND poc.protocol = ?
                       AND poc.protocol_signature_found = 1
                       AND poc.variant != 'StampsUnknown'
                       AND poc.content_type IS NULL"
                }
                "OmniLayer" => {
                    // Exclude FailedDeobfuscation (valid None case)
                    // Only flag outputs with protocol_signature_found=true
                    "SELECT COUNT(*)
                     FROM p2ms_output_classifications poc
                     JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                     WHERE txo.is_spent = 0
                       AND txo.script_type = 'multisig'
                       AND poc.protocol = ?
                       AND poc.protocol_signature_found = 1
                       AND poc.variant != 'OmniFailedDeobfuscation'
                       AND poc.content_type IS NULL"
                }
                _ => {
                    // Only flag outputs with protocol_signature_found=true
                    // This excludes Counterparty dust outputs (protocol_signature_found=false)
                    "SELECT COUNT(*)
                     FROM p2ms_output_classifications poc
                     JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                     WHERE txo.is_spent = 0
                       AND txo.script_type = 'multisig'
                       AND poc.protocol = ?
                       AND poc.protocol_signature_found = 1
                       AND poc.content_type IS NULL"
                }
            };

            let invalid_count: i64 = conn.query_row(query, [protocol], |row| row.get(0))?;

            if invalid_count > 0 {
                let total_outputs: i64 = conn.query_row(
                    "SELECT COUNT(*)
                     FROM p2ms_output_classifications poc
                     JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                     WHERE txo.is_spent = 0
                       AND txo.script_type = 'multisig'
                       AND poc.protocol = ?",
                    [protocol],
                    |row| row.get(0),
                )?;

                breakdown.push(ContentTypeProtocolStats {
                    protocol: protocol.to_string(),
                    total_outputs: total_outputs as usize,
                    with_content_type: 0,
                    without_content_type: invalid_count as usize,
                    coverage_percentage: 0.0,
                    content_types: vec![],
                });
            }
        }

        Ok(breakdown)
    }

    /// Analyse content types for a specific protocol
    ///
    /// Useful for drilling down into specific protocol content type distributions.
    pub fn analyse_protocol_content_types(
        db: &Database,
        protocol: &str,
    ) -> AppResult<ContentTypeProtocolStats> {
        let conn = db.connection();

        let total_outputs: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.protocol = ?",
            [protocol],
            |row| row.get(0),
        )?;

        let with_content_type: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.protocol = ?
               AND poc.content_type IS NOT NULL",
            [protocol],
            |row| row.get(0),
        )?;

        let without_content_type: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.protocol = ?
               AND poc.content_type IS NULL",
            [protocol],
            |row| row.get(0),
        )?;

        let mut stmt = conn.prepare(
            "SELECT poc.content_type, COUNT(*) as count
             FROM p2ms_output_classifications poc
             JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
             WHERE txo.is_spent = 0
               AND txo.script_type = 'multisig'
               AND poc.protocol = ?
               AND poc.content_type IS NOT NULL
             GROUP BY poc.content_type
             ORDER BY count DESC",
        )?;

        let content_types = stmt
            .query_map([protocol], |row| {
                let count: i64 = row.get(1)?;
                let percentage = if total_outputs > 0 {
                    (count as f64 * 100.0) / total_outputs as f64
                } else {
                    0.0
                };

                Ok(ContentTypeStats {
                    mime_type: row.get(0)?,
                    count: count as usize,
                    percentage,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let coverage_percentage = if total_outputs > 0 {
            (with_content_type as f64 * 100.0) / total_outputs as f64
        } else {
            0.0
        };

        Ok(ContentTypeProtocolStats {
            protocol: protocol.to_string(),
            total_outputs: total_outputs as usize,
            with_content_type: with_content_type as usize,
            without_content_type: without_content_type as usize,
            coverage_percentage,
            content_types,
        })
    }

    /// Analyse content types for a specific MIME type
    ///
    /// Returns breakdown of which protocols use this MIME type.
    pub fn analyse_mime_type_usage(
        db: &Database,
        mime_type: &str,
    ) -> AppResult<Vec<ContentTypeProtocolStats>> {
        let conn = db.connection();

        let protocols = vec![
            "BitcoinStamps",
            "Counterparty",
            "OmniLayer",
            "AsciiIdentifierProtocols",
            "Chancecoin",
            "PPk",
            "OpReturnSignalled",
            "DataStorage",
        ];

        let mut breakdown = Vec::new();

        for protocol in protocols {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*)
                 FROM p2ms_output_classifications poc
                 JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                 WHERE txo.is_spent = 0
                   AND txo.script_type = 'multisig'
                   AND poc.protocol = ?
                   AND poc.content_type = ?",
                [protocol, mime_type],
                |row| row.get(0),
            )?;

            if count > 0 {
                let total_outputs: i64 = conn.query_row(
                    "SELECT COUNT(*)
                     FROM p2ms_output_classifications poc
                     JOIN transaction_outputs txo ON (poc.txid = txo.txid AND poc.vout = txo.vout)
                     WHERE txo.is_spent = 0
                       AND txo.script_type = 'multisig'
                       AND poc.protocol = ?",
                    [protocol],
                    |row| row.get(0),
                )?;

                let percentage = if total_outputs > 0 {
                    (count as f64 * 100.0) / total_outputs as f64
                } else {
                    0.0
                };

                breakdown.push(ContentTypeProtocolStats {
                    protocol: protocol.to_string(),
                    total_outputs: total_outputs as usize,
                    with_content_type: count as usize,
                    without_content_type: (total_outputs - count) as usize,
                    coverage_percentage: percentage,
                    content_types: vec![ContentTypeStats {
                        mime_type: mime_type.to_string(),
                        count: count as usize,
                        percentage,
                    }],
                });
            }
        }

        Ok(breakdown)
    }
}
