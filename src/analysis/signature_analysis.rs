//! Signature analysis functionality
//!
//! This module provides comprehensive analysis of protocol signature detection,
//! replacing the raw SQL queries from the justfile with structured analysis.

use crate::database::{Database, QueryHelper};
use crate::errors::AppResult;
use crate::types::analysis_results::{
    BurnPatternCorrelation, ConfidenceStats, SignatureAnalysisReport,
};
use crate::types::ProtocolType;
use std::str::FromStr;

/// Signature analyser for protocol detection insights
pub struct SignatureAnalyser;

impl SignatureAnalyser {
    /// Analyse signature detection comprehensively
    pub fn analyse_signatures(db: &Database) -> AppResult<SignatureAnalysisReport> {
        let conn = db.connection();

        // Get classification method distribution with automatic percentages
        let results = conn.query_grouped_percentages(
            "SELECT classification_method, COUNT(*) as count
             FROM transaction_classifications
             GROUP BY classification_method
             ORDER BY count DESC",
        )?;

        // Convert to MethodStats
        let classification_methods = results
            .into_iter()
            .map(
                |(method, count, percentage)| crate::types::analysis_results::MethodStats {
                    method,
                    count,
                    percentage,
                },
            )
            .collect();

        // Get burn pattern correlation
        let burn_pattern_analysis = Self::analyse_burn_pattern_correlation(db)?;

        // Get confidence analysis
        let confidence_analysis = Self::analyse_confidence_levels(db)?;

        Ok(SignatureAnalysisReport {
            classification_methods,
            burn_pattern_analysis,
            confidence_analysis,
        })
    }

    /// Analyse correlation between burn patterns and protocol classifications
    pub fn analyse_burn_pattern_correlation(db: &Database) -> AppResult<BurnPatternCorrelation> {
        let conn = db.connection();

        // Use query_collect for cleaner code
        let correlations = conn.query_collect(
            "WITH pattern_counts AS (
                 SELECT tc.txid, tc.protocol, COUNT(DISTINCT bp.pattern_type) as pattern_count
                 FROM transaction_classifications tc
                 INNER JOIN burn_patterns bp ON tc.txid = bp.txid
                 GROUP BY tc.txid, tc.protocol
             )
             SELECT protocol, pattern_count as burn_patterns_count, COUNT(*) as transactions
             FROM pattern_counts
             WHERE pattern_count > 0
             GROUP BY protocol, pattern_count
             ORDER BY protocol, pattern_count",
            |row| {
                let protocol_str: String = row.get(0)?;
                // Parse protocol string to enum (parse once at DB boundary)
                let protocol = ProtocolType::from_str(&protocol_str).unwrap_or_default();

                Ok(crate::types::analysis_results::PatternProtocolCorrelation {
                    protocol,
                    burn_patterns_count: row.get::<_, i64>(1)? as usize,
                    transactions: row.get::<_, i64>(2)? as usize,
                })
            },
        )?;

        Ok(BurnPatternCorrelation { correlations })
    }

    /// Analyse confidence levels in classifications
    pub fn analyse_confidence_levels(db: &Database) -> AppResult<ConfidenceStats> {
        let conn = db.connection();

        // Use signature detection as a proxy for confidence
        // High confidence = definitive signatures found
        // Medium confidence = heuristic detection
        // Low confidence = unknown or uncertain

        // Use count_rows for cleaner queries
        let high_confidence = conn.count_rows(
            "transaction_classifications",
            Some("protocol_signature_found = 1"),
        )?;

        let total_count = conn.count_rows("transaction_classifications", None)?;

        let low_confidence =
            conn.count_rows("transaction_classifications", Some("protocol = 'Unknown'"))?;

        let medium_confidence = total_count - high_confidence - low_confidence;

        Ok(ConfidenceStats {
            high_confidence: high_confidence as usize,
            medium_confidence: medium_confidence as usize,
            low_confidence: low_confidence as usize,
        })
    }
}
