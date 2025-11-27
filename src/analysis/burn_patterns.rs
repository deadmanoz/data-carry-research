//! Burn pattern analysis functionality
//!
//! This module provides comprehensive analysis of burn patterns detected in P2MS transactions.

use crate::types::analysis_results::{BurnPatternAnalysis, BurnPatternSample, PatternTypeStats};
use crate::database::{Database, QueryHelper};
use crate::errors::AppResult;

/// Burn pattern analyser for comprehensive pattern insights
pub struct BurnPatternAnalyser;

impl BurnPatternAnalyser {
    /// Analyse all burn patterns in the database
    pub fn analyse_patterns(db: &Database) -> AppResult<BurnPatternAnalysis> {
        // Get pattern type breakdown with counts and percentages
        let pattern_breakdown = Self::get_pattern_breakdown(db)?;

        // Calculate total patterns from breakdown
        let total_patterns = pattern_breakdown.iter().map(|p| p.count).sum();

        // Get sample patterns for examination
        let sample_patterns = Self::get_sample_patterns(db, 5)?;

        Ok(BurnPatternAnalysis {
            total_patterns,
            pattern_breakdown,
            sample_patterns,
        })
    }

    /// Get detailed breakdown of pattern types with statistics
    pub fn get_pattern_breakdown(db: &Database) -> AppResult<Vec<PatternTypeStats>> {
        let conn = db.connection();

        // Query pattern type breakdown with automatic percentage calculation
        let results = conn.query_grouped_percentages(
            "SELECT pattern_type, COUNT(*) as count
             FROM burn_patterns
             GROUP BY pattern_type
             ORDER BY count DESC",
        )?;

        // Convert to PatternTypeStats
        let patterns = results
            .into_iter()
            .map(|(pattern_type, count, percentage)| PatternTypeStats {
                pattern_type,
                count,
                percentage,
            })
            .collect();

        Ok(patterns)
    }

    /// Get sample burn patterns for examination
    pub fn get_sample_patterns(db: &Database, limit: usize) -> AppResult<Vec<BurnPatternSample>> {
        let conn = db.connection();

        // Note: query_collect doesn't support parameters yet, so we use string formatting
        // This is safe because limit is a usize, not user input
        let sql = format!(
            "SELECT bp.txid, bp.pattern_type, bp.pattern_data, bp.vout, bp.pubkey_index
             FROM burn_patterns bp
             ORDER BY bp.pattern_type, bp.txid
             LIMIT {}",
            limit
        );

        let samples = conn.query_collect(&sql, |row| {
            Ok(BurnPatternSample {
                txid: row.get(0)?,
                pattern_type: row.get(1)?,
                pattern_data: row.get(2)?,
                vout: row.get(3)?,
                pubkey_index: row.get(4)?,
            })
        })?;

        Ok(samples)
    }
}
