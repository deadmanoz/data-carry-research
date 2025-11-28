//! Dust threshold analysis functionality
//!
//! This module provides analysis of P2MS outputs relative to Bitcoin Core's dust thresholds.
//! Reports outputs below dust limits when spending to different destination types:
//! - 546 sats: threshold when spending to non-segwit destination (e.g., P2PKH)
//! - 294 sats: threshold when spending to segwit destination (e.g., P2WPKH)
//!
//! These are *spending* thresholds (determined by destination output type), NOT creation-time
//! P2MS dust limits (which vary with m-of-n configuration).

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    DustAnalysisReport, DustBucket, DustThresholds, GlobalDustStats, ProtocolDustStats,
    UNCLASSIFIED_SENTINEL,
};
use crate::types::ProtocolType;
use std::collections::HashSet;
use std::str::FromStr;

/// Dust threshold analysis engine
pub struct DustAnalyser;

impl DustAnalyser {
    /// Analyse dust thresholds across all P2MS outputs
    ///
    /// Provides comprehensive dust threshold analysis including:
    /// - Global statistics across all unspent P2MS outputs
    /// - Per-protocol breakdown (sorted by canonical ProtocolType enum order)
    /// - Reconciliation fields for unclassified outputs
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<DustAnalysisReport>` - Dust threshold analysis report
    pub fn analyse_dust_thresholds(db: &Database) -> AppResult<DustAnalysisReport> {
        let conn = db.connection();

        // Query 1: Global statistics from transaction_outputs
        let global_stats = conn.query_row(
            "SELECT
                COUNT(*) as total_outputs,
                COALESCE(SUM(amount), 0) as total_value_sats,
                -- Below 546 (cumulative - non-segwit destination dust)
                COALESCE(SUM(CASE WHEN amount < 546 THEN 1 ELSE 0 END), 0) as count_below_546,
                COALESCE(SUM(CASE WHEN amount < 546 THEN amount ELSE 0 END), 0) as value_below_546,
                -- Below 294 (subset - segwit destination dust)
                COALESCE(SUM(CASE WHEN amount < 294 THEN 1 ELSE 0 END), 0) as count_below_294,
                COALESCE(SUM(CASE WHEN amount < 294 THEN amount ELSE 0 END), 0) as value_below_294,
                -- Above dust (>= 546)
                COALESCE(SUM(CASE WHEN amount >= 546 THEN 1 ELSE 0 END), 0) as count_above_dust,
                COALESCE(SUM(CASE WHEN amount >= 546 THEN amount ELSE 0 END), 0) as value_above_dust
            FROM transaction_outputs
            WHERE is_spent = 0 AND script_type = 'multisig'",
            [],
            |row| {
                let total_outputs = row.get::<_, i64>(0)? as usize;
                let total_value_sats = row.get::<_, i64>(1)? as u64;
                let count_below_546 = row.get::<_, i64>(2)? as usize;
                let value_below_546 = row.get::<_, i64>(3)? as u64;
                let count_below_294 = row.get::<_, i64>(4)? as usize;
                let value_below_294 = row.get::<_, i64>(5)? as u64;
                let count_above_dust = row.get::<_, i64>(6)? as usize;
                let value_above_dust = row.get::<_, i64>(7)? as u64;

                Ok(GlobalDustStats {
                    total_outputs,
                    total_value_sats,
                    below_non_segwit_threshold: DustBucket::new(
                        count_below_546,
                        value_below_546,
                        total_outputs,
                        total_value_sats,
                    ),
                    below_segwit_threshold: DustBucket::new(
                        count_below_294,
                        value_below_294,
                        total_outputs,
                        total_value_sats,
                    ),
                    above_dust: DustBucket::new(
                        count_above_dust,
                        value_above_dust,
                        total_outputs,
                        total_value_sats,
                    ),
                })
            },
        )?;

        // Query 2: Per-protocol statistics (distinguishing Unknown from Unclassified)
        let mut stmt = conn.prepare(&format!(
            "SELECT
                -- Use sentinel to distinguish truly unclassified (no classification row)
                -- from classified-as-Unknown (has row with protocol='Unknown')
                -- COALESCE handles case where c.txid exists but tc.protocol is NULL
                CASE
                    WHEN c.txid IS NULL THEN '{sentinel}'
                    ELSE COALESCE(tc.protocol, 'Unknown')
                END as protocol,
                COUNT(*) as total_outputs,
                COALESCE(SUM(o.amount), 0) as total_value_sats,
                COALESCE(SUM(CASE WHEN o.amount < 546 THEN 1 ELSE 0 END), 0) as count_below_546,
                COALESCE(SUM(CASE WHEN o.amount < 546 THEN o.amount ELSE 0 END), 0) as value_below_546,
                COALESCE(SUM(CASE WHEN o.amount < 294 THEN 1 ELSE 0 END), 0) as count_below_294,
                COALESCE(SUM(CASE WHEN o.amount < 294 THEN o.amount ELSE 0 END), 0) as value_below_294,
                COALESCE(SUM(CASE WHEN o.amount >= 546 THEN 1 ELSE 0 END), 0) as count_above_dust,
                COALESCE(SUM(CASE WHEN o.amount >= 546 THEN o.amount ELSE 0 END), 0) as value_above_dust
            FROM transaction_outputs o
            LEFT JOIN p2ms_output_classifications c ON (o.txid = c.txid AND o.vout = c.vout)
            LEFT JOIN transaction_classifications tc ON c.txid = tc.txid
            WHERE o.is_spent = 0 AND o.script_type = 'multisig'
            GROUP BY CASE WHEN c.txid IS NULL THEN '{sentinel}' ELSE COALESCE(tc.protocol, 'Unknown') END
            ORDER BY total_outputs DESC, protocol ASC",
            sentinel = UNCLASSIFIED_SENTINEL
        ))?;

        // Track warnings for unexpected protocol strings (deduplicated)
        let mut warned_protocols: HashSet<String> = HashSet::new();

        // Collect results, separating unclassified from protocol breakdown
        let mut protocol_breakdown: Vec<ProtocolDustStats> = Vec::new();
        let mut unclassified_count = 0usize;
        let mut unclassified_value_sats = 0u64;

        let rows = stmt.query_map([], |row| {
            let protocol_str: String = row.get(0)?;
            let total_outputs = row.get::<_, i64>(1)? as usize;
            let total_value_sats = row.get::<_, i64>(2)? as u64;
            let count_below_546 = row.get::<_, i64>(3)? as usize;
            let value_below_546 = row.get::<_, i64>(4)? as u64;
            let count_below_294 = row.get::<_, i64>(5)? as usize;
            let value_below_294 = row.get::<_, i64>(6)? as u64;
            let count_above_dust = row.get::<_, i64>(7)? as usize;
            let value_above_dust = row.get::<_, i64>(8)? as u64;

            Ok((
                protocol_str,
                total_outputs,
                total_value_sats,
                count_below_546,
                value_below_546,
                count_below_294,
                value_below_294,
                count_above_dust,
                value_above_dust,
            ))
        })?;

        for row_result in rows {
            let (
                protocol_str,
                total_outputs,
                total_value_sats,
                count_below_546,
                value_below_546,
                count_below_294,
                value_below_294,
                count_above_dust,
                value_above_dust,
            ) = row_result?;

            // Handle unclassified sentinel
            if protocol_str == UNCLASSIFIED_SENTINEL {
                unclassified_count = total_outputs;
                unclassified_value_sats = total_value_sats;
                continue;
            }

            // Parse protocol string to ProtocolType enum
            let protocol = match ProtocolType::from_str(&protocol_str) {
                Ok(p) => p,
                Err(_) => {
                    // Log warning for unexpected protocol string (capped to avoid spam)
                    if warned_protocols.len() < 10 && !warned_protocols.contains(&protocol_str) {
                        tracing::warn!(
                            "Unexpected protocol string in dust analysis: {}",
                            protocol_str
                        );
                        warned_protocols.insert(protocol_str.clone());
                    }
                    ProtocolType::Unknown
                }
            };

            protocol_breakdown.push(ProtocolDustStats {
                protocol,
                total_outputs,
                total_value_sats,
                below_non_segwit_threshold: DustBucket::new(
                    count_below_546,
                    value_below_546,
                    total_outputs,
                    total_value_sats,
                ),
                below_segwit_threshold: DustBucket::new(
                    count_below_294,
                    value_below_294,
                    total_outputs,
                    total_value_sats,
                ),
                above_dust: DustBucket::new(
                    count_above_dust,
                    value_above_dust,
                    total_outputs,
                    total_value_sats,
                ),
            });
        }

        // Sort by canonical ProtocolType enum discriminant order
        protocol_breakdown.sort_by_key(|p| p.protocol.clone() as u8);

        // Calculate classified total
        let classified_outputs_total: usize =
            protocol_breakdown.iter().map(|p| p.total_outputs).sum();

        let report = DustAnalysisReport {
            thresholds: DustThresholds::default(),
            global_stats,
            protocol_breakdown,
            classified_outputs_total,
            unclassified_count,
            unclassified_value_sats,
        };

        // Validate consistency (integer comparisons only)
        Self::validate_consistency(&report)?;

        Ok(report)
    }

    /// Validate internal consistency of the report
    ///
    /// Checks (integer comparisons only, no floating-point):
    /// - below_294.count <= below_546.count (subset)
    /// - below_546.count + above_dust.count == total_outputs
    /// - sum(protocol.total_outputs) + unclassified_count == global.total_outputs
    /// - Same checks for values
    fn validate_consistency(report: &DustAnalysisReport) -> AppResult<()> {
        let global = &report.global_stats;

        // Count consistency
        if global.below_segwit_threshold.count > global.below_non_segwit_threshold.count {
            tracing::warn!(
                "Inconsistency: below_294 count ({}) > below_546 count ({})",
                global.below_segwit_threshold.count,
                global.below_non_segwit_threshold.count
            );
        }

        let bucket_sum = global.below_non_segwit_threshold.count + global.above_dust.count;
        if bucket_sum != global.total_outputs {
            tracing::warn!(
                "Inconsistency: below_546 + above_dust ({}) != total_outputs ({})",
                bucket_sum,
                global.total_outputs
            );
        }

        let protocol_plus_unclassified =
            report.classified_outputs_total + report.unclassified_count;
        if protocol_plus_unclassified != global.total_outputs {
            tracing::warn!(
                "Inconsistency: classified ({}) + unclassified ({}) != total_outputs ({})",
                report.classified_outputs_total,
                report.unclassified_count,
                global.total_outputs
            );
        }

        // Value consistency
        if global.below_segwit_threshold.value > global.below_non_segwit_threshold.value {
            tracing::warn!(
                "Inconsistency: below_294 value ({}) > below_546 value ({})",
                global.below_segwit_threshold.value,
                global.below_non_segwit_threshold.value
            );
        }

        let value_bucket_sum = global.below_non_segwit_threshold.value + global.above_dust.value;
        if value_bucket_sum != global.total_value_sats {
            tracing::warn!(
                "Inconsistency: below_546 value + above_dust value ({}) != total_value ({})",
                value_bucket_sum,
                global.total_value_sats
            );
        }

        let protocol_value_total: u64 = report
            .protocol_breakdown
            .iter()
            .map(|p| p.total_value_sats)
            .sum();
        let value_plus_unclassified = protocol_value_total + report.unclassified_value_sats;
        if value_plus_unclassified != global.total_value_sats {
            tracing::warn!(
                "Inconsistency: classified value ({}) + unclassified value ({}) != total_value ({})",
                protocol_value_total,
                report.unclassified_value_sats,
                global.total_value_sats
            );
        }

        Ok(())
    }
}
