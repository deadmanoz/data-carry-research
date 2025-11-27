//! Spendability statistics analysis
//!
//! This module provides comprehensive analysis of P2MS output spendability,
//! replacing raw SQL queries with structured, type-safe analysis.
//!
//! ## Overview
//!
//! Spendability analysis determines whether P2MS outputs are spendable (contain
//! real signing keys) or unspendable (only burn keys or data keys). This is critical
//! for understanding UTXO bloat attribution.
//!
//! ## Key Concepts
//!
//! - **Spendable**: Output contains at least one valid signing key (can be spent by user)
//! - **Unspendable**: Output contains only burn keys or data keys (cannot be spent)
//! - **Burn Keys**: Known Bitcoin Stamps patterns (022222..., 033333..., 020202..., 030303...)
//! - **Data Keys**: Invalid EC points used for data embedding
//! - **Real Keys**: Valid secp256k1 EC points that could be signing keys

use super::types::{
    KeyCountDistribution, KeyCountStats, OverallSpendability, ProtocolSpendabilityStats,
    ReasonStats, SpendabilityStatsReport, TransactionSpendabilityStats,
};
use crate::database::Database;
use crate::errors::AppResult;

// SQL constants for reusability in tests
// CRITICAL: Only count UTXO outputs (is_spent = 0), not spent outputs
// All queries join with transaction_outputs to filter by is_spent
const SQL_OVERALL_BREAKDOWN: &str = "
    SELECT c.is_spendable, COUNT(*) as count
    FROM p2ms_output_classifications c
    JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
    WHERE o.is_spent = 0
    GROUP BY c.is_spendable
";

const SQL_PROTOCOL_BREAKDOWN: &str = "
    SELECT c.protocol, c.is_spendable, COUNT(*) as count
    FROM p2ms_output_classifications c
    JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
    WHERE o.is_spent = 0
    GROUP BY c.protocol, c.is_spendable
    ORDER BY c.protocol, c.is_spendable
";

const SQL_REASON_DISTRIBUTION: &str = "
    SELECT c.spendability_reason, COUNT(*) as count
    FROM p2ms_output_classifications c
    JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
    WHERE o.is_spent = 0
    AND c.spendability_reason IS NOT NULL
    GROUP BY c.spendability_reason
    ORDER BY count DESC
";

const SQL_KEY_COUNT_STATS: &str = "
    SELECT
        SUM(c.real_pubkey_count) as total_real,
        AVG(c.real_pubkey_count) as avg_real,
        MIN(c.real_pubkey_count) as min_real,
        MAX(c.real_pubkey_count) as max_real,
        SUM(c.burn_key_count) as total_burn,
        AVG(c.burn_key_count) as avg_burn,
        MIN(c.burn_key_count) as min_burn,
        MAX(c.burn_key_count) as max_burn,
        SUM(c.data_key_count) as total_data,
        AVG(c.data_key_count) as avg_data,
        MIN(c.data_key_count) as min_data,
        MAX(c.data_key_count) as max_data
    FROM p2ms_output_classifications c
    JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
    WHERE o.is_spent = 0
";

const SQL_TX_LEVEL_AGGREGATION: &str = "
    SELECT
        COUNT(DISTINCT CASE WHEN has_spendable = 1 THEN txid END) as txs_with_spendable,
        COUNT(DISTINCT txid) as total_txs
    FROM (
        SELECT c.txid, MAX(c.is_spendable) as has_spendable
        FROM p2ms_output_classifications c
        JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
        WHERE o.is_spent = 0
        GROUP BY c.txid
    )
";

/// Spendability statistics analyser
pub struct SpendabilityStatsAnalyser;

impl SpendabilityStatsAnalyser {
    /// Analyse spendability statistics comprehensively
    /// Provides:
    /// - Overall spendable vs unspendable breakdown
    /// - Per-protocol spendability rates
    /// - Spendability reason distribution
    /// - Key count statistics (burn/data/real)
    /// - Transaction-level aggregation
    pub fn analyse_spendability(db: &Database) -> AppResult<SpendabilityStatsReport> {
        let overall = Self::get_overall_breakdown(db)?;
        let protocol_breakdown = Self::get_protocol_breakdown(db)?;
        let reason_distribution = Self::get_reason_distribution(db)?;
        let key_count_distribution = Self::get_key_count_distributions(db)?;
        let transaction_level = Self::get_transaction_level_stats(db)?;

        Ok(SpendabilityStatsReport {
            overall,
            protocol_breakdown,
            reason_distribution,
            key_count_distribution,
            transaction_level,
        })
    }

    /// Get overall spendability breakdown
    ///
    /// Queries: `SELECT is_spendable, COUNT(*) FROM p2ms_output_classifications`
    ///
    /// CRITICAL: Only counts UTXO outputs (is_spent = 0), not spent outputs
    pub fn get_overall_breakdown(db: &Database) -> AppResult<OverallSpendability> {
        let conn = db.connection();

        // Get total count for percentage calculation (UTXO outputs only)
        let total_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM p2ms_output_classifications c
             JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
             WHERE o.is_spent = 0",
            [],
            |row| row.get(0),
        )?;

        if total_count == 0 {
            return Ok(OverallSpendability::default());
        }

        // Get spendable/unspendable counts
        let mut stmt = conn.prepare(SQL_OVERALL_BREAKDOWN)?;
        let mut rows = stmt.query([])?;

        let mut spendable_count = 0usize;
        let mut unspendable_count = 0usize;

        while let Some(row) = rows.next()? {
            let is_spendable: Option<bool> = row.get(0)?;
            let count: i64 = row.get(1)?;

            match is_spendable {
                Some(true) => spendable_count = count as usize,
                Some(false) => unspendable_count = count as usize,
                None => {
                    // Should never happen - all protocols evaluate spendability
                    // If we see NULL, that's a bug in the classifiers
                }
            }
        }

        let spendable_percentage = (spendable_count as f64 * 100.0) / total_count as f64;
        let unspendable_percentage = (unspendable_count as f64 * 100.0) / total_count as f64;

        Ok(OverallSpendability {
            total_outputs: total_count as usize,
            spendable_count,
            spendable_percentage,
            unspendable_count,
            unspendable_percentage,
        })
    }

    /// Get per-protocol spendability breakdown
    ///
    /// No join required - p2ms_output_classifications already has protocol column.
    ///
    /// Queries: `SELECT protocol, is_spendable, COUNT(*) FROM p2ms_output_classifications`
    pub fn get_protocol_breakdown(db: &Database) -> AppResult<Vec<ProtocolSpendabilityStats>> {
        let conn = db.connection();

        let mut stmt = conn.prepare(SQL_PROTOCOL_BREAKDOWN)?;
        let rows = stmt.query_map([], |row| {
            let protocol: String = row.get(0)?;
            let is_spendable: Option<bool> = row.get(1)?;
            let count: i64 = row.get(2)?;
            Ok((protocol, is_spendable, count))
        })?;

        // Aggregate by protocol - two categories: spendable, unspendable
        use std::collections::HashMap;
        let mut protocol_map: HashMap<String, (usize, usize)> = HashMap::new();

        for row in rows {
            let (protocol, is_spendable, count) = row?;
            let entry = protocol_map.entry(protocol).or_insert((0, 0));

            match is_spendable {
                Some(true) => entry.0 += count as usize,  // spendable
                Some(false) => entry.1 += count as usize, // unspendable
                None => {
                    // Should never happen - all protocols evaluate spendability
                    // If we see NULL, that's a bug in the classifiers
                }
            }
        }

        // Convert to Vec of stats
        let mut protocol_stats: Vec<ProtocolSpendabilityStats> = protocol_map
            .into_iter()
            .map(|(protocol, (spendable, unspendable))| {
                let total = spendable + unspendable;
                let spendable_percentage = if total > 0 {
                    (spendable as f64 * 100.0) / total as f64
                } else {
                    0.0
                };
                let unspendable_percentage = if total > 0 {
                    (unspendable as f64 * 100.0) / total as f64
                } else {
                    0.0
                };

                ProtocolSpendabilityStats {
                    protocol,
                    total_outputs: total,
                    spendable_count: spendable,
                    spendable_percentage,
                    unspendable_count: unspendable,
                    unspendable_percentage,
                }
            })
            .collect();

        // Sort by canonical ProtocolType enum order for consistent JSON output
        protocol_stats.sort_by(|a, b| {
            use crate::types::ProtocolType;
            use std::str::FromStr;
            let a_order = ProtocolType::from_str(&a.protocol)
                .map(|p| p as u8)
                .unwrap_or(u8::MAX);
            let b_order = ProtocolType::from_str(&b.protocol)
                .map(|p| p as u8)
                .unwrap_or(u8::MAX);
            a_order.cmp(&b_order)
        });

        Ok(protocol_stats)
    }

    /// Get spendability reason distribution
    ///
    /// Queries: `SELECT spendability_reason, COUNT(*) FROM p2ms_output_classifications`
    /// CRITICAL: Only counts UTXO outputs (is_spent = 0), not spent outputs
    pub fn get_reason_distribution(db: &Database) -> AppResult<Vec<ReasonStats>> {
        let conn = db.connection();

        // Get total count for percentage calculation (UTXO only)
        let total_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM p2ms_output_classifications c
             JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
             WHERE o.is_spent = 0 AND c.spendability_reason IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        if total_count == 0 {
            return Ok(Vec::new());
        }

        let mut stmt = conn.prepare(SQL_REASON_DISTRIBUTION)?;
        let reason_stats = stmt
            .query_map([], |row| {
                let reason: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                let percentage = (count as f64 * 100.0) / total_count as f64;

                Ok(ReasonStats {
                    reason,
                    count: count as usize,
                    percentage,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(reason_stats)
    }

    /// Get key count distribution statistics
    ///
    /// Aggregates statistics on real_pubkey_count, burn_key_count, data_key_count.
    pub fn get_key_count_distributions(db: &Database) -> AppResult<KeyCountDistribution> {
        let conn = db.connection();

        let mut stmt = conn.prepare(SQL_KEY_COUNT_STATS)?;
        let mut rows = stmt.query([])?;

        if let Some(row) = rows.next()? {
            // Handle NULL values from aggregate functions on empty tables
            let total_real: Option<i64> = row.get(0)?;
            let avg_real: Option<f64> = row.get(1)?;
            let min_real: Option<i64> = row.get(2)?;
            let max_real: Option<i64> = row.get(3)?;

            let total_burn: Option<i64> = row.get(4)?;
            let avg_burn: Option<f64> = row.get(5)?;
            let min_burn: Option<i64> = row.get(6)?;
            let max_burn: Option<i64> = row.get(7)?;

            let total_data: Option<i64> = row.get(8)?;
            let avg_data: Option<f64> = row.get(9)?;
            let min_data: Option<i64> = row.get(10)?;
            let max_data: Option<i64> = row.get(11)?;

            Ok(KeyCountDistribution {
                real_pubkey_stats: KeyCountStats {
                    total: total_real.unwrap_or(0) as u64,
                    average: avg_real.unwrap_or(0.0),
                    min: min_real.unwrap_or(0) as u8,
                    max: max_real.unwrap_or(0) as u8,
                },
                burn_key_stats: KeyCountStats {
                    total: total_burn.unwrap_or(0) as u64,
                    average: avg_burn.unwrap_or(0.0),
                    min: min_burn.unwrap_or(0) as u8,
                    max: max_burn.unwrap_or(0) as u8,
                },
                data_key_stats: KeyCountStats {
                    total: total_data.unwrap_or(0) as u64,
                    average: avg_data.unwrap_or(0.0),
                    min: min_data.unwrap_or(0) as u8,
                    max: max_data.unwrap_or(0) as u8,
                },
            })
        } else {
            Ok(KeyCountDistribution::default())
        }
    }

    /// Get transaction-level spendability statistics
    ///
    /// Aggregates whether transactions have ANY spendable output.
    ///
    /// Queries: `SELECT txid, MAX(is_spendable) FROM p2ms_output_classifications GROUP BY txid`
    pub fn get_transaction_level_stats(db: &Database) -> AppResult<TransactionSpendabilityStats> {
        let conn = db.connection();

        let mut stmt = conn.prepare(SQL_TX_LEVEL_AGGREGATION)?;
        let mut rows = stmt.query([])?;

        if let Some(row) = rows.next()? {
            // Handle NULL values from aggregate functions on empty tables
            let txs_with_spendable: Option<i64> = row.get(0)?;
            let total_txs: Option<i64> = row.get(1)?;

            let txs_with_spendable = txs_with_spendable.unwrap_or(0);
            let total_txs = total_txs.unwrap_or(0);

            let txs_all_unspendable = (total_txs - txs_with_spendable) as usize;
            let spendable_percentage = if total_txs > 0 {
                (txs_with_spendable as f64 * 100.0) / total_txs as f64
            } else {
                0.0
            };

            Ok(TransactionSpendabilityStats {
                total_transactions: total_txs as usize,
                transactions_with_spendable_outputs: txs_with_spendable as usize,
                transactions_all_unspendable: txs_all_unspendable,
                spendable_transaction_percentage: spendable_percentage,
            })
        } else {
            Ok(TransactionSpendabilityStats::default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyser_creation() {
        // Test that analyser can be instantiated
        let db = Database::new_v2(":memory:").unwrap();
        let result = SpendabilityStatsAnalyser::analyse_spendability(&db);
        if let Err(e) = &result {
            eprintln!("Error: {}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_sql_constants_validity() {
        // Verify SQL constants contain expected keywords and table aliases
        assert!(SQL_OVERALL_BREAKDOWN.contains("c.is_spendable"));
        assert!(SQL_OVERALL_BREAKDOWN.contains("p2ms_output_classifications"));
        assert!(SQL_OVERALL_BREAKDOWN.contains("WHERE o.is_spent = 0"));

        assert!(SQL_PROTOCOL_BREAKDOWN.contains("c.protocol"));
        assert!(SQL_PROTOCOL_BREAKDOWN.contains("c.is_spendable"));
        assert!(SQL_PROTOCOL_BREAKDOWN.contains("WHERE o.is_spent = 0"));

        assert!(SQL_REASON_DISTRIBUTION.contains("c.spendability_reason"));
        assert!(SQL_REASON_DISTRIBUTION.contains("WHERE o.is_spent = 0"));

        assert!(SQL_KEY_COUNT_STATS.contains("c.real_pubkey_count"));
        assert!(SQL_KEY_COUNT_STATS.contains("c.burn_key_count"));
        assert!(SQL_KEY_COUNT_STATS.contains("c.data_key_count"));
        assert!(SQL_KEY_COUNT_STATS.contains("WHERE o.is_spent = 0"));

        assert!(SQL_TX_LEVEL_AGGREGATION.contains("MAX(c.is_spendable)"));
        assert!(SQL_TX_LEVEL_AGGREGATION.contains("GROUP BY c.txid"));
        assert!(SQL_TX_LEVEL_AGGREGATION.contains("WHERE o.is_spent = 0"));
    }
}
