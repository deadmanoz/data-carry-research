//! Value analysis functionality
//!
//! This module provides comprehensive value distribution analysis for P2MS transactions,
//! showing economic metrics by protocol including BTC value distribution, output counts,
//! and fee context.

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    FeeAnalysisReport, GlobalValueDistribution, OverallValueStats, ProtocolFeeStats,
    ProtocolValueDistribution, ProtocolValueStats, ValueAnalysisReport, ValueBucket,
    ValueDistributionReport, ValuePercentiles,
};
use crate::types::ProtocolType;
use std::str::FromStr;

/// Maximum number of values to load into memory for percentile calculation
/// Protects against memory exhaustion on very large datasets (100M values ≈ 800MB)
/// Conservative limit suitable for systems with 16GB+ RAM
pub(crate) const MAX_VALUES_IN_MEMORY: i64 = 100_000_000;

/// Value analysis engine for protocol-level economic analysis
pub struct ValueAnalysisEngine;

impl ValueAnalysisEngine {
    /// Analyse value distribution across all protocols
    ///
    /// This provides comprehensive value analysis including:
    /// - Per-protocol BTC value locked in P2MS outputs
    /// - Output count distribution
    /// - Average, min, max values per protocol
    /// - Fee analysis context
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `fee_report` - Existing fee analysis report for context
    ///
    /// # Returns
    /// * `AppResult<ValueAnalysisReport>` - Comprehensive value analysis
    pub fn analyse_value_distribution(
        db: &Database,
        fee_report: FeeAnalysisReport,
    ) -> AppResult<ValueAnalysisReport> {
        let conn = db.connection();

        // Query protocol-level value statistics from output-level data
        // CRITICAL: Only count UTXO outputs (is_spent = 0), not spent outputs
        let mut stmt = conn.prepare(
            "SELECT
                tc.protocol,
                COUNT(*) as output_count,
                COUNT(DISTINCT tc.txid) as tx_count,
                SUM(to1.amount) as total_value_sats,
                AVG(to1.amount) as avg_value_sats,
                MIN(to1.amount) as min_value_sats,
                MAX(to1.amount) as max_value_sats
            FROM transaction_classifications tc
            JOIN transaction_outputs to1 ON tc.txid = to1.txid
            WHERE to1.script_type = 'multisig'
            AND to1.is_spent = 0
            GROUP BY tc.protocol
            ORDER BY output_count DESC",
        )?;

        let protocol_stats = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?, // protocol
                    row.get::<_, i64>(1)?,    // output_count
                    row.get::<_, i64>(2)?,    // tx_count
                    row.get::<_, i64>(3)?,    // total_value_sats
                    row.get::<_, f64>(4)?,    // avg_value_sats
                    row.get::<_, i64>(5)?,    // min_value_sats
                    row.get::<_, i64>(6)?,    // max_value_sats
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Query fee statistics per protocol
        let mut fee_stmt = conn.prepare(
            "SELECT
                tc.protocol,
                SUM(et.transaction_fee) as total_fees,
                AVG(et.transaction_fee) as avg_fee,
                AVG(et.fee_per_byte) as avg_fee_per_byte,
                AVG(et.data_storage_fee_rate) as avg_storage_cost
            FROM transaction_classifications tc
            JOIN enriched_transactions et ON tc.txid = et.txid
            GROUP BY tc.protocol",
        )?;

        let fee_stats: std::collections::HashMap<String, ProtocolFeeStats> = fee_stmt
            .query_map([], |row| {
                let protocol: String = row.get(0)?;
                let stats = ProtocolFeeStats {
                    total_fees_paid_sats: row.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
                    average_fee_sats: row.get::<_, Option<f64>>(2)?.unwrap_or(0.0),
                    average_fee_per_byte: row.get::<_, Option<f64>>(3)?.unwrap_or(0.0),
                    average_storage_cost_per_byte: row.get::<_, Option<f64>>(4)?.unwrap_or(0.0),
                };
                Ok((protocol, stats))
            })?
            .collect::<Result<_, _>>()?;

        // Calculate totals for percentages
        let total_value_sats: i64 = protocol_stats
            .iter()
            .map(|(_, _, _, total, _, _, _)| total)
            .sum();
        let total_outputs: i64 = protocol_stats
            .iter()
            .map(|(_, count, _, _, _, _, _)| count)
            .sum();

        // Build protocol value breakdown with fee stats
        let mut protocol_value_breakdown: Vec<ProtocolValueStats> = protocol_stats
            .into_iter()
            .map(
                |(
                    protocol_str,
                    output_count,
                    tx_count,
                    total_sats,
                    avg_sats,
                    min_sats,
                    max_sats,
                )| {
                    let percentage_of_total_value = if total_value_sats > 0 {
                        (total_sats as f64 / total_value_sats as f64) * 100.0
                    } else {
                        0.0
                    };

                    // Get fee stats for this protocol, or use defaults if not found
                    let protocol_fee_stats =
                        fee_stats.get(&protocol_str).cloned().unwrap_or_default();

                    // Parse protocol string to enum (parse once at DB boundary)
                    let protocol = ProtocolType::from_str(&protocol_str).unwrap_or_default();

                    ProtocolValueStats {
                        protocol,
                        output_count: output_count as usize,
                        transaction_count: tx_count as usize,
                        total_btc_value_sats: total_sats as u64,
                        average_btc_per_output: avg_sats,
                        min_btc_value_sats: min_sats as u64,
                        max_btc_value_sats: max_sats as u64,
                        percentage_of_total_value,
                        fee_stats: protocol_fee_stats,
                    }
                },
            )
            .collect();

        // Sort by canonical ProtocolType enum order for consistent JSON output
        protocol_value_breakdown.sort_by_key(|p| p.protocol as u8);

        // Calculate overall statistics
        let overall_statistics = OverallValueStats {
            total_outputs_analysed: total_outputs as usize,
            total_btc_locked_in_p2ms: total_value_sats as u64,
            total_protocols: protocol_value_breakdown.len(),
        };

        Ok(ValueAnalysisReport {
            protocol_value_breakdown,
            overall_statistics,
            fee_context: fee_report,
        })
    }

    /// Analyse detailed value distribution histograms across all protocols
    ///
    /// This provides histogram data suitable for plotting value distributions:
    /// - Global distribution across all P2MS outputs
    /// - Per-protocol distributions
    /// - Value buckets with counts and percentages
    /// - Statistical percentiles
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<ValueDistributionReport>` - Comprehensive value distribution histograms
    pub fn analyse_value_distributions(db: &Database) -> AppResult<ValueDistributionReport> {
        let conn = db.connection();

        // Define bucket ranges aware of Bitcoin dust limits and common P2MS value patterns
        //
        // BUCKET RATIONALE:
        // - 546 sats: Standard P2PKH dust limit (3 * (148 + 34) + 10 = 546)
        // - 2,730 sats: Approximate P2MS dust limit for 1-of-3 multisig (3 * (148 + 254) + 10 ≈ 2,730)
        //                P2MS scripts are larger, requiring higher minimum values to be economically spendable
        // - 5K-100K: Common range for data-carrying protocols (Stamps, Counterparty)
        // - 100K-1M: Medium value range, less common for pure data storage
        // - 1M+: Large values, typically legitimate multisig or mixed-use outputs
        //
        // These ranges optimise for detecting economic patterns in data-carrying P2MS outputs.
        let bucket_ranges: Vec<(u64, u64)> = vec![
            (0, 546),                     // Below standard dust (should be empty)
            (546, 1_000),                 // Standard dust to 1K sats
            (1_000, 2_730),               // Above standard dust, below P2MS dust limit
            (2_730, 5_000),               // Just above P2MS dust to 5K
            (5_000, 10_000),              // 5K-10K satoshis
            (10_000, 50_000),             // 10K-50K satoshis
            (50_000, 100_000),            // 50K-100K satoshis
            (100_000, 500_000),           // 100K-500K satoshis
            (500_000, 1_000_000),         // 500K-1M satoshis (0.005-0.01 BTC)
            (1_000_000, 5_000_000),       // 1M-5M satoshis (0.01-0.05 BTC)
            (5_000_000, 10_000_000),      // 5M-10M satoshis (0.05-0.1 BTC)
            (10_000_000, 50_000_000),     // 10M-50M satoshis (0.1-0.5 BTC)
            (50_000_000, 100_000_000),    // 50M-100M satoshis (0.5-1 BTC)
            (100_000_000, 500_000_000),   // 100M-500M satoshis (1-5 BTC)
            (500_000_000, 1_000_000_000), // 500M-1B satoshis (5-10 BTC)
            (1_000_000_000, i64::MAX as u64), // 1B+ satoshis (10+ BTC)
                                          // LIMIT: i64::MAX (9.22M BTC) for SQLite INTEGER compatibility
                                          // This is well above Bitcoin's 21M BTC supply, so no practical limitation
        ];

        // First, get global distribution (all P2MS outputs)
        let global_distribution = Self::calculate_global_distribution(conn, &bucket_ranges)?;

        // Get list of protocols
        let mut protocol_stmt = conn.prepare(
            "SELECT DISTINCT protocol
             FROM transaction_classifications
             ORDER BY protocol",
        )?;

        let protocols: Vec<String> = protocol_stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        // Calculate distribution for each protocol
        let mut protocol_distributions = Vec::new();
        for protocol in protocols {
            let distribution =
                Self::calculate_protocol_distribution(conn, &protocol, &bucket_ranges)?;
            protocol_distributions.push(distribution);
        }

        Ok(ValueDistributionReport {
            global_distribution,
            protocol_distributions,
            bucket_ranges: bucket_ranges.clone(),
        })
    }

    /// Calculate global value distribution across all P2MS outputs
    fn calculate_global_distribution(
        conn: &rusqlite::Connection,
        bucket_ranges: &[(u64, u64)],
    ) -> AppResult<GlobalValueDistribution> {
        // Get basic statistics with NULL handling
        let mut stats_stmt = conn.prepare(
            "SELECT
                COUNT(*) as total_outputs,
                COALESCE(SUM(amount), 0) as total_value,
                COALESCE(MIN(amount), 0) as min_value,
                COALESCE(MAX(amount), 0) as max_value,
                COALESCE(AVG(amount), 0.0) as mean_value
            FROM transaction_outputs
            WHERE script_type = 'multisig'
            AND is_spent = 0",
        )?;

        let (total_outputs, total_value_sats, min_value, max_value, mean_value) = stats_stmt
            .query_row([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, f64>(4)?,
                ))
            })?;

        // Calculate percentiles
        let percentiles = Self::calculate_percentiles(conn, None)?;

        // Calculate bucket distributions
        let buckets =
            Self::calculate_buckets(conn, bucket_ranges, None, total_outputs, total_value_sats)?;

        Ok(GlobalValueDistribution {
            total_outputs,
            total_value_sats,
            buckets,
            percentiles,
            min_value,
            max_value,
            mean_value,
            median_value: percentiles.p50,
        })
    }

    /// Calculate value distribution for a specific protocol
    fn calculate_protocol_distribution(
        conn: &rusqlite::Connection,
        protocol: &str,
        bucket_ranges: &[(u64, u64)],
    ) -> AppResult<ProtocolValueDistribution> {
        // Get basic statistics for this protocol with NULL handling
        let mut stats_stmt = conn.prepare(
            "SELECT
                COUNT(*) as total_outputs,
                COALESCE(SUM(to1.amount), 0) as total_value
            FROM transaction_classifications tc
            JOIN transaction_outputs to1 ON tc.txid = to1.txid
            WHERE to1.script_type = 'multisig'
            AND to1.is_spent = 0
            AND tc.protocol = ?",
        )?;

        let (total_outputs, total_value_sats) = stats_stmt.query_row([protocol], |row| {
            Ok((row.get::<_, i64>(0)? as usize, row.get::<_, i64>(1)? as u64))
        })?;

        // Calculate percentiles for this protocol
        let percentiles = Self::calculate_percentiles(conn, Some(protocol))?;

        // Calculate bucket distributions
        let buckets = Self::calculate_buckets(
            conn,
            bucket_ranges,
            Some(protocol),
            total_outputs,
            total_value_sats,
        )?;

        // Parse protocol string to enum (parse once at DB boundary)
        let protocol_type = ProtocolType::from_str(protocol).unwrap_or_default();

        Ok(ProtocolValueDistribution {
            protocol: protocol_type,
            total_outputs,
            total_value_sats,
            buckets,
            percentiles,
        })
    }

    /// Calculate percentiles for value distribution
    ///
    /// NOTE: This implementation loads all values into memory for accurate percentile calculation.
    /// For very large datasets (millions of outputs), this could use significant memory.
    ///
    /// Alternative approaches for production systems with memory constraints:
    /// 1. Use SQL percentile approximation: `percentile_cont(0.5) WITHIN GROUP (ORDER BY amount)`
    ///    (requires SQLite extension or PostgreSQL)
    /// 2. Use sampling: Select a random subset for percentile estimation
    /// 3. Use histogram-based approximation from bucket data
    fn calculate_percentiles(
        conn: &rusqlite::Connection,
        protocol: Option<&str>,
    ) -> AppResult<ValuePercentiles> {
        // First, get the count to avoid loading data if empty
        let count_query = if protocol.is_some() {
            "SELECT COUNT(*) FROM transaction_outputs to1
             JOIN transaction_classifications tc ON to1.txid = tc.txid
             WHERE to1.script_type = 'multisig' AND to1.is_spent = 0 AND tc.protocol = ?"
        } else {
            "SELECT COUNT(*) FROM transaction_outputs
             WHERE script_type = 'multisig' AND is_spent = 0"
        };

        let mut count_stmt = conn.prepare(count_query)?;
        let count: i64 = if let Some(proto) = protocol {
            count_stmt.query_row([proto], |row| row.get(0))?
        } else {
            count_stmt.query_row([], |row| row.get(0))?
        };

        if count == 0 {
            return Ok(ValuePercentiles {
                p25: 0,
                p50: 0,
                p75: 0,
                p90: 0,
                p95: 0,
                p99: 0,
            });
        }

        // MEMORY SAFETY: Refuse to load excessive data into memory
        // For very large datasets, use bucket-based median approximation instead
        if count > MAX_VALUES_IN_MEMORY {
            tracing::warn!(
                "Dataset too large for in-memory percentile calculation ({} outputs). \
                 Use bucket data for median approximation. Returning zeros for percentiles.",
                count
            );
            return Ok(ValuePercentiles {
                p25: 0,
                p50: 0,
                p75: 0,
                p90: 0,
                p95: 0,
                p99: 0,
            });
        }

        // Build query based on whether we're filtering by protocol
        let query = if protocol.is_some() {
            "SELECT amount
             FROM transaction_outputs to1
             JOIN transaction_classifications tc ON to1.txid = tc.txid
             WHERE to1.script_type = 'multisig'
             AND to1.is_spent = 0
             AND tc.protocol = ?
             ORDER BY amount"
        } else {
            "SELECT amount
             FROM transaction_outputs
             WHERE script_type = 'multisig'
             AND is_spent = 0
             ORDER BY amount"
        };

        let mut stmt = conn.prepare(query)?;

        let values: Vec<u64> = if let Some(proto) = protocol {
            stmt.query_map([proto], |row| Ok(row.get::<_, i64>(0)? as u64))?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map([], |row| Ok(row.get::<_, i64>(0)? as u64))?
                .collect::<Result<Vec<_>, _>>()?
        };

        let len = values.len();
        if len == 0 {
            return Ok(ValuePercentiles {
                p25: 0,
                p50: 0,
                p75: 0,
                p90: 0,
                p95: 0,
                p99: 0,
            });
        }

        // PERCENTILE METHOD: Nearest-rank (NOT linear interpolation)
        //
        // This uses simple array indexing which is adequate for large datasets (1000+ values).
        // For datasets <100 values, linear interpolation would be more accurate but adds
        // complexity. Since most analyses involve thousands of outputs, nearest-rank
        // provides sufficient precision.
        //
        // Bounds checking via saturating_sub prevents underflow, min prevents overflow.
        Ok(ValuePercentiles {
            p25: values[len.saturating_sub(1).min(len * 25 / 100)],
            p50: values[len.saturating_sub(1).min(len * 50 / 100)],
            p75: values[len.saturating_sub(1).min(len * 75 / 100)],
            p90: values[len.saturating_sub(1).min(len * 90 / 100)],
            p95: values[len.saturating_sub(1).min(len * 95 / 100)],
            p99: values[len.saturating_sub(1).min(len * 99 / 100)],
        })
    }

    /// Calculate bucket distributions
    ///
    /// Bucket ranges use inclusive lower bound, exclusive upper bound: [range_min, range_max)
    /// Example: bucket (546, 1000) contains values 546 ≤ amount < 1000
    fn calculate_buckets(
        conn: &rusqlite::Connection,
        bucket_ranges: &[(u64, u64)],
        protocol: Option<&str>,
        total_outputs: usize,
        total_value: u64,
    ) -> AppResult<Vec<ValueBucket>> {
        let mut buckets = Vec::new();

        for (range_min, range_max) in bucket_ranges {
            // Build query based on whether we're filtering by protocol
            let query = if protocol.is_some() {
                "SELECT
                    COUNT(*) as count,
                    COALESCE(SUM(to1.amount), 0) as total_value
                FROM transaction_outputs to1
                JOIN transaction_classifications tc ON to1.txid = tc.txid
                WHERE to1.script_type = 'multisig'
                AND to1.is_spent = 0
                AND to1.amount >= ?
                AND to1.amount < ?
                AND tc.protocol = ?"
            } else {
                "SELECT
                    COUNT(*) as count,
                    COALESCE(SUM(amount), 0) as total_value
                FROM transaction_outputs
                WHERE script_type = 'multisig'
                AND is_spent = 0
                AND amount >= ?
                AND amount < ?"
            };

            let mut stmt = conn.prepare(query)?;

            let (count, bucket_total_value): (i64, i64) = if let Some(proto) = protocol {
                stmt.query_row(
                    rusqlite::params![*range_min as i64, *range_max as i64, proto],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?
            } else {
                stmt.query_row([*range_min as i64, *range_max as i64], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
            };

            let count = count as usize;
            let bucket_total_value = bucket_total_value as u64;

            buckets.push(ValueBucket::new(
                *range_min,
                *range_max,
                count,
                bucket_total_value,
                total_outputs,
                total_value,
            ));
        }

        Ok(buckets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::database::Database;

    #[test]
    fn test_value_analysis_empty_database() {
        let db = Database::new(":memory:").unwrap();

        // Create empty fee report for test
        let fee_report = FeeAnalysisReport::default();

        // Should not fail on empty database
        let result = ValueAnalysisEngine::analyse_value_distribution(&db, fee_report);
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert_eq!(analysis.overall_statistics.total_outputs_analysed, 0);
        assert_eq!(analysis.overall_statistics.total_btc_locked_in_p2ms, 0);
        assert_eq!(analysis.protocol_value_breakdown.len(), 0);
    }

    #[test]
    fn test_value_distributions_empty_database() {
        let db = Database::new(":memory:").unwrap();

        // Should not fail on empty database (tests NULL handling)
        let result = ValueAnalysisEngine::analyse_value_distributions(&db);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.global_distribution.total_outputs, 0);
        assert_eq!(report.global_distribution.total_value_sats, 0);
        assert_eq!(report.protocol_distributions.len(), 0);
        assert!(!report.bucket_ranges.is_empty()); // Buckets should still be defined
    }

    #[test]
    fn test_value_distributions_large_values() {
        // Test that values >= 1B sats are properly counted (tests i64::MAX fix)
        let db = Database::new(":memory:").unwrap();
        let conn = db.connection();

        // Setup minimal schema
        conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])
            .unwrap();

        // Add a very large value output (10 BTC = 1B sats)
        conn.execute(
            "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, is_coinbase, is_spent)
             VALUES ('large_tx', 0, 100000, 1000000000, 'dummy', 'multisig', 100, 0, 0)",
            [],
        )
        .unwrap();

        let result = ValueAnalysisEngine::analyse_value_distributions(&db);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.global_distribution.total_outputs, 1);
        assert_eq!(report.global_distribution.total_value_sats, 1_000_000_000);

        // Find the 1B+ bucket and verify it has the output
        let large_bucket = report
            .global_distribution
            .buckets
            .iter()
            .find(|b| b.range_min == 1_000_000_000)
            .expect("Should have 1B+ bucket");

        assert_eq!(large_bucket.count, 1, "Large value should be in top bucket");
        assert_eq!(large_bucket.value, 1_000_000_000);
    }

    #[test]
    fn test_percentile_calculation_edge_cases() {
        let db = Database::new(":memory:").unwrap();
        let conn = db.connection();

        // Setup minimal schema
        conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])
            .unwrap();

        // Add outputs with known values for percentile testing
        let test_values = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
        for (i, value) in test_values.iter().enumerate() {
            conn.execute(
                "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, is_coinbase, is_spent)
                 VALUES (?1, 0, 100000, ?2, 'dummy', 'multisig', 100, 0, 0)",
                [format!("tx_{}", i), value.to_string()],
            )
            .unwrap();
        }

        let result = ValueAnalysisEngine::analyse_value_distributions(&db);
        assert!(result.is_ok());

        let report = result.unwrap();
        let percentiles = &report.global_distribution.percentiles;

        // With 10 values, p50 should be around the middle
        assert!(percentiles.p50 >= 400 && percentiles.p50 <= 600);
        assert!(percentiles.p25 <= percentiles.p50);
        assert!(percentiles.p50 <= percentiles.p75);
        assert!(percentiles.p75 <= percentiles.p90);
    }

    #[test]
    fn test_bucket_boundaries() {
        // Test that values at bucket boundaries are correctly categorised
        let db = Database::new(":memory:").unwrap();
        let conn = db.connection();

        conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])
            .unwrap();

        // Test boundary values: 546 (dust limit), 2730 (P2MS dust), 1M, 1B
        let boundary_values = vec![
            ("tx_dust_exact", 546),
            ("tx_dust_minus1", 545),
            ("tx_p2ms_dust", 2730),
            ("tx_1m", 1_000_000),
            ("tx_1b", 1_000_000_000),
        ];

        for (txid, amount) in boundary_values {
            conn.execute(
                "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, is_coinbase, is_spent)
                 VALUES (?1, 0, 100000, ?2, 'dummy', 'multisig', 100, 0, 0)",
                [txid, &amount.to_string()],
            )
            .unwrap();
        }

        let result = ValueAnalysisEngine::analyse_value_distributions(&db);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.global_distribution.total_outputs, 5);

        // Verify 545 is in (0, 546) bucket, 546 is in (546, 1000) bucket
        let below_dust = report
            .global_distribution
            .buckets
            .iter()
            .find(|b| b.range_min == 0 && b.range_max == 546)
            .unwrap();
        assert_eq!(below_dust.count, 1); // Only tx_dust_minus1

        let dust_bucket = report
            .global_distribution
            .buckets
            .iter()
            .find(|b| b.range_min == 546 && b.range_max == 1_000)
            .unwrap();
        assert_eq!(dust_bucket.count, 1); // Only tx_dust_exact
    }

    #[test]
    fn test_single_value_dataset() {
        // Test percentiles with only 1 value
        let db = Database::new(":memory:").unwrap();
        let conn = db.connection();

        conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, is_coinbase, is_spent)
             VALUES ('single', 0, 100000, 12345, 'dummy', 'multisig', 100, 0, 0)",
            [],
        )
        .unwrap();

        let result = ValueAnalysisEngine::analyse_value_distributions(&db);
        assert!(result.is_ok());

        let report = result.unwrap();
        let percentiles = &report.global_distribution.percentiles;

        // All percentiles should be the same value
        assert_eq!(percentiles.p25, 12345);
        assert_eq!(percentiles.p50, 12345);
        assert_eq!(percentiles.p75, 12345);
        assert_eq!(percentiles.p90, 12345);
        assert_eq!(percentiles.p95, 12345);
        assert_eq!(percentiles.p99, 12345);
    }

    #[test]
    fn test_memory_safety_limit() {
        // Test that percentile calculation has a memory safety limit
        // We can't actually create 100M+ outputs in a test, but we can verify
        // the limit constant is set to a reasonable value

        // Verify the limit is set to 100 million (≈800MB of u64 values)
        assert_eq!(super::MAX_VALUES_IN_MEMORY, 100_000_000);

        // Note: A real test would require mocking the count query to trigger the limit.
        // This test verifies the protection mechanism exists and is configured correctly.
    }

    #[test]
    fn test_all_values_in_single_bucket() {
        // Test when all outputs fall into one bucket
        let db = Database::new(":memory:").unwrap();
        let conn = db.connection();

        conn.execute("INSERT INTO blocks (height) VALUES (100000)", [])
            .unwrap();

        // All values between 5000-10000 (single bucket)
        for i in 0..100 {
            conn.execute(
                "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, script_size, is_coinbase, is_spent)
                 VALUES (?1, 0, 100000, ?2, 'dummy', 'multisig', 100, 0, 0)",
                [format!("tx_{}", i), (5000 + i * 50).to_string()],
            )
            .unwrap();
        }

        let result = ValueAnalysisEngine::analyse_value_distributions(&db);
        assert!(result.is_ok());

        let report = result.unwrap();

        // Find the 5K-10K bucket
        let target_bucket = report
            .global_distribution
            .buckets
            .iter()
            .find(|b| b.range_min == 5_000 && b.range_max == 10_000)
            .unwrap();

        assert_eq!(target_bucket.count, 100);
        assert_eq!(target_bucket.pct_count, 100.0);

        // All other buckets should be empty
        let non_empty_buckets = report
            .global_distribution
            .buckets
            .iter()
            .filter(|b| b.count > 0)
            .count();
        assert_eq!(non_empty_buckets, 1);
    }
}
