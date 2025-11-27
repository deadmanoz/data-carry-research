//! Transaction size distribution analysis
//!
//! This module provides analysis of P2MS transaction sizes to help explain
//! fee patterns. Reports histogram distributions and percentiles for both
//! global and per-protocol breakdowns.

use super::plotly_types::{get_protocol_colour, PlotlyChart, PlotlyLayout, PlotlyTrace};
use super::types::{
    GlobalTxSizeDistribution, ProtocolTxSizeDistribution, TxSizeBucket, TxSizeDistributionReport,
    TxSizePercentiles,
};
use crate::database::Database;
use crate::errors::AppResult;
use crate::types::ProtocolType;
use std::str::FromStr;

/// Standard transaction size buckets (bytes) - single source of truth
/// Bucket semantics: [min, max) - inclusive min, exclusive max.
/// Except last bucket which is [min, ∞) - open-ended.
pub const TX_SIZE_BUCKET_RANGES: &[(u32, u32)] = &[
    (0, 250),            // [0, 250) - Minimal (1-in, 1-2 out)
    (250, 500),          // [250, 500) - Simple
    (500, 1_000),        // [500, 1000) - Moderate (2-3 inputs)
    (1_000, 2_000),      // [1000, 2000) - Multiple in/out
    (2_000, 5_000),      // [2000, 5000) - Complex, small data
    (5_000, 10_000),     // [5000, 10000) - Data-carrying (typical Stamps)
    (10_000, 25_000),    // [10000, 25000) - Large data-carrying
    (25_000, 50_000),    // [25000, 50000) - Very large
    (50_000, 100_000),   // [50000, 100000) - Massive
    (100_000, u32::MAX), // [100000, ∞) - Exceptional (open-ended)
];

/// Transaction size distribution analyser
pub struct TxSizeAnalyser;

impl TxSizeAnalyser {
    /// Analyse transaction size distribution across all P2MS transactions
    ///
    /// Returns histogram data suitable for understanding fee patterns:
    /// - Global distribution across all P2MS transactions
    /// - Per-protocol distributions (sorted by canonical ProtocolType order)
    /// - Percentiles for size distribution analysis
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<TxSizeDistributionReport>` - Comprehensive size distribution
    pub fn analyse_tx_sizes(db: &Database) -> AppResult<TxSizeDistributionReport> {
        let conn = db.connection();

        // Global aggregates
        let global_stats: (usize, u64, u64, Option<u32>, Option<u32>) = conn.query_row(
            "SELECT
                COUNT(*) as total_transactions,
                COALESCE(SUM(transaction_size_bytes), 0) as total_size_bytes,
                COALESCE(SUM(transaction_fee), 0) as total_fees_sats,
                MIN(transaction_size_bytes) as min_size,
                MAX(transaction_size_bytes) as max_size
            FROM enriched_transactions
            WHERE p2ms_outputs_count > 0
              AND is_coinbase = 0
              AND transaction_size_bytes IS NOT NULL
              AND transaction_size_bytes > 0
              AND transaction_fee IS NOT NULL",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                    row.get::<_, Option<i64>>(4)?.map(|v| v as u32),
                ))
            },
        )?;

        let (total_transactions, total_size_bytes, total_fees_sats, min_size_bytes, max_size_bytes) =
            global_stats;

        // Excluded count (NULL/zero size or NULL fee)
        let excluded_null_count: usize = conn.query_row(
            "SELECT COUNT(*) FROM enriched_transactions
            WHERE p2ms_outputs_count > 0
              AND is_coinbase = 0
              AND (transaction_size_bytes IS NULL
                   OR transaction_size_bytes = 0
                   OR transaction_fee IS NULL)",
            [],
            |row| Ok(row.get::<_, i64>(0)? as usize),
        )?;

        // Collect raw data for bucket assignment and percentiles
        let mut stmt = conn.prepare(
            "SELECT transaction_size_bytes, transaction_fee
            FROM enriched_transactions
            WHERE p2ms_outputs_count > 0
              AND is_coinbase = 0
              AND transaction_size_bytes IS NOT NULL
              AND transaction_size_bytes > 0
              AND transaction_fee IS NOT NULL",
        )?;

        let mut sizes: Vec<u32> = Vec::with_capacity(total_transactions);
        let mut buckets = Self::init_buckets();

        let rows = stmt.query_map([], |row| {
            let size = row.get::<_, i64>(0)? as u32;
            let fee = row.get::<_, i64>(1)? as u64;
            Ok((size, fee))
        })?;

        for row_result in rows {
            let (size, fee) = row_result?;
            sizes.push(size);

            // Assign to bucket
            let bucket_idx = Self::assign_bucket(size);
            buckets[bucket_idx].count += 1;
            buckets[bucket_idx].value += fee;
        }

        // Compute bucket percentages after aggregation
        for bucket in &mut buckets {
            bucket.compute_percentages(total_transactions, total_fees_sats);
        }

        // Calculate percentiles
        let percentiles = Self::calculate_percentiles(&mut sizes);

        // Calculate average
        let avg_size_bytes = if total_transactions > 0 {
            total_size_bytes as f64 / total_transactions as f64
        } else {
            0.0
        };

        let global_distribution = GlobalTxSizeDistribution {
            total_transactions,
            total_fees_sats,
            total_size_bytes,
            buckets,
            percentiles,
            min_size_bytes,
            max_size_bytes,
            avg_size_bytes,
            excluded_null_count,
        };

        // Per-protocol distributions
        let protocol_distributions = Self::analyse_per_protocol(conn)?;

        Ok(TxSizeDistributionReport {
            global_distribution,
            protocol_distributions,
        })
    }

    /// Initialise empty buckets from the constant ranges
    fn init_buckets() -> Vec<TxSizeBucket> {
        TX_SIZE_BUCKET_RANGES
            .iter()
            .map(|(min, max)| TxSizeBucket::new_zeroed(*min, *max))
            .collect()
    }

    /// Assign a transaction size to a bucket index
    /// Bucket semantics: [min, max) except last bucket is [min, ∞)
    fn assign_bucket(size_bytes: u32) -> usize {
        TX_SIZE_BUCKET_RANGES
            .iter()
            .enumerate()
            .find_map(|(i, (min, max))| {
                let is_last = i == TX_SIZE_BUCKET_RANGES.len() - 1;
                if size_bytes >= *min && (is_last || size_bytes < *max) {
                    Some(i)
                } else {
                    None
                }
            })
            .expect("bucket ranges must cover all u32 values")
    }

    /// Calculate percentiles from sorted size data
    /// Uses in-memory sort: sorted_vec[(n - 1) * p / 100]
    fn calculate_percentiles(sizes: &mut [u32]) -> Option<TxSizePercentiles> {
        if sizes.is_empty() {
            return None;
        }

        sizes.sort_unstable();
        let n = sizes.len();

        // Percentile calculation: index = (n - 1) * p / 100
        let p25_idx = (n - 1) * 25 / 100;
        let p50_idx = (n - 1) * 50 / 100;
        let p75_idx = (n - 1) * 75 / 100;
        let p90_idx = (n - 1) * 90 / 100;
        let p95_idx = (n - 1) * 95 / 100;
        let p99_idx = (n - 1) * 99 / 100;

        Some(TxSizePercentiles {
            p25: sizes[p25_idx],
            p50: sizes[p50_idx],
            p75: sizes[p75_idx],
            p90: sizes[p90_idx],
            p95: sizes[p95_idx],
            p99: sizes[p99_idx],
        })
    }

    /// Analyse per-protocol transaction size distributions
    fn analyse_per_protocol(
        conn: &rusqlite::Connection,
    ) -> AppResult<Vec<ProtocolTxSizeDistribution>> {
        // Get list of protocols with P2MS transactions
        let mut proto_stmt = conn.prepare(
            "SELECT DISTINCT tc.protocol
            FROM transaction_classifications tc
            INNER JOIN enriched_transactions e ON tc.txid = e.txid
            WHERE e.p2ms_outputs_count > 0
              AND e.is_coinbase = 0
            ORDER BY tc.protocol",
        )?;

        let protocols: Vec<String> = proto_stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        let mut distributions: Vec<ProtocolTxSizeDistribution> = Vec::new();

        for protocol_str in protocols {
            // Parse protocol string to enum
            let protocol = match ProtocolType::from_str(&protocol_str) {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        "Unknown protocol string in tx size analysis: {}",
                        protocol_str
                    );
                    ProtocolType::Unknown
                }
            };

            // Get excluded count for this protocol
            let excluded_null_count: usize = conn.query_row(
                "SELECT COUNT(DISTINCT e.txid) FROM enriched_transactions e
                INNER JOIN transaction_classifications tc ON e.txid = tc.txid
                WHERE e.p2ms_outputs_count > 0
                  AND e.is_coinbase = 0
                  AND tc.protocol = ?
                  AND (e.transaction_size_bytes IS NULL
                       OR e.transaction_size_bytes = 0
                       OR e.transaction_fee IS NULL)",
                [&protocol_str],
                |row| Ok(row.get::<_, i64>(0)? as usize),
            )?;

            // Query per-protocol data (DISTINCT to avoid multi-output double-counting)
            let mut stmt = conn.prepare(
                "SELECT DISTINCT e.txid, e.transaction_size_bytes, e.transaction_fee
                FROM enriched_transactions e
                INNER JOIN transaction_classifications tc ON e.txid = tc.txid
                WHERE e.p2ms_outputs_count > 0
                  AND e.is_coinbase = 0
                  AND tc.protocol = ?
                  AND e.transaction_size_bytes IS NOT NULL
                  AND e.transaction_size_bytes > 0
                  AND e.transaction_fee IS NOT NULL",
            )?;

            let mut sizes: Vec<u32> = Vec::new();
            let mut buckets = Self::init_buckets();
            let mut total_transactions = 0usize;
            let mut total_fees_sats = 0u64;
            let mut total_size_bytes = 0u64;

            let rows = stmt.query_map([&protocol_str], |row| {
                let size = row.get::<_, i64>(1)? as u32;
                let fee = row.get::<_, i64>(2)? as u64;
                Ok((size, fee))
            })?;

            for row_result in rows {
                let (size, fee) = row_result?;
                sizes.push(size);
                total_transactions += 1;
                total_fees_sats += fee;
                total_size_bytes += size as u64;

                let bucket_idx = Self::assign_bucket(size);
                buckets[bucket_idx].count += 1;
                buckets[bucket_idx].value += fee;
            }

            // Compute bucket percentages after aggregation
            for bucket in &mut buckets {
                bucket.compute_percentages(total_transactions, total_fees_sats);
            }

            let percentiles = Self::calculate_percentiles(&mut sizes);

            let avg_size_bytes = if total_transactions > 0 {
                total_size_bytes as f64 / total_transactions as f64
            } else {
                0.0
            };

            let avg_fee_per_byte = if total_size_bytes > 0 {
                total_fees_sats as f64 / total_size_bytes as f64
            } else {
                0.0
            };

            distributions.push(ProtocolTxSizeDistribution {
                protocol,
                total_transactions,
                total_fees_sats,
                buckets,
                percentiles,
                avg_size_bytes,
                avg_fee_per_byte,
                excluded_null_count,
            });
        }

        // Sort by canonical ProtocolType enum discriminant order
        distributions.sort_by_key(|d| d.protocol.clone() as u8);

        Ok(distributions)
    }
}

impl TxSizeDistributionReport {
    /// Convert report to Plotly-native JSON format
    ///
    /// Produces a stacked bar chart showing transaction counts per size bucket with:
    /// - X-axis: Size bucket labels (e.g., "0-250", "250-500", ..., "100K+")
    /// - Y-axis: Transaction count per bucket (stacked by protocol)
    /// - "All P2MS Transactions" trace (hidden by default, can be toggled via legend)
    pub fn to_plotly_chart(&self) -> PlotlyChart {
        // Generate bucket labels for x-axis
        let x_labels: Vec<String> = TX_SIZE_BUCKET_RANGES
            .iter()
            .enumerate()
            .map(|(i, (min, max))| {
                let is_last = i == TX_SIZE_BUCKET_RANGES.len() - 1;
                if is_last {
                    format!("{}+", Self::format_size(*min))
                } else {
                    format!("{}-{}", Self::format_size(*min), Self::format_size(*max))
                }
            })
            .collect();

        let mut traces: Vec<PlotlyTrace> = Vec::new();

        // Add "All P2MS Transactions" trace first (hidden by default)
        // Users can toggle this on via the legend to see the total distribution
        let all_counts: Vec<f64> = self
            .global_distribution
            .buckets
            .iter()
            .map(|b| b.count as f64)
            .collect();
        let all_trace = PlotlyTrace::bar(
            x_labels.clone(),
            all_counts,
            "All P2MS Transactions",
            "#34495E",
        )
        .hidden_by_default();
        traces.push(all_trace);

        // Add per-protocol bar traces (stacked)
        for proto_dist in &self.protocol_distributions {
            // Use Debug format for colour lookup (matches get_protocol_colour keys)
            let colour_key = format!("{:?}", proto_dist.protocol);
            let colour = get_protocol_colour(&colour_key);
            // Use display_name() for user-facing trace names
            let display_name = proto_dist.protocol.display_name();

            let counts: Vec<f64> = proto_dist.buckets.iter().map(|b| b.count as f64).collect();

            let mut trace = PlotlyTrace::bar(x_labels.clone(), counts, display_name, colour);
            // Hide protocols with zero transactions by default
            if proto_dist.total_transactions == 0 {
                trace = trace.hidden_by_default();
            }
            traces.push(trace);
        }

        let mut layout = PlotlyLayout::basic(
            "P2MS Transaction Size Distribution by Protocol",
            "Transaction Size (bytes)",
            "Transaction Count",
        );
        // Rotate x-axis labels for readability
        layout.xaxis.tickangle = Some(-45);
        // Stack bars for per-protocol breakdown
        layout.barmode = Some("stack".to_string());

        PlotlyChart {
            data: traces,
            layout,
        }
    }

    /// Format size for display (e.g., 100000 -> "100K")
    fn format_size(bytes: u32) -> String {
        if bytes >= 1_000_000 {
            format!("{}M", bytes / 1_000_000)
        } else if bytes >= 1_000 {
            format!("{}K", bytes / 1_000)
        } else {
            bytes.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_assignment_boundaries() {
        // Test [min, max) semantics
        assert_eq!(TxSizeAnalyser::assign_bucket(0), 0); // [0, 250)
        assert_eq!(TxSizeAnalyser::assign_bucket(249), 0); // Just under boundary
        assert_eq!(TxSizeAnalyser::assign_bucket(250), 1); // [250, 500) - boundary crosses
        assert_eq!(TxSizeAnalyser::assign_bucket(499), 1);
        assert_eq!(TxSizeAnalyser::assign_bucket(500), 2); // [500, 1000)
        assert_eq!(TxSizeAnalyser::assign_bucket(999), 2);
        assert_eq!(TxSizeAnalyser::assign_bucket(1000), 3); // [1000, 2000)

        // Last bucket is open-ended [100000, ∞)
        assert_eq!(TxSizeAnalyser::assign_bucket(99_999), 8); // [50000, 100000)
        assert_eq!(TxSizeAnalyser::assign_bucket(100_000), 9); // [100000, ∞)
        assert_eq!(TxSizeAnalyser::assign_bucket(1_000_000), 9); // Large value
        assert_eq!(TxSizeAnalyser::assign_bucket(u32::MAX), 9); // Maximum
    }

    #[test]
    fn test_percentile_calculation_empty() {
        let mut sizes: Vec<u32> = Vec::new();
        let result = TxSizeAnalyser::calculate_percentiles(&mut sizes);
        assert!(result.is_none());
    }

    #[test]
    fn test_percentile_calculation_single() {
        let mut sizes = vec![1000];
        let result = TxSizeAnalyser::calculate_percentiles(&mut sizes);
        assert!(result.is_some());
        let p = result.unwrap();
        // All percentiles should be the same for single element
        assert_eq!(p.p25, 1000);
        assert_eq!(p.p50, 1000);
        assert_eq!(p.p75, 1000);
        assert_eq!(p.p90, 1000);
        assert_eq!(p.p95, 1000);
        assert_eq!(p.p99, 1000);
    }

    #[test]
    fn test_percentile_calculation_known_distribution() {
        // 100 values from 1 to 100
        let mut sizes: Vec<u32> = (1..=100).collect();
        let result = TxSizeAnalyser::calculate_percentiles(&mut sizes);
        assert!(result.is_some());
        let p = result.unwrap();

        // With 100 elements, indices are: (99 * p) / 100
        // p25: (99 * 25) / 100 = 24 → sizes[24] = 25
        // p50: (99 * 50) / 100 = 49 → sizes[49] = 50
        // p75: (99 * 75) / 100 = 74 → sizes[74] = 75
        // p90: (99 * 90) / 100 = 89 → sizes[89] = 90
        // p95: (99 * 95) / 100 = 94 → sizes[94] = 95
        // p99: (99 * 99) / 100 = 98 → sizes[98] = 99
        assert_eq!(p.p25, 25);
        assert_eq!(p.p50, 50);
        assert_eq!(p.p75, 75);
        assert_eq!(p.p90, 90);
        assert_eq!(p.p95, 95);
        assert_eq!(p.p99, 99);
    }

    #[test]
    fn test_init_buckets() {
        let buckets = TxSizeAnalyser::init_buckets();
        assert_eq!(buckets.len(), TX_SIZE_BUCKET_RANGES.len());

        // Verify first bucket
        assert_eq!(buckets[0].range_min, 0);
        assert_eq!(buckets[0].range_max, 250);
        assert_eq!(buckets[0].count, 0);
        assert_eq!(buckets[0].value, 0);

        // Verify last bucket (open-ended)
        let last = buckets.last().unwrap();
        assert_eq!(last.range_min, 100_000);
        assert_eq!(last.range_max, u32::MAX);
    }
}
