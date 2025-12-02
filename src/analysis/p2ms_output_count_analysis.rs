//! P2MS output count distribution analysis
//!
//! This module provides analysis of the number of P2MS outputs per transaction
//! to help understand data embedding patterns across protocols. Reports histogram
//! distributions and percentiles for both global and per-protocol breakdowns.
//!
//! **Scope**: Analyses the current UTXO state (outputs with `is_spent = 0`), not
//! historical transaction structure. A transaction that originally created 5 P2MS
//! outputs, of which 3 are now spent, counts as having 2 outputs.

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    GlobalOutputCountDistribution, OutputCountBucket, OutputCountDistributionReport,
    OutputCountPercentiles, ProtocolOutputCountDistribution,
};
use crate::types::visualisation::{get_protocol_colour, PlotlyChart, PlotlyLayout, PlotlyTrace};
use crate::types::ProtocolType;
use std::str::FromStr;

/// P2MS output count buckets - single source of truth
/// Bucket semantics: [min, max) - inclusive min, exclusive max.
/// Last bucket is [101, ∞) - open-ended.
pub const OUTPUT_COUNT_BUCKET_RANGES: &[(u32, u32)] = &[
    (1, 2),          // [1, 2) = exactly 1 output
    (2, 3),          // [2, 3) = exactly 2 outputs
    (3, 4),          // [3, 4) = exactly 3 outputs
    (4, 6),          // [4, 6) = 4-5 outputs
    (6, 11),         // [6, 11) = 6-10 outputs
    (11, 21),        // [11, 21) = 11-20 outputs
    (21, 51),        // [21, 51) = 21-50 outputs
    (51, 101),       // [51, 101) = 51-100 outputs
    (101, u32::MAX), // [101, ∞) = 101+ outputs (u32::MAX as sentinel)
];

/// Analyse P2MS output count distribution across all transactions
///
/// Returns histogram data suitable for understanding data embedding patterns:
/// - Global distribution across all transactions with unspent P2MS outputs
/// - Per-protocol distributions (sorted by canonical ProtocolType order)
/// - Percentiles for output count distribution analysis
///
/// # Arguments
/// * `db` - Database connection
///
/// # Returns
/// * `AppResult<OutputCountDistributionReport>` - Comprehensive output count distribution
pub fn analyse_output_counts(db: &Database) -> AppResult<OutputCountDistributionReport> {
    let conn = db.connection();

    // Global aggregates - count P2MS outputs per transaction
    let mut stmt = conn.prepare(
        "SELECT
                txid,
                COUNT(*) as p2ms_count,
                SUM(amount) as total_value
            FROM transaction_outputs
            WHERE is_spent = 0
              AND script_type = 'multisig'
            GROUP BY txid",
    )?;

    let mut counts: Vec<u32> = Vec::new();
    let mut buckets = init_buckets();
    let mut total_transactions = 0usize;
    let mut total_p2ms_outputs = 0usize;
    let mut total_value_sats = 0u64;
    let mut min_output_count: Option<u32> = None;
    let mut max_output_count: Option<u32> = None;

    let rows = stmt.query_map([], |row| {
        let p2ms_count = row.get::<_, i64>(1)? as u32;
        let value = row.get::<_, i64>(2)? as u64;
        Ok((p2ms_count, value))
    })?;

    for row_result in rows {
        let (p2ms_count, value) = row_result?;
        counts.push(p2ms_count);
        total_transactions += 1;
        total_p2ms_outputs += p2ms_count as usize;
        total_value_sats += value;

        // Track min/max
        min_output_count = Some(min_output_count.map_or(p2ms_count, |m| m.min(p2ms_count)));
        max_output_count = Some(max_output_count.map_or(p2ms_count, |m| m.max(p2ms_count)));

        // Assign to bucket
        let bucket_idx = assign_bucket(p2ms_count);
        buckets[bucket_idx].count += 1;
        buckets[bucket_idx].value += value;
    }

    // Compute bucket percentages after aggregation
    for bucket in &mut buckets {
        bucket.compute_percentages(total_transactions, total_value_sats);
    }

    // Calculate percentiles
    let percentiles = calculate_percentiles(&mut counts);

    // Calculate average
    let avg_output_count = if total_transactions > 0 {
        total_p2ms_outputs as f64 / total_transactions as f64
    } else {
        0.0
    };

    let global_distribution = GlobalOutputCountDistribution {
        total_transactions,
        total_p2ms_outputs,
        total_value_sats,
        buckets,
        percentiles,
        min_output_count,
        max_output_count,
        avg_output_count,
    };

    // Per-protocol distributions
    let protocol_distributions = analyse_per_protocol(conn)?;

    // Calculate unclassified count (guard against underflow with saturating_sub)
    let sum_of_per_protocol: usize = protocol_distributions
        .iter()
        .map(|d| d.total_transactions)
        .sum();
    let unclassified_transaction_count = total_transactions.saturating_sub(sum_of_per_protocol);

    Ok(OutputCountDistributionReport {
        global_distribution,
        protocol_distributions,
        unclassified_transaction_count,
    })
}

/// Initialise empty buckets from the constant ranges
fn init_buckets() -> Vec<OutputCountBucket> {
    OUTPUT_COUNT_BUCKET_RANGES
        .iter()
        .map(|(min, max)| OutputCountBucket::new_zeroed(*min, *max))
        .collect()
}

/// Assign an output count to a bucket index
///
/// Bucket semantics: [min, max) - uses `count >= min && count < max`
/// Last bucket is [101, ∞) - uses `count >= 101` (no upper bound check)
/// Note: Comparator is `<` not `<=` to avoid off-by-one with u32::MAX
pub fn assign_bucket(count: u32) -> usize {
    OUTPUT_COUNT_BUCKET_RANGES
        .iter()
        .enumerate()
        .find_map(|(i, (min, max))| {
            let is_last = i == OUTPUT_COUNT_BUCKET_RANGES.len() - 1;
            if count >= *min && (is_last || count < *max) {
                Some(i)
            } else {
                None
            }
        })
        .expect("bucket ranges must cover all u32 values >= 1")
}

/// Calculate percentiles using nearest-rank method
///
/// Returns None for empty datasets.
/// Formula: `sorted_vec[(n - 1) * p / 100]`
pub fn calculate_percentiles(counts: &mut [u32]) -> Option<OutputCountPercentiles> {
    if counts.is_empty() {
        return None;
    }

    counts.sort_unstable();
    let n = counts.len();

    // Percentile calculation: index = (n - 1) * p / 100
    let p25_idx = (n - 1) * 25 / 100;
    let p50_idx = (n - 1) * 50 / 100;
    let p75_idx = (n - 1) * 75 / 100;
    let p90_idx = (n - 1) * 90 / 100;
    let p95_idx = (n - 1) * 95 / 100;
    let p99_idx = (n - 1) * 99 / 100;

    Some(OutputCountPercentiles {
        p25: counts[p25_idx],
        p50: counts[p50_idx],
        p75: counts[p75_idx],
        p90: counts[p90_idx],
        p95: counts[p95_idx],
        p99: counts[p99_idx],
    })
}

/// Analyse per-protocol P2MS output count distributions
fn analyse_per_protocol(
    conn: &rusqlite::Connection,
) -> AppResult<Vec<ProtocolOutputCountDistribution>> {
    // Get list of protocols with P2MS transactions
    let mut proto_stmt = conn.prepare(
        "SELECT DISTINCT tc.protocol
            FROM transaction_classifications tc
            INNER JOIN transaction_outputs o ON tc.txid = o.txid
            WHERE o.is_spent = 0
              AND o.script_type = 'multisig'
            ORDER BY tc.protocol",
    )?;

    let protocols: Vec<String> = proto_stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    let mut distributions: Vec<ProtocolOutputCountDistribution> = Vec::new();

    for protocol_str in protocols {
        // Parse protocol string to enum
        let protocol = match ProtocolType::from_str(&protocol_str) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "Unknown protocol string in output count analysis: {}",
                    protocol_str
                );
                ProtocolType::Unknown
            }
        };

        // Query per-protocol data (DISTINCT subquery guards against duplicate classifications)
        let mut stmt = conn.prepare(
            "SELECT
                    o.txid,
                    COUNT(*) AS p2ms_count,
                    SUM(o.amount) AS total_value
                FROM transaction_outputs o
                INNER JOIN (
                    SELECT DISTINCT txid FROM transaction_classifications WHERE protocol = ?
                ) tc ON o.txid = tc.txid
                WHERE o.is_spent = 0
                  AND o.script_type = 'multisig'
                GROUP BY o.txid",
        )?;

        let mut counts: Vec<u32> = Vec::new();
        let mut buckets = init_buckets();
        let mut total_transactions = 0usize;
        let mut total_p2ms_outputs = 0usize;
        let mut total_value_sats = 0u64;

        let rows = stmt.query_map([&protocol_str], |row| {
            let p2ms_count = row.get::<_, i64>(1)? as u32;
            let value = row.get::<_, i64>(2)? as u64;
            Ok((p2ms_count, value))
        })?;

        for row_result in rows {
            let (p2ms_count, value) = row_result?;
            counts.push(p2ms_count);
            total_transactions += 1;
            total_p2ms_outputs += p2ms_count as usize;
            total_value_sats += value;

            let bucket_idx = assign_bucket(p2ms_count);
            buckets[bucket_idx].count += 1;
            buckets[bucket_idx].value += value;
        }

        // Compute bucket percentages after aggregation
        for bucket in &mut buckets {
            bucket.compute_percentages(total_transactions, total_value_sats);
        }

        let percentiles = calculate_percentiles(&mut counts);

        let avg_output_count = if total_transactions > 0 {
            total_p2ms_outputs as f64 / total_transactions as f64
        } else {
            0.0
        };

        distributions.push(ProtocolOutputCountDistribution {
            protocol,
            total_transactions,
            total_p2ms_outputs,
            total_value_sats,
            buckets,
            percentiles,
            avg_output_count,
        });
    }

    // Sort by canonical ProtocolType enum discriminant order
    distributions.sort_by_key(|d| d.protocol as u8);

    Ok(distributions)
}

impl OutputCountDistributionReport {
    /// Convert report to Plotly-native JSON format
    ///
    /// Produces a stacked bar chart showing transaction counts per output count bucket with:
    /// - X-axis: Output count bucket labels (e.g., "1", "2", "3", "4-5", ..., "101+")
    /// - Y-axis: Transaction count per bucket (stacked by protocol)
    /// - "All P2MS Transactions" trace (hidden by default, can be toggled via legend)
    pub fn to_plotly_chart(&self) -> PlotlyChart {
        // Generate bucket labels for x-axis
        let x_labels: Vec<String> = OUTPUT_COUNT_BUCKET_RANGES
            .iter()
            .map(|(min, max)| Self::bucket_label(*min, *max))
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
            let colour = get_protocol_colour(proto_dist.protocol);
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
            "P2MS Output Count Distribution by Protocol",
            "P2MS Outputs per Transaction",
            "Transaction Count",
        )
        .with_legend("v", 1.02, 1.0, "left");
        // Rotate x-axis labels for readability
        layout.xaxis.tickangle = Some(-45);
        // Stack bars for per-protocol breakdown
        layout.barmode = Some("stack".to_string());

        PlotlyChart {
            data: traces,
            layout,
        }
    }

    /// Generate a human-readable label for a bucket range
    pub fn bucket_label(min: u32, max: u32) -> String {
        if min + 1 == max {
            // Single value: "1", "2", "3"
            format!("{}", min)
        } else if max == u32::MAX {
            // Open-ended: "101+"
            format!("{}+", min)
        } else {
            // Range: "4-5", "6-10"
            format!("{}-{}", min, max - 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_assignment_single_output() {
        assert_eq!(assign_bucket(1), 0); // [1, 2) = exactly 1
    }

    #[test]
    fn test_bucket_assignment_boundary_2() {
        assert_eq!(assign_bucket(2), 1); // [2, 3) = exactly 2
    }

    #[test]
    fn test_bucket_assignment_boundary_3() {
        assert_eq!(assign_bucket(3), 2); // [3, 4) = exactly 3
    }

    #[test]
    fn test_bucket_assignment_boundary_4() {
        assert_eq!(assign_bucket(4), 3); // [4, 6) = 4-5
    }

    #[test]
    fn test_bucket_assignment_boundary_5() {
        assert_eq!(assign_bucket(5), 3); // [4, 6) = 4-5
    }

    #[test]
    fn test_bucket_assignment_boundary_6() {
        assert_eq!(assign_bucket(6), 4); // [6, 11) = 6-10
    }

    #[test]
    fn test_bucket_assignment_boundary_10() {
        assert_eq!(assign_bucket(10), 4); // [6, 11) = 6-10
    }

    #[test]
    fn test_bucket_assignment_boundary_11() {
        assert_eq!(assign_bucket(11), 5); // [11, 21) = 11-20
    }

    #[test]
    fn test_bucket_assignment_boundary_101() {
        assert_eq!(assign_bucket(101), 8); // [101, ∞) = 101+
    }

    #[test]
    fn test_bucket_assignment_large() {
        assert_eq!(assign_bucket(1000), 8); // [101, ∞)
        assert_eq!(assign_bucket(u32::MAX), 8); // Maximum
    }

    #[test]
    fn test_percentile_calculation_empty() {
        let mut counts: Vec<u32> = Vec::new();
        let result = calculate_percentiles(&mut counts);
        assert!(result.is_none());
    }

    #[test]
    fn test_percentile_calculation_single() {
        let mut counts = vec![5];
        let result = calculate_percentiles(&mut counts);
        assert!(result.is_some());
        let p = result.unwrap();
        // All percentiles should be the same for single element
        assert_eq!(p.p25, 5);
        assert_eq!(p.p50, 5);
        assert_eq!(p.p75, 5);
        assert_eq!(p.p90, 5);
        assert_eq!(p.p95, 5);
        assert_eq!(p.p99, 5);
    }

    #[test]
    fn test_percentile_calculation_ordered() {
        // Crafted data with distinct values to ensure strictly increasing percentiles
        let mut counts: Vec<u32> = (1..=100).collect();
        let result = calculate_percentiles(&mut counts);
        assert!(result.is_some());
        let p = result.unwrap();

        // With 100 elements, indices are: (99 * p) / 100
        // p25: (99 * 25) / 100 = 24 → counts[24] = 25
        // p50: (99 * 50) / 100 = 49 → counts[49] = 50
        // p75: (99 * 75) / 100 = 74 → counts[74] = 75
        // p90: (99 * 90) / 100 = 89 → counts[89] = 90
        // p95: (99 * 95) / 100 = 94 → counts[94] = 95
        // p99: (99 * 99) / 100 = 98 → counts[98] = 99
        assert_eq!(p.p25, 25);
        assert_eq!(p.p50, 50);
        assert_eq!(p.p75, 75);
        assert_eq!(p.p90, 90);
        assert_eq!(p.p95, 95);
        assert_eq!(p.p99, 99);

        // Verify strictly increasing (with crafted data this should hold)
        assert!(p.p25 < p.p50);
        assert!(p.p50 < p.p75);
        assert!(p.p75 < p.p90);
        assert!(p.p90 < p.p95);
        assert!(p.p95 < p.p99);
    }

    #[test]
    fn test_bucket_label_single() {
        assert_eq!(OutputCountDistributionReport::bucket_label(1, 2), "1");
        assert_eq!(OutputCountDistributionReport::bucket_label(2, 3), "2");
        assert_eq!(OutputCountDistributionReport::bucket_label(3, 4), "3");
    }

    #[test]
    fn test_bucket_label_range() {
        assert_eq!(OutputCountDistributionReport::bucket_label(4, 6), "4-5");
        assert_eq!(OutputCountDistributionReport::bucket_label(6, 11), "6-10");
        assert_eq!(OutputCountDistributionReport::bucket_label(11, 21), "11-20");
    }

    #[test]
    fn test_bucket_label_open_ended() {
        assert_eq!(
            OutputCountDistributionReport::bucket_label(101, u32::MAX),
            "101+"
        );
    }

    #[test]
    fn test_bucket_counts_sum() {
        // Verify that buckets cover the expected ranges
        let buckets = init_buckets();
        assert_eq!(buckets.len(), OUTPUT_COUNT_BUCKET_RANGES.len());
        assert_eq!(buckets.len(), 9);

        // All buckets should start with zero counts
        for bucket in &buckets {
            assert_eq!(bucket.count, 0);
            assert_eq!(bucket.value, 0);
        }
    }
}
