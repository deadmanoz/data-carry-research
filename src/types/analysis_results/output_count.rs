//! P2MS output count distribution analysis types

use super::common::OutputCountBucket;
use crate::types::ProtocolType;
use serde::{Deserialize, Serialize};

/// P2MS output count percentiles
///
/// Calculated using nearest-rank method: `sorted_vec[(n - 1) * p / 100]`
/// Percentiles are over output counts (not values).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OutputCountPercentiles {
    pub p25: u32,
    /// 50th percentile IS the median
    pub p50: u32,
    pub p75: u32,
    pub p90: u32,
    pub p95: u32,
    pub p99: u32,
}

/// Global P2MS output count distribution across all transactions
///
/// Analyses the current UTXO state (outputs with `is_spent = 0`), not
/// historical transaction structure. A transaction that originally created
/// 5 P2MS outputs, of which 3 are now spent, counts as having 2 outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalOutputCountDistribution {
    /// Total number of transactions with unspent P2MS outputs
    pub total_transactions: usize,
    /// Sum of all unspent P2MS output counts
    pub total_p2ms_outputs: usize,
    /// Sum of all unspent P2MS output values (satoshis)
    pub total_value_sats: u64,
    /// Histogram buckets
    pub buckets: Vec<OutputCountBucket>,
    /// Output count percentiles (None if empty dataset)
    pub percentiles: Option<OutputCountPercentiles>,
    /// Minimum output count observed (None if empty)
    pub min_output_count: Option<u32>,
    /// Maximum output count observed (None if empty)
    pub max_output_count: Option<u32>,
    /// Average output count per transaction (0.0 if empty)
    pub avg_output_count: f64,
}

/// Per-protocol P2MS output count distribution
///
/// NOTE ON MULTI-PROTOCOL TRANSACTIONS: A transaction classified under multiple
/// protocols (rare but possible) will be counted in EACH protocol's distribution.
/// This is expected behaviour matching the classification data model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolOutputCountDistribution {
    /// Protocol type (uses enum for type safety)
    pub protocol: ProtocolType,
    /// Total number of transactions for this protocol
    pub total_transactions: usize,
    /// Sum of P2MS output counts for this protocol
    pub total_p2ms_outputs: usize,
    /// Sum of P2MS output values (satoshis) for this protocol
    pub total_value_sats: u64,
    /// Histogram buckets
    pub buckets: Vec<OutputCountBucket>,
    /// Output count percentiles (None if empty dataset)
    pub percentiles: Option<OutputCountPercentiles>,
    /// Average output count per transaction (0.0 if empty)
    pub avg_output_count: f64,
}

/// Comprehensive P2MS output count distribution report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputCountDistributionReport {
    /// Global distribution across all transactions with unspent P2MS outputs
    pub global_distribution: GlobalOutputCountDistribution,
    /// Per-protocol distributions (sorted by canonical ProtocolType order)
    pub protocol_distributions: Vec<ProtocolOutputCountDistribution>,
    /// Transactions in global but not in any protocol (unclassified)
    /// Computed as `global.total_transactions.saturating_sub(sum_of_per_protocol)`
    pub unclassified_transaction_count: usize,
}
