//! Transaction size distribution analysis types

use super::common::TxSizeBucket;
use crate::types::ProtocolType;
use serde::{Deserialize, Serialize};

/// Transaction size percentiles
///
/// Calculated using in-memory sort: `sorted_vec[(n - 1) * p / 100]`
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TxSizePercentiles {
    pub p25: u32,
    /// 50th percentile IS the median
    pub p50: u32,
    pub p75: u32,
    pub p90: u32,
    pub p95: u32,
    pub p99: u32,
}

/// Global transaction size distribution across all P2MS transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalTxSizeDistribution {
    /// Total number of transactions analysed
    pub total_transactions: usize,
    /// Sum of all transaction fees (satoshis)
    pub total_fees_sats: u64,
    /// Sum of all transaction sizes (bytes) - for average calculation
    pub total_size_bytes: u64,
    /// Histogram buckets
    pub buckets: Vec<TxSizeBucket>,
    /// Size percentiles (None if empty dataset)
    pub percentiles: Option<TxSizePercentiles>,
    /// Minimum transaction size observed (None if empty)
    pub min_size_bytes: Option<u32>,
    /// Maximum transaction size observed (None if empty)
    pub max_size_bytes: Option<u32>,
    /// Average transaction size (0.0 if empty)
    pub avg_size_bytes: f64,
    /// Count of excluded transactions (NULL/zero size or NULL fee)
    pub excluded_null_count: usize,
}

/// Protocol-specific transaction size distribution
///
/// NOTE ON FEE TOTALS: A transaction classified under multiple protocols
/// (e.g., both Stamps and Counterparty) will have its fees counted in EACH
/// protocol's total_fees_sats. This is intentional - it shows the fee cost
/// associated with transactions containing each protocol. The global
/// total_fees_sats is the true deduplicated total. Per-protocol fees
/// should NOT be summed to compare against global total.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTxSizeDistribution {
    /// Protocol type (uses enum for type safety)
    pub protocol: ProtocolType,
    /// Total number of transactions for this protocol
    pub total_transactions: usize,
    /// Sum of fees (may double-count for multi-protocol transactions)
    pub total_fees_sats: u64,
    /// Histogram buckets
    pub buckets: Vec<TxSizeBucket>,
    /// Size percentiles (None if empty dataset)
    pub percentiles: Option<TxSizePercentiles>,
    /// Average transaction size (0.0 if empty)
    pub avg_size_bytes: f64,
    /// Average fee per byte (0.0 if total_size_bytes == 0)
    pub avg_fee_per_byte: f64,
    /// Count of excluded transactions for this protocol
    pub excluded_null_count: usize,
}

/// Comprehensive transaction size distribution report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSizeDistributionReport {
    /// Global distribution across all P2MS transactions
    pub global_distribution: GlobalTxSizeDistribution,
    /// Per-protocol distributions (sorted by canonical ProtocolType order)
    pub protocol_distributions: Vec<ProtocolTxSizeDistribution>,
}
