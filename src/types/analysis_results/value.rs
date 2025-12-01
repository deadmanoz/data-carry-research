//! Value distribution analysis types

use super::common::ValueBucket;
use super::fees::{FeeAnalysisReport, ProtocolFeeStats};
use serde::{Deserialize, Serialize};

/// Comprehensive value distribution analysis across protocols
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ValueAnalysisReport {
    pub protocol_value_breakdown: Vec<ProtocolValueStats>,
    pub overall_statistics: OverallValueStats,
    pub fee_context: FeeAnalysisReport,
}

/// Value statistics for a specific protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolValueStats {
    pub protocol: String,
    pub output_count: usize,
    pub transaction_count: usize,
    pub total_btc_value_sats: u64,
    pub average_btc_per_output: f64,
    pub min_btc_value_sats: u64,
    pub max_btc_value_sats: u64,
    pub percentage_of_total_value: f64,
    pub fee_stats: ProtocolFeeStats,
}

/// Overall value statistics across all protocols
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OverallValueStats {
    pub total_outputs_analysed: usize,
    pub total_btc_locked_in_p2ms: u64,
    pub total_protocols: usize,
}

/// Protocol-specific value distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolValueDistribution {
    pub protocol: String,
    pub total_outputs: usize,
    pub total_value_sats: u64,
    pub buckets: Vec<ValueBucket>,
    pub percentiles: ValuePercentiles,
}

/// Value percentiles for statistical analysis
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ValuePercentiles {
    pub p25: u64, // 25th percentile
    pub p50: u64, // 50th percentile (median)
    pub p75: u64, // 75th percentile
    pub p90: u64, // 90th percentile
    pub p95: u64, // 95th percentile
    pub p99: u64, // 99th percentile
}

/// Comprehensive value distribution report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueDistributionReport {
    pub global_distribution: GlobalValueDistribution,
    pub protocol_distributions: Vec<ProtocolValueDistribution>,
    pub bucket_ranges: Vec<(u64, u64)>, // Standard bucket ranges used
}

/// Global value distribution across all P2MS outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalValueDistribution {
    pub total_outputs: usize,
    pub total_value_sats: u64,
    pub buckets: Vec<ValueBucket>,
    pub percentiles: ValuePercentiles,
    pub min_value: u64,
    pub max_value: u64,
    pub mean_value: f64,
    pub median_value: u64,
}
