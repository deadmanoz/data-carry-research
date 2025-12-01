//! Dust threshold analysis types

use crate::types::ProtocolType;
use crate::utils::math::{safe_percentage, safe_percentage_u64};
use serde::{Deserialize, Serialize};

/// Sentinel value used to distinguish truly unclassified outputs from classified-as-Unknown
/// This value cannot collide with any real protocol string in ProtocolType
pub const UNCLASSIFIED_SENTINEL: &str = "__UNCLASSIFIED_SENTINEL__";

/// Dust threshold analysis report
///
/// Reports on P2MS outputs below Bitcoin Core's dust limits when spending to different
/// destination types. These are *spending* thresholds (determined by destination output type),
/// NOT creation-time P2MS dust limits (which vary with m-of-n configuration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DustAnalysisReport {
    /// Dust threshold constants used in this analysis
    pub thresholds: DustThresholds,
    /// Global statistics across all P2MS outputs
    pub global_stats: GlobalDustStats,
    /// Per-protocol breakdown (sorted by canonical ProtocolType enum order)
    pub protocol_breakdown: Vec<ProtocolDustStats>,
    /// Reconciliation: sum of all protocol output counts
    pub classified_outputs_total: usize,
    /// Outputs in global but not in any protocol classification (Stage 3 incomplete)
    pub unclassified_count: usize,
    /// Total value of unclassified outputs in satoshis
    pub unclassified_value_sats: u64,
}

/// Dust threshold constants with clear semantics
///
/// Bitcoin Core calculates dust as: output_size + assumed_input_size (148 bytes for non-segwit,
/// 98 bytes for segwit) × dustRelayFeeIn (3 sat/vB by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DustThresholds {
    /// 546 sats - dust when spending to non-segwit (P2PKH) destination
    /// Calculated as: (182 bytes × 3 sat/vB) for typical non-segwit output + input
    pub non_segwit_destination_sats: u64,
    /// 294 sats - dust when spending to segwit (P2WPKH) destination
    /// Calculated as: (98 bytes × 3 sat/vB) for typical segwit output + input
    pub segwit_destination_sats: u64,
}

impl Default for DustThresholds {
    fn default() -> Self {
        Self {
            non_segwit_destination_sats: 546,
            segwit_destination_sats: 294,
        }
    }
}

/// Global dust statistics across all P2MS outputs
///
/// Uses cumulative buckets: below_segwit_threshold is a subset of below_non_segwit_threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalDustStats {
    /// Total number of unspent P2MS outputs analysed
    pub total_outputs: usize,
    /// Total value of all outputs in satoshis
    pub total_value_sats: u64,
    /// Below 546 sats - dust if spending to non-segwit destination (cumulative)
    pub below_non_segwit_threshold: DustBucket,
    /// Below 294 sats - dust if spending to ANY destination (subset of above)
    pub below_segwit_threshold: DustBucket,
    /// >= 546 sats - not dust for any destination type
    pub above_dust: DustBucket,
}

/// Dust threshold bucket (threshold-based, NOT histogram)
///
/// **IMPORTANT**: This is NOT a histogram bucket. It represents cumulative
/// counts below/above fixed thresholds:
/// - `below_segwit_threshold`: outputs < 294 sats (subset of below_non_segwit)
/// - `below_non_segwit_threshold`: outputs < 546 sats
/// - `above_dust`: outputs >= 546 sats
///
/// Do NOT treat as ranged buckets - these are cumulative categories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DustBucket {
    /// Number of outputs in this bucket
    pub count: usize,
    /// Total value of outputs in this bucket (satoshis)
    pub value: u64,
    /// Percentage of total outputs in this bucket
    pub pct_count: f64,
    /// Percentage of total value in this bucket
    pub pct_value: f64,
}

impl DustBucket {
    /// Create a new dust bucket with computed percentages
    pub fn new(count: usize, value: u64, total_count: usize, total_value: u64) -> Self {
        Self {
            count,
            value,
            pct_count: safe_percentage(count, total_count),
            pct_value: safe_percentage_u64(value, total_value),
        }
    }
}

/// Per-protocol dust statistics using typed protocol enum
///
/// Sorted by canonical ProtocolType enum discriminant order for stable output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDustStats {
    /// Protocol type (uses enum for type safety)
    pub protocol: ProtocolType,
    /// Total number of outputs for this protocol
    pub total_outputs: usize,
    /// Total value for this protocol in satoshis
    pub total_value_sats: u64,
    /// Below 546 sats (cumulative)
    pub below_non_segwit_threshold: DustBucket,
    /// Below 294 sats (subset of above)
    pub below_segwit_threshold: DustBucket,
    /// >= 546 sats
    pub above_dust: DustBucket,
}
