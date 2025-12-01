//! Analysis result types and data structures
//!
//! This module defines the comprehensive data structures returned by various
//! analysis operations, replacing the raw SQL output with structured, type-safe results.

use crate::types::ProtocolType;
use crate::utils::math::{safe_percentage, safe_percentage_u64};
use serde::{Deserialize, Serialize};

/// Comprehensive burn pattern analysis results
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BurnPatternAnalysis {
    pub total_patterns: usize,
    pub pattern_breakdown: Vec<PatternTypeStats>,
    pub sample_patterns: Vec<BurnPatternSample>,
}

/// Statistics for a specific burn pattern type
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PatternTypeStats {
    pub pattern_type: String,
    pub count: usize,
    pub percentage: f64,
}

/// Sample burn pattern with transaction context
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BurnPatternSample {
    pub txid: String,
    pub pattern_type: String,
    pub pattern_data: String,
    pub vout: u32,
    pub pubkey_index: usize,
}

/// Comprehensive fee analysis report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FeeAnalysisReport {
    pub total_transactions: usize,
    pub coinbase_transactions: usize,
    pub regular_transactions: usize,
    pub fee_statistics: FeeStatistics,
    pub storage_cost_analysis: StorageCostAnalysis,
}

/// Detailed fee statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FeeStatistics {
    pub total_fees_paid: u64,
    pub average_fee: f64,
    pub median_fee_per_byte: f64,
    pub average_storage_cost: f64,
}

/// Storage cost analysis for P2MS data
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StorageCostAnalysis {
    pub total_p2ms_data_bytes: usize,
    pub average_cost_per_byte: f64,
}

/// Protocol classification statistics report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClassificationStatsReport {
    pub total_classified: usize,
    pub protocol_breakdown: ProtocolBreakdown,
    pub signature_detection_rates: SignatureDetectionStats,
    pub sample_classifications: Vec<ClassificationSample>,
}

/// Breakdown of classifications by protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolBreakdown {
    pub bitcoin_stamps: ProtocolStats,
    pub counterparty: ProtocolStats,
    pub ascii_identifier_protocols: ProtocolStats,
    pub omni_layer: ProtocolStats,
    pub chancecoin: ProtocolStats,
    pub ppk: ProtocolStats,
    pub opreturn_signalled: ProtocolStats,
    pub data_storage: ProtocolStats,
    pub likely_data_storage: ProtocolStats,
    pub likely_legitimate: ProtocolStats,
    pub unknown: ProtocolStats,
}

/// Statistics for a specific protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolStats {
    pub count: usize,
    pub percentage: f64,
    pub variants: Vec<VariantStats>,
}

/// Statistics for protocol variants
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VariantStats {
    pub variant: String,
    pub count: usize,
    pub classification_method: String,
}

/// Signature detection statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignatureDetectionStats {
    pub definitive_signatures: usize,
    pub signature_percentage: f64,
    pub method_breakdown: Vec<MethodStats>,
}

/// Statistics for classification methods
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MethodStats {
    pub method: String,
    pub count: usize,
    pub percentage: f64,
}

/// Sample classification result
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClassificationSample {
    pub protocol: String,
    pub variant: String,
    pub classification_method: String,
    pub count: usize,
}

/// Signature analysis comprehensive report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignatureAnalysisReport {
    pub classification_methods: Vec<MethodStats>,
    pub burn_pattern_analysis: BurnPatternCorrelation,
    pub confidence_analysis: ConfidenceStats,
}

/// Correlation between burn patterns and protocol classifications
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BurnPatternCorrelation {
    pub correlations: Vec<PatternProtocolCorrelation>,
}

/// Correlation data between pattern and protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PatternProtocolCorrelation {
    pub protocol: String,
    pub burn_patterns_count: usize,
    pub transactions: usize,
}

/// Classification confidence statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConfidenceStats {
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
}

/// Spendability analysis comprehensive report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SpendabilityStatsReport {
    pub overall: OverallSpendability,
    pub protocol_breakdown: Vec<ProtocolSpendabilityStats>,
    pub reason_distribution: Vec<ReasonStats>,
    pub key_count_distribution: KeyCountDistribution,
    pub transaction_level: TransactionSpendabilityStats,
}

/// Overall spendability breakdown
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OverallSpendability {
    pub total_outputs: usize,
    pub spendable_count: usize,
    pub spendable_percentage: f64,
    pub unspendable_count: usize,
    pub unspendable_percentage: f64,
}

/// Per-protocol spendability statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolSpendabilityStats {
    pub protocol: String,
    pub total_outputs: usize,
    pub spendable_count: usize,
    pub spendable_percentage: f64,
    pub unspendable_count: usize,
    pub unspendable_percentage: f64,
}

/// Spendability reason distribution
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReasonStats {
    pub reason: String,
    pub count: usize,
    pub percentage: f64,
}

/// Key count distribution statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyCountDistribution {
    pub real_pubkey_stats: KeyCountStats,
    pub burn_key_stats: KeyCountStats,
    pub data_key_stats: KeyCountStats,
}

/// Statistics for a specific key count type
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyCountStats {
    pub total: u64,
    pub average: f64,
    pub min: u8,
    pub max: u8,
}

/// Transaction-level spendability statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TransactionSpendabilityStats {
    pub total_transactions: usize,
    pub transactions_with_spendable_outputs: usize,
    pub transactions_all_unspendable: usize,
    pub spendable_transaction_percentage: f64,
}

/// File extension analysis report summarizing stored payload formats
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FileExtensionReport {
    pub total_transactions: usize,
    pub total_outputs: usize,
    pub total_bytes: u64,
    pub categories: Vec<CategoryBreakdown>,
}

/// Aggregated statistics for a single content category (Images, Documents, ...)
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CategoryBreakdown {
    pub category: String,
    pub extensions: Vec<ExtensionStats>,
    pub category_totals: CategoryTotals,
}

/// Statistics for a specific file extension within a category
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ExtensionStats {
    pub extension: String,
    pub transaction_count: usize,
    pub output_count: usize,
    pub total_bytes: u64,
    pub transaction_percentage: f64,
    pub output_percentage: f64,
    pub byte_percentage: f64,
}

/// Totals for a content category used for percentage calculations
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CategoryTotals {
    pub transaction_count: usize,
    pub output_count: usize,
    pub total_bytes: u64,
    pub transaction_percentage: f64,
    pub output_percentage: f64,
    pub byte_percentage: f64,
}

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

/// Fee statistics for a specific protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolFeeStats {
    pub total_fees_paid_sats: u64,
    pub average_fee_sats: f64,
    pub average_fee_per_byte: f64,
    pub average_storage_cost_per_byte: f64,
}

/// Overall value statistics across all protocols
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OverallValueStats {
    pub total_outputs_analysed: usize,
    pub total_btc_locked_in_p2ms: u64,
    pub total_protocols: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Data Size Analysis Types
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol-level data size report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDataSizeReport {
    pub total_bytes: u64,
    pub total_outputs: usize,
    pub total_transactions: usize,
    pub protocols: Vec<ProtocolDataSize>,
}

/// Per-protocol data size statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDataSize {
    pub protocol: String,
    pub variant: Option<String>,
    pub output_count: usize,
    pub transaction_count: usize,
    pub total_bytes: u64,
    pub average_bytes: f64,
    pub min_bytes: u64,
    pub max_bytes: u64,
    pub percentage_of_total: f64,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
    pub spendable_percentage: f64,
}

/// Spendability-focused data size report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendabilityDataSizeReport {
    pub overall: SpendabilityDataMetrics,
    pub by_protocol: Vec<ProtocolSpendabilityData>,
    pub by_reason: Vec<ReasonSpendabilityData>,
}

/// Overall spendability data metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendabilityDataMetrics {
    pub total_bytes: u64,
    pub total_transactions: usize,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
    pub spendable_percentage: f64,
    pub spendable_output_count: usize,
    pub unspendable_output_count: usize,
}

/// Per-protocol spendability data breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSpendabilityData {
    pub protocol: String,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
    pub spendable_output_count: usize,
    pub unspendable_output_count: usize,
}

/// Per-reason spendability data statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonSpendabilityData {
    pub reason: String,
    pub output_count: usize,
    pub total_bytes: u64,
    pub percentage_of_total: f64,
}

/// Content type with spendability cross-analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeSpendabilityReport {
    pub total_bytes: u64,
    pub total_transactions: usize,
    pub categories: Vec<CategorySpendabilityData>,
}

/// Category-level spendability data aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySpendabilityData {
    pub category: String,
    pub content_types: Vec<ContentTypeData>,
    pub category_totals: CategoryDataMetrics,
}

/// Per-content-type data with spendability metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeData {
    pub mime_type: String,
    pub extension: String,
    pub transaction_count: usize,
    pub output_count: usize,
    pub total_bytes: u64,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
    pub spendable_percentage: f64,
}

/// Category-level aggregated metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryDataMetrics {
    pub transaction_count: usize,
    pub output_count: usize,
    pub total_bytes: u64,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
}

/// Comprehensive data size report combining all dimensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveDataSizeReport {
    pub overall_summary: OverallDataSummary,
    pub protocol_breakdown: ProtocolDataSizeReport,
    pub spendability_breakdown: SpendabilityDataSizeReport,
    pub content_type_breakdown: ContentTypeSpendabilityReport,
}

/// Overall data size summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallDataSummary {
    pub total_p2ms_bytes: u64,
    pub total_outputs: usize,
    pub total_transactions: usize,
    pub average_bytes_per_output: f64,
    pub spendable_percentage: f64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Generic Distribution Bucket
// ═══════════════════════════════════════════════════════════════════════════

/// Generic histogram bucket for distribution analysis
///
/// Bucket semantics: [range_min, range_max) - inclusive min, exclusive max.
/// Last bucket is open-ended: [range_min, ∞) when range_max == T::MAX.
///
/// The `value` field always represents satoshis:
/// - For ValueBucket: total output value in satoshis
/// - For TxSizeBucket: total transaction fees in satoshis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionBucket<T: Copy> {
    /// Lower bound of bucket range (inclusive)
    pub range_min: T,
    /// Upper bound of bucket range (exclusive, except last bucket)
    pub range_max: T,
    /// Number of items in this bucket
    pub count: usize,
    /// Aggregate satoshis (output values for ValueBucket, fees for TxSizeBucket)
    pub value: u64,
    /// Percentage of total count
    pub pct_count: f64,
    /// Percentage of total value
    pub pct_value: f64,
}

impl<T: Copy> DistributionBucket<T> {
    /// Create a new bucket with computed percentages
    ///
    /// Percentages are computed using `safe_percentage*` which returns 0.0
    /// when totals are zero (no NaN or division-by-zero).
    pub fn new(
        range_min: T,
        range_max: T,
        count: usize,
        value: u64,
        total_count: usize,
        total_value: u64,
    ) -> Self {
        Self {
            range_min,
            range_max,
            count,
            value,
            pct_count: safe_percentage(count, total_count),
            pct_value: safe_percentage_u64(value, total_value),
        }
    }

    /// Create a zeroed bucket for streaming aggregation
    ///
    /// Use when accumulating counts/values before totals are known.
    /// Call `compute_percentages()` after aggregation is complete.
    pub fn new_zeroed(range_min: T, range_max: T) -> Self {
        Self {
            range_min,
            range_max,
            count: 0,
            value: 0,
            pct_count: 0.0,
            pct_value: 0.0,
        }
    }

    /// Compute percentages after streaming aggregation
    pub fn compute_percentages(&mut self, total_count: usize, total_value: u64) {
        self.pct_count = safe_percentage(self.count, total_count);
        self.pct_value = safe_percentage_u64(self.value, total_value);
    }
}

/// Type alias for satoshi value distributions (range bounds in satoshis)
pub type ValueBucket = DistributionBucket<u64>;

/// Type alias for transaction size distributions (range bounds in bytes)
pub type TxSizeBucket = DistributionBucket<u32>;

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

/// Comprehensive analysis report containing all analysis types
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FullAnalysisReport {
    pub burn_patterns: BurnPatternAnalysis,
    pub fee_analysis: FeeAnalysisReport,
    pub classifications: ClassificationStatsReport,
    pub signatures: SignatureAnalysisReport,
    pub spendability: SpendabilityStatsReport,

    /// File extension + data size breakdown (Stage 3 content analysis)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_extensions: Option<FileExtensionReport>,

    /// Bitcoin Stamps transport mechanism breakdown
    /// Added in v2.0 - backward compatible via Option + serde(default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamps_transport: Option<StampsTransportAnalysis>,

    /// Bitcoin Stamps signature variant distribution
    /// Added in v2.1 - backward compatible via Option + serde(default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stamps_signatures: Option<StampsSignatureAnalysis>,

    /// Comprehensive data size analysis
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_size: Option<ComprehensiveDataSizeReport>,

    pub generated_at: String,
}

/// Individual multisig configuration entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigConfiguration {
    pub m: u32,                   // Required signatures
    pub n: u32,                   // Total keys
    pub key_config: String,       // e.g., "CCC", "CCU", "CUU", "UUU"
    pub script_size: u32,         // Total script size in bytes
    pub data_capacity_bytes: u32, // Actual data-carrying capacity
    pub efficiency_pct: f64,      // data_capacity / script_size * 100
    pub output_count: u64,        // Number of outputs with this configuration
    pub total_script_bytes: u64,  // Total blockchain footprint
    pub protocol: Option<String>, // Protocol classification
    pub variant: Option<String>,  // Protocol variant
}

/// Multisig configuration analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigConfigReport {
    pub configurations: Vec<MultisigConfiguration>,
    pub total_outputs: u64,
    pub total_script_bytes: u64,
    pub total_data_capacity: u64,
    pub overall_efficiency: f64,
    pub type_summary: std::collections::BTreeMap<String, u64>, // m-of-n -> count
}

/// Content type (MIME type) analysis report
///
/// Provides comprehensive breakdown of content types across all classified unspent P2MS outputs.
/// Distinguishes between data-carrying outputs (with content types) and valid None cases
/// (LikelyDataStorage, LikelyLegitimateMultisig, StampsUnknown, OmniFailedDeobfuscation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeAnalysisReport {
    pub total_outputs: usize,
    pub outputs_with_content_type: usize,
    pub outputs_without_content_type: usize,
    pub content_type_percentage: f64,
    pub content_type_breakdown: Vec<ContentTypeStats>,
    pub category_breakdown: Vec<ContentTypeCategoryStats>,
    pub protocol_breakdown: Vec<ContentTypeProtocolStats>,
    pub valid_none_stats: ValidNoneStats,
    pub invalid_none_stats: Vec<ContentTypeProtocolStats>,
}

/// Statistics for a specific MIME type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeStats {
    pub mime_type: String,
    pub count: usize,
    pub percentage: f64,
}

/// MIME category statistics (image/*, text/*, application/*)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeCategoryStats {
    pub category: String,
    pub count: usize,
    pub percentage: f64,
    pub specific_types: Vec<ContentTypeStats>,
}

/// Protocol-specific content type statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeProtocolStats {
    pub protocol: String,
    pub total_outputs: usize,
    pub with_content_type: usize,
    pub without_content_type: usize,
    pub coverage_percentage: f64,
    pub content_types: Vec<ContentTypeStats>,
}

/// Statistics for valid None cases (architecturally correct)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidNoneStats {
    pub total_valid_none: usize,
    pub likely_data_storage: usize,
    pub likely_legitimate_multisig: usize,
    pub stamps_unknown: usize,
    pub omni_failed_deobfuscation: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Dust Threshold Analysis Types
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// Bitcoin Stamps Weekly Fee Analysis Types
// ═══════════════════════════════════════════════════════════════════════════

/// Weekly fee statistics for Bitcoin Stamps transactions
///
/// Aggregates transaction fees at the TRANSACTION level (not output level)
/// to avoid double-counting fees for multi-output transactions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StampsWeeklyFeeReport {
    /// Number of weeks with data
    pub total_weeks: usize,
    /// Total number of distinct Bitcoin Stamps transactions
    pub total_transactions: usize,
    /// Sum of all transaction fees in satoshis
    pub total_fees_sats: u64,
    /// Per-week breakdown ordered by week_bucket
    pub weekly_data: Vec<WeeklyStampsFeeStats>,
    /// Summary statistics across all weeks
    pub summary: StampsFeeSummary,
}

/// Statistics for a single week of Bitcoin Stamps transactions
///
/// Week boundaries are Thursday-to-Wednesday (Unix epoch started Thursday 1970-01-01).
/// Each bucket is exactly 604800 seconds (7 days) with no drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyStampsFeeStats {
    /// Integer bucket number for ordering (timestamp / 604800)
    pub week_bucket: i64,
    /// Unix timestamp of week start (for Plotly/programmatic use)
    pub week_start_ts: i64,
    /// ISO 8601 date for display (YYYY-MM-DD)
    pub week_start_iso: String,
    /// Week end date for display (YYYY-MM-DD)
    pub week_end_iso: String,
    /// Number of distinct transactions in this week
    pub transaction_count: usize,
    /// Sum of fees in satoshis
    pub total_fees_sats: u64,
    /// Average fee per transaction in satoshis
    pub avg_fee_sats: f64,
    /// Sum of P2MS script_size bytes
    pub total_script_bytes: u64,
    /// Fee efficiency: total_fees / total_script_bytes (0.0 if no script bytes)
    pub avg_fee_per_byte_sats: f64,
}

/// Summary statistics for Bitcoin Stamps fee analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampsFeeSummary {
    /// First week start date (ISO 8601) or empty string if no data
    pub date_range_start: String,
    /// Last week end date (ISO 8601) or empty string if no data
    pub date_range_end: String,
    /// Total fees in BTC (presentation convenience)
    pub total_fees_btc: f64,
    /// Average fee per transaction across all weeks in satoshis
    pub avg_fee_per_tx_sats: f64,
    /// Average fee per byte across all weeks in satoshis
    pub avg_fee_per_byte_sats: f64,
}

impl Default for StampsFeeSummary {
    fn default() -> Self {
        Self {
            date_range_start: String::new(),
            date_range_end: String::new(),
            total_fees_btc: 0.0,
            avg_fee_per_tx_sats: 0.0,
            avg_fee_per_byte_sats: 0.0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Transaction Size Distribution Analysis Types
// ═══════════════════════════════════════════════════════════════════════════

// NOTE: TxSizeBucket is now a type alias for DistributionBucket<u32>
// defined above with the other distribution bucket types.

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

// ============================================================================
// P2MS Output Count Distribution Types
// ============================================================================

/// Type alias for output count distribution buckets (range bounds in output counts)
pub type OutputCountBucket = DistributionBucket<u32>;

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

// ============================================================================
// Stamps-specific analysis types (moved from analysis modules to avoid cycle)
// ============================================================================

/// Statistics for a specific signature variant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVariantStats {
    pub variant: String,
    pub count: usize,
    pub percentage: f64,
}

/// Bitcoin Stamps signature variant distribution analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampsSignatureAnalysis {
    pub total_stamps: usize,
    pub signature_distribution: Vec<SignatureVariantStats>,
    pub pure_stamps_signatures: Vec<SignatureVariantStats>,
    pub counterparty_stamps_signatures: Vec<SignatureVariantStats>,
}

/// Bitcoin Stamps transport mechanism analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampsTransportAnalysis {
    /// Total number of Bitcoin Stamps transactions
    pub total_transactions: usize,

    /// Total number of Bitcoin Stamps outputs
    pub total_outputs: usize,

    /// Pure Bitcoin Stamps statistics
    #[serde(default)]
    pub pure_stamps: TransportStats,

    /// Counterparty-transported Bitcoin Stamps statistics
    #[serde(default)]
    pub counterparty_transport: TransportStats,
}

/// Statistics for a specific transport mechanism
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportStats {
    /// Number of transactions using this transport
    pub transaction_count: usize,

    /// Percentage of total Bitcoin Stamps transactions
    pub transaction_percentage: f64,

    /// Breakdown by variant (StampsSRC20, StampsClassic, etc.)
    #[serde(default)]
    pub variant_breakdown: Vec<TransportVariantStats>,

    /// Number of spendable outputs
    pub spendable_outputs: usize,

    /// Number of unspendable outputs
    pub unspendable_outputs: usize,

    /// Total outputs for this transport type
    pub total_outputs: usize,
}

/// Variant statistics within a transport mechanism (Stamps-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportVariantStats {
    /// Variant name (e.g., "StampsSRC20")
    pub variant: String,

    /// Number of transactions with this variant
    pub count: usize,

    /// Percentage within this transport type
    pub percentage: f64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Stamps Variant Temporal Distribution
// ═══════════════════════════════════════════════════════════════════════════

/// Temporal distribution of Bitcoin Stamps variants
///
/// Week boundaries are Thursday-to-Wednesday (Unix epoch started Thursday).
/// Uses fixed 7-day buckets: `timestamp / 604800`
///
/// Follows the same pattern as `StampsWeeklyFeeReport` for consistency.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StampsVariantTemporalReport {
    /// Total outputs with valid (non-NULL) variants
    pub total_outputs: usize,

    /// Total value of all outputs in satoshis
    pub total_value_sats: u64,

    /// First week in the data range (ISO date: YYYY-MM-DD)
    pub date_range_start: String,

    /// Last week in the data range (ISO date: YYYY-MM-DD)
    pub date_range_end: String,

    /// Aggregate statistics per variant
    pub variant_totals: Vec<VariantTotal>,

    /// Weekly time series data - one entry per (week, variant) pair
    pub weekly_data: Vec<WeeklyVariantStats>,

    /// First appearance of each variant (ordered by height)
    pub first_appearances: Vec<VariantFirstSeen>,

    /// Count of outputs with NULL variant (indicates bug - should be 0)
    pub null_variant_count: usize,
}

/// Aggregate statistics for a single variant
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VariantTotal {
    /// Variant name (e.g., "Classic", "SRC-20")
    pub variant: String,

    /// Total output count for this variant
    pub count: usize,

    /// Percentage of total Stamps outputs (denominator = unspent P2MS Stamps with non-NULL variant)
    pub percentage: f64,

    /// Total value of outputs in satoshis
    pub total_value_sats: u64,
}

/// Weekly statistics for a single variant
///
/// Empty weeks are omitted (following stamps_weekly_fee_analysis pattern).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WeeklyVariantStats {
    /// Week bucket number (timestamp / 604800)
    pub week_bucket: i64,

    /// Week start date (ISO format: YYYY-MM-DD)
    pub week_start_iso: String,

    /// Week end date (ISO format: YYYY-MM-DD)
    pub week_end_iso: String,

    /// Variant name
    pub variant: String,

    /// Output count for this variant in this week
    pub count: usize,

    /// Total value in satoshis for this variant in this week
    pub value_sats: u64,
}

/// First appearance information for a variant
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VariantFirstSeen {
    /// Variant name
    pub variant: String,

    /// Block height of first appearance
    pub first_height: u64,

    /// Date of first appearance (ISO format: YYYY-MM-DD)
    pub first_date: String,

    /// TXID of first appearance (deterministic tie-break: MIN(txid) at MIN(height))
    pub first_txid: String,
}

// ============================================================================
// Protocol Temporal Analysis Types
// ============================================================================

/// Temporal distribution of P2MS protocols
///
/// Shows how different protocols (Bitcoin Stamps, Counterparty, etc.) are
/// distributed across weekly time buckets.
///
/// Week boundaries are Thursday-to-Wednesday (Unix epoch started Thursday).
/// Uses fixed 7-day buckets: `timestamp / 604800`
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolTemporalReport {
    /// Total number of unspent P2MS outputs analysed
    pub total_outputs: usize,

    /// Total value in satoshis across all outputs
    pub total_value_sats: u64,

    /// Number of unique weeks with data
    pub week_count: usize,

    /// Per-protocol totals
    pub protocol_totals: Vec<ProtocolTotal>,

    /// Weekly breakdown by protocol - one entry per (week, protocol) pair
    pub weekly_data: Vec<WeeklyProtocolStats>,
}

/// Total counts for a single protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolTotal {
    /// Protocol identifier (e.g., "BitcoinStamps", "Counterparty")
    pub protocol: String,

    /// Human-readable display name
    pub display_name: String,

    /// Total output count for this protocol
    pub count: usize,

    /// Total value in satoshis
    pub value_sats: u64,
}

/// Weekly statistics for a protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WeeklyProtocolStats {
    /// Week bucket number (timestamp / 604800)
    pub week_bucket: i64,

    /// Week start date (ISO format: YYYY-MM-DD)
    pub week_start_iso: String,

    /// Week end date (ISO format: YYYY-MM-DD)
    pub week_end_iso: String,

    /// Protocol identifier
    pub protocol: String,

    /// Output count for this protocol in this week
    pub count: usize,

    /// Total value in satoshis for this protocol in this week
    pub value_sats: u64,
}

// ============================================================================
// Spendability Temporal Analysis Types
// ============================================================================

/// Temporal distribution of P2MS output spendability
///
/// Shows the percentage of spendable vs unspendable outputs over time.
///
/// Week boundaries are Thursday-to-Wednesday (Unix epoch started Thursday).
/// Uses fixed 7-day buckets: `timestamp / 604800`
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SpendabilityTemporalReport {
    /// Total number of unspent P2MS outputs analysed
    pub total_outputs: usize,

    /// Number of spendable outputs
    pub spendable_count: usize,

    /// Number of unspendable outputs
    pub unspendable_count: usize,

    /// Overall spendable percentage
    pub overall_spendable_pct: f64,

    /// Number of unique weeks with data
    pub week_count: usize,

    /// Weekly breakdown
    pub weekly_data: Vec<WeeklySpendabilityStats>,
}

/// Weekly statistics for spendability
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WeeklySpendabilityStats {
    /// Week bucket number (timestamp / 604800)
    pub week_bucket: i64,

    /// Week start date (ISO format: YYYY-MM-DD)
    pub week_start_iso: String,

    /// Week end date (ISO format: YYYY-MM-DD)
    pub week_end_iso: String,

    /// Number of spendable outputs in this week
    pub spendable_count: usize,

    /// Number of unspendable outputs in this week
    pub unspendable_count: usize,

    /// Total outputs in this week
    pub total_count: usize,

    /// Percentage of spendable outputs
    pub spendable_pct: f64,

    /// Percentage of unspendable outputs
    pub unspendable_pct: f64,
}
