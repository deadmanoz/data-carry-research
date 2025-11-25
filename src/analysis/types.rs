//! Analysis result types and data structures
//!
//! This module defines the comprehensive data structures returned by various
//! analysis operations, replacing the raw SQL output with structured, type-safe results.

use crate::analysis::stamps_signature_stats::StampsSignatureAnalysis;
use crate::analysis::stamps_transport_stats::StampsTransportAnalysis;
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
    pub cost_distribution: Vec<CostBucket>,
}

/// Cost bucket for fee distribution analysis
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CostBucket {
    pub range_min: f64,
    pub range_max: f64,
    pub transaction_count: usize,
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

/// Value distribution histogram bucket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueBucket {
    pub range_min: u64,             // Minimum value in satoshis
    pub range_max: u64,             // Maximum value in satoshis
    pub count: usize,               // Number of outputs in this range
    pub total_value: u64,           // Total satoshis in this bucket
    pub percentage_of_outputs: f64, // % of total outputs
    pub percentage_of_value: f64,   // % of total value
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
