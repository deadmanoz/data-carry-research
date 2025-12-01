//! Analysis result types and data structures
//!
//! This module defines the comprehensive data structures returned by various
//! analysis operations, replacing the raw SQL output with structured, type-safe results.

mod burn_patterns;
mod classification;
mod common;
mod content_types;
mod data_size;
mod dust;
mod fees;
mod file_extensions;
mod full_report;
mod multisig;
mod output_count;
mod signatures;
mod spendability;
mod stamps;
mod temporal;
mod tx_size;
mod value;

// Re-export all types for backwards compatibility with existing imports
pub use burn_patterns::{BurnPatternAnalysis, BurnPatternSample, PatternTypeStats};
pub use classification::{
    ClassificationSample, ClassificationStatsReport, MethodStats, ProtocolBreakdown, ProtocolStats,
    SignatureDetectionStats, VariantStats,
};
pub use common::{DistributionBucket, OutputCountBucket, TxSizeBucket, ValueBucket};
pub use content_types::{
    ContentTypeAnalysisReport, ContentTypeCategoryStats, ContentTypeProtocolStats, ContentTypeStats,
    ValidNoneStats,
};
pub use data_size::{
    CategoryDataMetrics, CategorySpendabilityData, ComprehensiveDataSizeReport, ContentTypeData,
    ContentTypeSpendabilityReport, OverallDataSummary, ProtocolDataSize, ProtocolDataSizeReport,
    ProtocolSpendabilityData, ReasonSpendabilityData, SpendabilityDataMetrics,
    SpendabilityDataSizeReport,
};
pub use dust::{
    DustAnalysisReport, DustBucket, DustThresholds, GlobalDustStats, ProtocolDustStats,
    UNCLASSIFIED_SENTINEL,
};
pub use fees::{FeeAnalysisReport, FeeStatistics, ProtocolFeeStats, StorageCostAnalysis};
pub use file_extensions::{CategoryBreakdown, CategoryTotals, ExtensionStats, FileExtensionReport};
pub use full_report::FullAnalysisReport;
pub use multisig::{MultisigConfigReport, MultisigConfiguration};
pub use output_count::{
    GlobalOutputCountDistribution, OutputCountDistributionReport, OutputCountPercentiles,
    ProtocolOutputCountDistribution,
};
pub use signatures::{
    BurnPatternCorrelation, ConfidenceStats, PatternProtocolCorrelation, SignatureAnalysisReport,
};
pub use spendability::{
    KeyCountDistribution, KeyCountStats, OverallSpendability, ProtocolSpendabilityStats, ReasonStats,
    SpendabilityStatsReport, SpendabilityTemporalReport, TransactionSpendabilityStats,
    WeeklySpendabilityStats,
};
pub use stamps::{
    SignatureVariantStats, StampsFeeSummary, StampsSignatureAnalysis, StampsTransportAnalysis,
    StampsVariantTemporalReport, StampsWeeklyFeeReport, TransportStats, TransportVariantStats,
    VariantFirstSeen, VariantTotal, WeeklyStampsFeeStats, WeeklyVariantStats,
};
pub use temporal::{ProtocolTemporalReport, ProtocolTotal, WeeklyProtocolStats};
pub use tx_size::{
    GlobalTxSizeDistribution, ProtocolTxSizeDistribution, TxSizeDistributionReport,
    TxSizePercentiles,
};
pub use value::{
    GlobalValueDistribution, OverallValueStats, ProtocolValueDistribution, ProtocolValueStats,
    ValueAnalysisReport, ValueDistributionReport, ValuePercentiles,
};
