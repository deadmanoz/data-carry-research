//! Full analysis report type

use super::burn_patterns::BurnPatternAnalysis;
use super::classification::ClassificationStatsReport;
use super::data_size::ComprehensiveDataSizeReport;
use super::fees::FeeAnalysisReport;
use super::file_extensions::FileExtensionReport;
use super::signatures::SignatureAnalysisReport;
use super::spendability::SpendabilityStatsReport;
use super::stamps::{StampsSignatureAnalysis, StampsTransportAnalysis};
use serde::{Deserialize, Serialize};

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
