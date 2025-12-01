//! Report formatting and output generation
//!
//! Provides formatting for analysis results via the [`ReportFormatter`] facade.
//! Supports Console, JSON, and Plotly output formats.

pub mod classification;
pub mod data_size;
pub mod distributions;
pub mod full_report;
pub mod spendability;
pub mod stamps;
pub mod temporal;
pub mod utils;
pub mod value;

use crate::analysis::stamps_signature_stats::StampsSignatureAnalysis;
use crate::analysis::stamps_transport_stats::StampsTransportAnalysis;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    BurnPatternAnalysis, ClassificationStatsReport, ComprehensiveDataSizeReport,
    ContentTypeSpendabilityReport, DustAnalysisReport, FeeAnalysisReport, FileExtensionReport,
    FullAnalysisReport, MultisigConfigReport, OutputCountDistributionReport,
    ProtocolDataSizeReport, ProtocolTemporalReport, SignatureAnalysisReport,
    SpendabilityDataSizeReport, SpendabilityStatsReport, SpendabilityTemporalReport,
    StampsVariantTemporalReport, StampsWeeklyFeeReport, TxSizeDistributionReport,
    ValueAnalysisReport, ValueDistributionReport,
};

/// Output format options for analysis reports
#[derive(Debug, Clone, Default)]
pub enum OutputFormat {
    #[default]
    Console,
    Json,
    Plotly,
}

/// Facade for all report formatting operations
pub struct ReportFormatter;

impl ReportFormatter {
    // Utilities
    pub fn format_number(n: usize) -> String {
        utils::format_number(n)
    }
    pub fn format_bytes(bytes: u64) -> String {
        utils::format_bytes(bytes)
    }

    // Classification & Signatures
    pub fn format_burn_patterns(a: &BurnPatternAnalysis, f: &OutputFormat) -> AppResult<String> {
        classification::format_burn_patterns(a, f)
    }
    pub fn format_classification_stats(
        r: &ClassificationStatsReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        classification::format_classification_stats(r, f)
    }
    pub fn format_signature_analysis(
        r: &SignatureAnalysisReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        classification::format_signature_analysis(r, f)
    }

    // Value
    pub fn format_value_analysis(r: &ValueAnalysisReport, f: &OutputFormat) -> AppResult<String> {
        value::format_value_analysis(r, f)
    }
    pub fn format_value_distributions(
        r: &ValueDistributionReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        value::format_value_distributions(r, f)
    }

    // Spendability
    pub fn format_spendability_report(
        r: &SpendabilityStatsReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        spendability::format_spendability_report(r, f)
    }
    pub fn format_spendability_data_size_report(
        r: &SpendabilityDataSizeReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        spendability::format_spendability_data_size_report(r, f)
    }
    pub fn format_spendability_temporal(
        r: &SpendabilityTemporalReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        spendability::format_spendability_temporal(r, f)
    }

    // Data Size
    pub fn format_protocol_data_size_report(
        r: &ProtocolDataSizeReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        data_size::format_protocol_data_size_report(r, f)
    }
    pub fn format_content_type_spendability_report(
        r: &ContentTypeSpendabilityReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        data_size::format_content_type_spendability_report(r, f)
    }
    pub fn format_comprehensive_data_size_report(
        r: &ComprehensiveDataSizeReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        data_size::format_comprehensive_data_size_report(r, f)
    }

    // Stamps
    pub fn format_stamps_transport(
        s: &StampsTransportAnalysis,
        f: &OutputFormat,
    ) -> AppResult<String> {
        stamps::format_stamps_transport(s, f)
    }
    pub fn format_stamps_signatures(
        s: &StampsSignatureAnalysis,
        f: &OutputFormat,
    ) -> AppResult<String> {
        stamps::format_stamps_signatures(s, f)
    }
    pub fn format_stamps_weekly_fees(
        r: &StampsWeeklyFeeReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        stamps::format_stamps_weekly_fees(r, f)
    }
    pub fn format_stamps_variant_temporal(
        r: &StampsVariantTemporalReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        stamps::format_stamps_variant_temporal(r, f)
    }

    // Distributions
    pub fn format_tx_sizes(r: &TxSizeDistributionReport, f: &OutputFormat) -> AppResult<String> {
        distributions::format_tx_sizes(r, f)
    }
    pub fn format_output_count_distribution(
        r: &OutputCountDistributionReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        distributions::format_output_count_distribution(r, f)
    }
    pub fn format_dust_analysis(r: &DustAnalysisReport, f: &OutputFormat) -> AppResult<String> {
        distributions::format_dust_analysis(r, f)
    }
    pub fn format_multisig_config_report(
        r: &MultisigConfigReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        distributions::format_multisig_config_report(r, f)
    }

    // Temporal
    pub fn format_protocol_temporal(
        r: &ProtocolTemporalReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        temporal::format_protocol_temporal(r, f)
    }

    // Full Report
    pub fn format_fee_analysis(r: &FeeAnalysisReport, f: &OutputFormat) -> AppResult<String> {
        full_report::format_fee_analysis(r, f)
    }
    pub fn format_file_extension_report(
        r: &FileExtensionReport,
        f: &OutputFormat,
    ) -> AppResult<String> {
        full_report::format_file_extension_report(r, f)
    }
    pub fn format_full_report(r: &FullAnalysisReport, f: &OutputFormat) -> AppResult<String> {
        full_report::format_full_report(r, f)
    }
}
