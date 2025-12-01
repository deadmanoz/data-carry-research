//! Classification, signature, and burn pattern report formatters
//!
//! Provides formatting for protocol classification statistics, signature analysis,
//! and burn pattern analysis results.

use super::utils::export_json;
use super::OutputFormat;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    BurnPatternAnalysis, ClassificationStatsReport, SignatureAnalysisReport,
};

/// Format burn pattern analysis results for console output
pub fn format_burn_patterns(
    analysis: &BurnPatternAnalysis,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Console => {
            let mut output = String::new();

            // Pattern breakdown
            for pattern in &analysis.pattern_breakdown {
                output.push_str(&format!(
                    "{}|{}|{:.2}%\n",
                    pattern.pattern_type, pattern.count, pattern.percentage
                ));
            }

            // Sample patterns section
            if !analysis.sample_patterns.is_empty() {
                output.push_str("\nSample burn patterns:\n");
                for sample in &analysis.sample_patterns {
                    output.push_str(&format!(
                        "{}|{}|{}\n",
                        sample.txid, sample.pattern_type, sample.pattern_data
                    ));
                }
            }

            Ok(output)
        }
        OutputFormat::Json | OutputFormat::Plotly => export_json(analysis),
    }
}

/// Format classification statistics for console output
pub fn format_classification_stats(
    report: &ClassificationStatsReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Console => {
            let mut output = format!("Total classified: {}\n", report.total_classified);

            // Protocol breakdown
            output.push_str(&format!(
                "Bitcoin Stamps: {} ({:.1}%)\n",
                report.protocol_breakdown.bitcoin_stamps.count,
                report.protocol_breakdown.bitcoin_stamps.percentage
            ));
            output.push_str(&format!(
                "Counterparty: {} ({:.1}%)\n",
                report.protocol_breakdown.counterparty.count,
                report.protocol_breakdown.counterparty.percentage
            ));
            output.push_str(&format!(
                "ASCII ID Protocols: {} ({:.1}%)\n",
                report.protocol_breakdown.ascii_identifier_protocols.count,
                report
                    .protocol_breakdown
                    .ascii_identifier_protocols
                    .percentage
            ));
            output.push_str(&format!(
                "Omni Layer: {} ({:.1}%)\n",
                report.protocol_breakdown.omni_layer.count,
                report.protocol_breakdown.omni_layer.percentage
            ));
            output.push_str(&format!(
                "Chancecoin: {} ({:.1}%)\n",
                report.protocol_breakdown.chancecoin.count,
                report.protocol_breakdown.chancecoin.percentage
            ));
            output.push_str(&format!(
                "PPk: {} ({:.1}%)\n",
                report.protocol_breakdown.ppk.count, report.protocol_breakdown.ppk.percentage
            ));
            output.push_str(&format!(
                "OP_RETURN Signalled: {} ({:.1}%)\n",
                report.protocol_breakdown.opreturn_signalled.count,
                report.protocol_breakdown.opreturn_signalled.percentage
            ));
            output.push_str(&format!(
                "Data Storage: {} ({:.1}%)\n",
                report.protocol_breakdown.data_storage.count,
                report.protocol_breakdown.data_storage.percentage
            ));
            output.push_str(&format!(
                "Likely Data Storage: {} ({:.1}%)\n",
                report.protocol_breakdown.likely_data_storage.count,
                report.protocol_breakdown.likely_data_storage.percentage
            ));
            output.push_str(&format!(
                "Likely Legitimate: {} ({:.1}%)\n",
                report.protocol_breakdown.likely_legitimate.count,
                report.protocol_breakdown.likely_legitimate.percentage
            ));
            output.push_str(&format!(
                "Unknown: {} ({:.1}%)\n",
                report.protocol_breakdown.unknown.count,
                report.protocol_breakdown.unknown.percentage
            ));
            output.push_str(&format!(
                "Definitive signatures: {} ({:.1}%)\n",
                report.signature_detection_rates.definitive_signatures,
                report.signature_detection_rates.signature_percentage
            ));

            // Sample classifications
            if !report.sample_classifications.is_empty() {
                output.push_str("\nSample Classifications:\n");
                for sample in &report.sample_classifications {
                    output.push_str(&format!(
                        "{}|{}|{}|{}\n",
                        sample.protocol, sample.variant, sample.classification_method, sample.count
                    ));
                }
            }

            Ok(output)
        }
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
    }
}

/// Format signature analysis results for console output
pub fn format_signature_analysis(
    report: &SignatureAnalysisReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Console => {
            let mut output = String::new();

            // Classification methods
            if !report.classification_methods.is_empty() {
                output.push_str("\nClassification Methods:\n");
                for method in &report.classification_methods {
                    output.push_str(&format!("{}|{}\n", method.method, method.count));
                }
            }

            // Burn pattern analysis
            if !report.burn_pattern_analysis.correlations.is_empty() {
                output.push_str("\nBurn Pattern Analysis:\n");
                for corr in &report.burn_pattern_analysis.correlations {
                    output.push_str(&format!(
                        "{}|{}|{}\n",
                        corr.protocol, corr.burn_patterns_count, corr.transactions
                    ));
                }
            }

            Ok(output)
        }
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
    }
}
