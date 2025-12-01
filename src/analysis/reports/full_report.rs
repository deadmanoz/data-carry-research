//! Full analysis report and aggregation formatters
//!
//! Provides formatting for comprehensive analysis reports, file extension analysis,
//! and fee analysis results.

use super::classification::{
    format_burn_patterns, format_classification_stats, format_signature_analysis,
};
use super::data_size::format_comprehensive_data_size_report;
use super::spendability::format_spendability_report;
use super::stamps::{format_stamps_signatures, format_stamps_transport};
use super::utils::{export_json, format_bytes, format_number};
use super::OutputFormat;
use crate::errors::AppResult;
use crate::types::analysis_results::{FeeAnalysisReport, FileExtensionReport, FullAnalysisReport};
use crate::utils::currency::{format_rate_as_btc, format_sats_as_btc, format_sats_as_btc_f64};

/// Format fee analysis results for console output
pub fn format_fee_analysis(report: &FeeAnalysisReport, format: &OutputFormat) -> AppResult<String> {
    match format {
        OutputFormat::Console => {
            let output = format!(
                "Total transactions: {}\n\
                 Coinbase transactions: {}\n\
                 Regular transactions: {}\n\
                 Total fees paid: {}\n\
                 Average fee: {}\n\
                 Median fee per byte: {}\n\
                 Average storage cost: {}\n",
                report.total_transactions,
                report.coinbase_transactions,
                report.regular_transactions,
                format_sats_as_btc(report.fee_statistics.total_fees_paid),
                format_sats_as_btc_f64(report.fee_statistics.average_fee),
                format_rate_as_btc(report.fee_statistics.median_fee_per_byte, "byte"),
                format_rate_as_btc(report.fee_statistics.average_storage_cost, "byte")
            );
            Ok(output)
        }
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
    }
}

/// Format file extension statistics for console or JSON output
pub fn format_file_extension_report(
    report: &FileExtensionReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
        OutputFormat::Console => {
            if report.total_transactions == 0 {
                return Ok(
                    "=== FILE TYPE BREAKDOWN ===\nNo classified transactions with content types.\n"
                        .to_string(),
                );
            }

            let mut output = String::new();
            output.push_str("=== FILE TYPE BREAKDOWN ===\n");
            output.push_str(&format!(
                "Totals: {} transactions, {} outputs, {}\n\n",
                format_number(report.total_transactions),
                format_number(report.total_outputs),
                format_bytes(report.total_bytes)
            ));

            for category in &report.categories {
                let totals = &category.category_totals;
                output.push_str(&format!(
                    "{}: {:.1}% ({})\n",
                    category.category,
                    totals.byte_percentage,
                    format_bytes(totals.total_bytes)
                ));

                for ext in &category.extensions {
                    output.push_str(&format!(
                        "  {:<10} {:>8} outputs {:>10}  (tx {:.1}%, out {:.1}%, bytes {:.1}%)\n",
                        ext.extension,
                        format_number(ext.output_count),
                        format_bytes(ext.total_bytes),
                        ext.transaction_percentage,
                        ext.output_percentage,
                        ext.byte_percentage
                    ));
                }

                output.push('\n');
            }

            Ok(output)
        }
    }
}

/// Format full analysis report
pub fn format_full_report(report: &FullAnalysisReport, format: &OutputFormat) -> AppResult<String> {
    match format {
        OutputFormat::Console => {
            let mut output = format!(
                "Full Analysis Report\nGenerated: {}\n\n",
                report.generated_at
            );

            // Burn patterns section
            output.push_str("=== BURN PATTERNS ===\n");
            output.push_str(&format_burn_patterns(
                &report.burn_patterns,
                &OutputFormat::Console,
            )?);
            output.push('\n');

            // Fee analysis section
            output.push_str("=== FEE ANALYSIS ===\n");
            output.push_str(&format_fee_analysis(
                &report.fee_analysis,
                &OutputFormat::Console,
            )?);
            output.push('\n');

            // Classification stats section
            output.push_str("=== CLASSIFICATION STATISTICS ===\n");
            output.push_str(&format_classification_stats(
                &report.classifications,
                &OutputFormat::Console,
            )?);
            output.push('\n');

            // Signature analysis section
            output.push_str("=== SIGNATURE ANALYSIS ===\n");
            output.push_str(&format_signature_analysis(
                &report.signatures,
                &OutputFormat::Console,
            )?);
            output.push('\n');

            // Spendability analysis section
            output.push_str("=== SPENDABILITY ANALYSIS ===\n");
            output.push_str(&format_spendability_report(
                &report.spendability,
                &OutputFormat::Console,
            )?);

            // Data size analysis section (optional)
            if let Some(ref data_size) = report.data_size {
                output.push('\n');
                output.push_str("=== DATA SIZE ANALYSIS ===\n");
                output.push_str(&format_comprehensive_data_size_report(
                    data_size,
                    &OutputFormat::Console,
                )?);
            }

            if let Some(ref file_extensions) = report.file_extensions {
                output.push('\n');
                output.push_str(&format_file_extension_report(
                    file_extensions,
                    &OutputFormat::Console,
                )?);
            }

            // Bitcoin Stamps transport section (optional)
            if let Some(ref transport_stats) = report.stamps_transport {
                output.push('\n');
                output.push_str(&format_stamps_transport(
                    transport_stats,
                    &OutputFormat::Console,
                )?);
            }

            // Bitcoin Stamps signature variants section (optional)
            if let Some(ref signature_stats) = report.stamps_signatures {
                output.push('\n');
                output.push_str(&format_stamps_signatures(
                    signature_stats,
                    &OutputFormat::Console,
                )?);
            }

            Ok(output)
        }
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::analysis_results::{CategoryBreakdown, CategoryTotals, ExtensionStats};

    #[test]
    fn test_format_file_extension_report_console() {
        let report = FileExtensionReport {
            total_transactions: 3,
            total_outputs: 4,
            total_bytes: 1_000,
            categories: vec![CategoryBreakdown {
                category: "Images".to_string(),
                extensions: vec![ExtensionStats {
                    extension: ".png".to_string(),
                    transaction_count: 2,
                    output_count: 2,
                    total_bytes: 700,
                    transaction_percentage: 66.7,
                    output_percentage: 50.0,
                    byte_percentage: 70.0,
                }],
                category_totals: CategoryTotals {
                    transaction_count: 2,
                    output_count: 2,
                    total_bytes: 700,
                    transaction_percentage: 66.7,
                    output_percentage: 50.0,
                    byte_percentage: 70.0,
                },
            }],
        };

        let output = format_file_extension_report(&report, &OutputFormat::Console)
            .expect("console formatting should succeed");

        assert!(output.contains("FILE TYPE BREAKDOWN"));
        assert!(output.contains("Images"));
        assert!(output.contains(".png"));
    }
}
