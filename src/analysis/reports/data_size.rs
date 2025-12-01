//! Data size analysis report formatters
//!
//! Provides formatting for protocol-level data sizes, comprehensive data size reports,
//! and content type spendability cross-analysis.

use super::utils::{export_json, format_bytes, format_number};
use super::OutputFormat;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    ComprehensiveDataSizeReport, ContentTypeSpendabilityReport, ProtocolDataSizeReport,
};

// Import spendability formatter for comprehensive report
use super::spendability::format_spendability_data_size_report;

/// Format protocol-level data size report
pub fn format_protocol_data_size_report(
    report: &ProtocolDataSizeReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
        OutputFormat::Console => {
            let mut output = String::new();
            output.push_str("\n📊 PROTOCOL DATA SIZES\n");
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            output.push_str(&format!(
                "Total P2MS Data:  {} across {} outputs ({} transactions)\n\n",
                format_bytes(report.total_bytes),
                format_number(report.total_outputs),
                format_number(report.total_transactions)
            ));

            for protocol in &report.protocols {
                let variant_str = if let Some(ref v) = protocol.variant {
                    format!(" ({})", v)
                } else {
                    String::new()
                };

                output.push_str(&format!(
                    "{}{:<30} {} ({:.1}%)\n",
                    protocol.protocol,
                    variant_str,
                    format_bytes(protocol.total_bytes),
                    protocol.percentage_of_total
                ));
                output.push_str(&format!(
                    "  Outputs:        {} ({} transactions)\n",
                    format_number(protocol.output_count),
                    format_number(protocol.transaction_count)
                ));
                output.push_str(&format!(
                    "  Avg/Min/Max:    {} / {} / {}\n",
                    format_bytes(protocol.average_bytes as u64),
                    format_bytes(protocol.min_bytes),
                    format_bytes(protocol.max_bytes)
                ));
                output.push_str(&format!(
                    "  Spendable:      {} ({:.1}%)\n",
                    format_bytes(protocol.spendable_bytes),
                    protocol.spendable_percentage
                ));
                output.push_str(&format!(
                    "  Unspendable:    {}\n\n",
                    format_bytes(protocol.unspendable_bytes)
                ));
            }

            Ok(output)
        }
    }
}

/// Format content type with spendability cross-analysis report
pub fn format_content_type_spendability_report(
    report: &ContentTypeSpendabilityReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
        OutputFormat::Console => {
            let mut output = String::new();
            output.push_str("\n📊 CONTENT TYPE × SPENDABILITY ANALYSIS\n");
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            output.push_str(&format!(
                "Total P2MS Data:  {} ({} transactions)\n\n",
                format_bytes(report.total_bytes),
                format_number(report.total_transactions)
            ));

            for category in &report.categories {
                let totals = &category.category_totals;
                let spendable_pct = if totals.total_bytes > 0 {
                    (totals.spendable_bytes as f64 / totals.total_bytes as f64) * 100.0
                } else {
                    0.0
                };

                output.push_str(&format!(
                    "{}: {} ({:.1}% spendable) - {} transactions, {} outputs\n",
                    category.category,
                    format_bytes(totals.total_bytes),
                    spendable_pct,
                    format_number(totals.transaction_count),
                    format_number(totals.output_count)
                ));

                // Show content types within category
                for ct in &category.content_types {
                    output.push_str(&format!(
                        "  {:<25} {} (spendable: {}, unspendable: {})\n",
                        format!("{} ({})", ct.extension, ct.mime_type),
                        format_bytes(ct.total_bytes),
                        format_bytes(ct.spendable_bytes),
                        format_bytes(ct.unspendable_bytes)
                    ));
                }
                output.push('\n');
            }

            Ok(output)
        }
    }
}

/// Format comprehensive data size report
pub fn format_comprehensive_data_size_report(
    report: &ComprehensiveDataSizeReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
        OutputFormat::Console => {
            let mut output = String::new();
            output.push_str("\n📊 COMPREHENSIVE DATA SIZE ANALYSIS\n");
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

            let summary = &report.overall_summary;
            output.push_str("\n🔍 Overall Summary:\n");
            output.push_str(&format!(
                "  Total P2MS Data:           {}\n",
                format_bytes(summary.total_p2ms_bytes)
            ));
            output.push_str(&format!(
                "  Total Outputs:             {}\n",
                format_number(summary.total_outputs)
            ));
            output.push_str(&format!(
                "  Total Transactions:        {}\n",
                format_number(summary.total_transactions)
            ));
            output.push_str(&format!(
                "  Average Bytes per Output:  {}\n",
                format_bytes(summary.average_bytes_per_output as u64)
            ));
            output.push_str(&format!(
                "  Spendable Percentage:      {:.1}%\n",
                summary.spendable_percentage
            ));

            // Protocol breakdown
            output.push_str("\n\n");
            output.push_str(&format_protocol_data_size_report(
                &report.protocol_breakdown,
                &OutputFormat::Console,
            )?);

            // Spendability breakdown
            output.push('\n');
            output.push_str(&format_spendability_data_size_report(
                &report.spendability_breakdown,
                &OutputFormat::Console,
            )?);

            // Content type breakdown
            output.push('\n');
            output.push_str(&format_content_type_spendability_report(
                &report.content_type_breakdown,
                &OutputFormat::Console,
            )?);

            Ok(output)
        }
    }
}
