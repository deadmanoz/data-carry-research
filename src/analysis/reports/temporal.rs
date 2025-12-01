//! Protocol temporal distribution report formatter
//!
//! Provides formatting for protocol distribution over time analysis.

use super::utils::{export_json, format_number};
use super::OutputFormat;
use crate::errors::AppResult;
use crate::types::analysis_results::ProtocolTemporalReport;
use crate::types::visualisation::PlotlyChart;
use crate::utils::currency::format_sats_as_btc;

/// Format protocol temporal distribution report
///
/// Displays temporal analysis of protocol distribution over time:
/// - Weekly aggregation with fixed 7-day buckets
/// - Per-protocol output counts and values
/// - Stacked bar chart data for visualisation
pub fn format_protocol_temporal(
    report: &ProtocolTemporalReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json => export_json(report),
        OutputFormat::Plotly => {
            let chart: PlotlyChart = report.to_plotly_chart();
            export_json(&chart)
        }
        OutputFormat::Console => {
            let mut output = String::new();

            // Header
            output.push_str("\n📊 Protocol Temporal Distribution\n");
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

            // Handle empty report
            if report.total_outputs == 0 {
                output.push_str("No P2MS outputs found.\n");
                return Ok(output);
            }

            // Summary
            output.push_str(&format!(
                "Total P2MS Outputs: {}\n",
                format_number(report.total_outputs)
            ));
            output.push_str(&format!(
                "Total Value: {}\n",
                format_sats_as_btc(report.total_value_sats)
            ));
            output.push_str(&format!("Weeks Analysed: {}\n\n", report.week_count));

            // Protocol Totals
            output.push_str("Protocol Totals:\n");
            output.push_str(&format!(
                "  {:<20} {:>12} {:>16}\n",
                "Protocol", "Outputs", "Value (BTC)"
            ));
            output.push_str(&format!("  {:-<20} {:->12} {:->16}\n", "", "", ""));

            for total in &report.protocol_totals {
                output.push_str(&format!(
                    "  {:<20} {:>12} {:>16}\n",
                    total.protocol.display_name(),
                    format_number(total.count),
                    format_sats_as_btc(total.value_sats)
                ));
            }
            output.push('\n');

            // Note about formats
            output.push_str(
                "Note: Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).\n",
            );
            output.push_str("      For full weekly data, use --format json\n");
            output.push_str("      For stacked bar chart data, use --format plotly\n");

            Ok(output)
        }
    }
}
