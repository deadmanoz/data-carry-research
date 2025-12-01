//! Spendability analysis report formatters
//!
//! Provides formatting for spendability statistics, data size by spendability,
//! and temporal spendability distribution.

use super::utils::{export_json, format_bytes, format_number};
use super::OutputFormat;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    SpendabilityDataSizeReport, SpendabilityStatsReport, SpendabilityTemporalReport,
};
use crate::types::visualisation::PlotlyChart;

/// Format spendability analysis results
pub fn format_spendability_report(
    report: &SpendabilityStatsReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Console => {
            let mut output = String::new();

            // Overall breakdown
            output.push_str(&format!(
                "Total outputs: {}\n\
                 Spendable: {} ({:.1}%)\n\
                 Unspendable: {} ({:.1}%)\n\n",
                report.overall.total_outputs,
                report.overall.spendable_count,
                report.overall.spendable_percentage,
                report.overall.unspendable_count,
                report.overall.unspendable_percentage
            ));

            // Per-protocol breakdown
            if !report.protocol_breakdown.is_empty() {
                output.push_str("Per-Protocol Breakdown:\n");
                for proto in &report.protocol_breakdown {
                    output.push_str(&format!(
                        "{}|Spendable:{}({:.1}%)|Unspendable:{}({:.1}%)\n",
                        proto.protocol,
                        proto.spendable_count,
                        proto.spendable_percentage,
                        proto.unspendable_count,
                        proto.unspendable_percentage
                    ));
                }
                output.push('\n');
            }

            // Reason distribution
            if !report.reason_distribution.is_empty() {
                output.push_str("Spendability Reasons:\n");
                for reason in &report.reason_distribution {
                    output.push_str(&format!(
                        "{}|{}|{:.1}%\n",
                        reason.reason, reason.count, reason.percentage
                    ));
                }
                output.push('\n');
            }

            // Key count distribution
            output.push_str(&format!(
                "Key Count Distribution:\n\
                 Real pubkeys: {} total, {:.2} avg, {}-{} range\n\
                 Burn keys: {} total, {:.2} avg, {}-{} range\n\
                 Data keys: {} total, {:.2} avg, {}-{} range\n\n",
                report.key_count_distribution.real_pubkey_stats.total,
                report.key_count_distribution.real_pubkey_stats.average,
                report.key_count_distribution.real_pubkey_stats.min,
                report.key_count_distribution.real_pubkey_stats.max,
                report.key_count_distribution.burn_key_stats.total,
                report.key_count_distribution.burn_key_stats.average,
                report.key_count_distribution.burn_key_stats.min,
                report.key_count_distribution.burn_key_stats.max,
                report.key_count_distribution.data_key_stats.total,
                report.key_count_distribution.data_key_stats.average,
                report.key_count_distribution.data_key_stats.min,
                report.key_count_distribution.data_key_stats.max
            ));

            // Transaction-level stats
            output.push_str(&format!(
                "Transaction-Level:\n\
                 Total transactions: {}\n\
                 With spendable outputs: {} ({:.1}%)\n\
                 All unspendable: {}\n",
                report.transaction_level.total_transactions,
                report.transaction_level.transactions_with_spendable_outputs,
                report.transaction_level.spendable_transaction_percentage,
                report.transaction_level.transactions_all_unspendable
            ));

            Ok(output)
        }
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
    }
}

/// Format spendability-focused data size report
pub fn format_spendability_data_size_report(
    report: &SpendabilityDataSizeReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
        OutputFormat::Console => {
            let mut output = String::new();
            output.push_str("\n📊 DATA SIZE BY SPENDABILITY\n");
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

            let overall = &report.overall;
            output.push_str(&format!(
                "Total P2MS Data:    {} ({} transactions)\n\n",
                format_bytes(overall.total_bytes),
                format_number(overall.total_transactions)
            ));

            output.push_str(&format!(
                "✅ Spendable:       {} ({:.1}%) - {} outputs\n",
                format_bytes(overall.spendable_bytes),
                overall.spendable_percentage,
                format_number(overall.spendable_output_count)
            ));
            output.push_str(&format!(
                "🔒 Unspendable:     {} ({:.1}%) - {} outputs\n\n",
                format_bytes(overall.unspendable_bytes),
                100.0 - overall.spendable_percentage,
                format_number(overall.unspendable_output_count)
            ));

            // By protocol
            if !report.by_protocol.is_empty() {
                output.push_str("By Protocol:\n");
                for protocol_data in &report.by_protocol {
                    let total = protocol_data.spendable_bytes + protocol_data.unspendable_bytes;
                    let spendable_pct = if total > 0 {
                        (protocol_data.spendable_bytes as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    };
                    output.push_str(&format!(
                        "  {:<25} Spendable: {} ({:.1}%), Unspendable: {}\n",
                        protocol_data.protocol,
                        format_bytes(protocol_data.spendable_bytes),
                        spendable_pct,
                        format_bytes(protocol_data.unspendable_bytes)
                    ));
                }
                output.push('\n');
            }

            // By reason
            if !report.by_reason.is_empty() {
                output.push_str("Unspendable Reasons:\n");
                for reason_data in &report.by_reason {
                    output.push_str(&format!(
                        "  {:<25} {} ({:.1}% of unspendable) - {} outputs\n",
                        reason_data.reason,
                        format_bytes(reason_data.total_bytes),
                        reason_data.percentage_of_total,
                        format_number(reason_data.output_count)
                    ));
                }
            }

            Ok(output)
        }
    }
}

/// Format spendability temporal distribution report
///
/// Displays temporal analysis of P2MS output spendability:
/// - Weekly aggregation with fixed 7-day buckets
/// - Spendable vs unspendable percentages
/// - Stacked area chart data for visualisation
pub fn format_spendability_temporal(
    report: &SpendabilityTemporalReport,
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
            output.push_str("\n📊 Spendability Temporal Distribution\n");
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
                "Spendable: {} ({:.1}%)\n",
                format_number(report.spendable_count),
                report.overall_spendable_pct
            ));
            output.push_str(&format!(
                "Unspendable: {} ({:.1}%)\n",
                format_number(report.unspendable_count),
                100.0 - report.overall_spendable_pct
            ));
            output.push_str(&format!("Weeks Analysed: {}\n\n", report.week_count));

            // Recent weeks (last 10)
            let recent_weeks: Vec<_> = report.weekly_data.iter().rev().take(10).collect();

            if !recent_weeks.is_empty() {
                output.push_str("Recent Weeks (last 10):\n");
                output.push_str(&format!(
                    "  {:<12} {:>10} {:>10} {:>12}\n",
                    "Week", "Spendable", "Unspendable", "Total"
                ));
                output.push_str(&format!(
                    "  {:-<12} {:->10} {:->10} {:->12}\n",
                    "", "", "", ""
                ));

                for week in recent_weeks.iter().rev() {
                    output.push_str(&format!(
                        "  {:<12} {:>9.1}% {:>9.1}% {:>12}\n",
                        week.week_start_iso,
                        week.spendable_pct,
                        week.unspendable_pct,
                        format_number(week.total_count)
                    ));
                }
            }
            output.push('\n');

            // Note about formats
            output.push_str(
                "Note: Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).\n",
            );
            output.push_str("      For full weekly data, use --format json\n");
            output.push_str("      For stacked area chart data, use --format plotly\n");

            Ok(output)
        }
    }
}
