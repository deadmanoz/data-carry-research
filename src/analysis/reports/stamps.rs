//! Bitcoin Stamps-specific report formatters
//!
//! Provides formatting for Bitcoin Stamps transport analysis, signature variants,
//! variant temporal distribution, and weekly fee analysis.

use super::utils::{export_json, format_number};
use super::OutputFormat;
use crate::analysis::stamps_signature_stats::StampsSignatureAnalysis;
use crate::analysis::stamps_transport_stats::StampsTransportAnalysis;
use crate::errors::AppResult;
use crate::types::analysis_results::{StampsVariantTemporalReport, StampsWeeklyFeeReport};
use crate::types::visualisation::PlotlyChart;
use crate::utils::currency::format_sats_as_btc;

/// Format Bitcoin Stamps transport mechanism statistics
///
/// This shows the breakdown of Pure vs Counterparty transport mechanisms
/// for Bitcoin Stamps transactions, including spendability analysis.
pub fn format_stamps_transport(
    stats: &StampsTransportAnalysis,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(stats),
        OutputFormat::Console => {
            let mut output = String::new();
            output.push_str("\n📊 Bitcoin Stamps Transport Analysis\n");
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            output.push_str(&format!(
                "Total Transactions:     {}\n",
                format_number(stats.total_transactions)
            ));
            output.push_str(&format!(
                "Total Outputs:          {}\n\n",
                format_number(stats.total_outputs)
            ));

            // Pure Stamps section
            output.push_str(&format!(
                "Pure Bitcoin Stamps:    {} ({:.1}%)\n",
                format_number(stats.pure_stamps.transaction_count),
                stats.pure_stamps.transaction_percentage
            ));
            output.push_str(&format!(
                "  └─ Outputs:           {} ({} spendable, {} unspendable)\n\n",
                format_number(stats.pure_stamps.total_outputs),
                format_number(stats.pure_stamps.spendable_outputs),
                format_number(stats.pure_stamps.unspendable_outputs)
            ));

            // Counterparty transport section
            output.push_str(&format!(
                "Counterparty Transport: {} ({:.1}%)\n",
                format_number(stats.counterparty_transport.transaction_count),
                stats.counterparty_transport.transaction_percentage
            ));
            output.push_str(&format!(
                "  ├─ Spendable:         {}\n",
                format_number(stats.counterparty_transport.spendable_outputs)
            ));
            output.push_str(&format!(
                "  └─ Unspendable:       {}\n\n",
                format_number(stats.counterparty_transport.unspendable_outputs)
            ));

            // Variant breakdown (only if non-empty)
            if !stats.counterparty_transport.variant_breakdown.is_empty() {
                output.push_str("Counterparty-Transported Variants:\n");
                for variant in &stats.counterparty_transport.variant_breakdown {
                    output.push_str(&format!(
                        "  {:<20} {} ({:.1}%)\n",
                        variant.variant,
                        format_number(variant.count),
                        variant.percentage
                    ));
                }
            }

            Ok(output)
        }
    }
}

/// Format Bitcoin Stamps signature variant statistics
///
/// This shows the distribution of signature variants (stamp:, STAMP:, stamps:, STAMPS:)
/// across all Bitcoin Stamps transactions, broken down by transport mechanism.
pub fn format_stamps_signatures(
    stats: &StampsSignatureAnalysis,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(stats),
        OutputFormat::Console => {
            let mut output = String::new();
            output.push_str("\n📊 Bitcoin Stamps Signature Variants\n");
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            output.push_str(&format!(
                "Total Classified: {}\n\n",
                format_number(stats.total_stamps)
            ));

            // Overall distribution
            if !stats.signature_distribution.is_empty() {
                output.push_str("Overall Distribution:\n");
                for sig in &stats.signature_distribution {
                    output.push_str(&format!(
                        "  {:<10} {} ({:.2}%)\n",
                        sig.variant,
                        format_number(sig.count),
                        sig.percentage
                    ));
                }
                output.push('\n');
            }

            // Pure Bitcoin Stamps
            if !stats.pure_stamps_signatures.is_empty() {
                output.push_str("🔷 Pure Bitcoin Stamps:\n");
                for sig in &stats.pure_stamps_signatures {
                    output.push_str(&format!(
                        "  {:<10} {} ({:.2}%)\n",
                        sig.variant,
                        format_number(sig.count),
                        sig.percentage
                    ));
                }
                output.push('\n');
            }

            // Counterparty Transport
            if !stats.counterparty_stamps_signatures.is_empty() {
                output.push_str("🔶 Counterparty Transport:\n");
                for sig in &stats.counterparty_stamps_signatures {
                    output.push_str(&format!(
                        "  {:<10} {} ({:.2}%)\n",
                        sig.variant,
                        format_number(sig.count),
                        sig.percentage
                    ));
                }
            }

            Ok(output)
        }
    }
}

/// Format Bitcoin Stamps weekly fee analysis report
///
/// Displays weekly fee aggregation for Bitcoin Stamps transactions with:
/// - Console: Human-readable table with BTC values
/// - JSON: Raw structured data with satoshi values
/// - Plotly: Plotly-native trace format for visualisation
pub fn format_stamps_weekly_fees(
    report: &StampsWeeklyFeeReport,
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
            output.push_str("\nBITCOIN STAMPS WEEKLY FEE ANALYSIS\n");
            output.push_str("═══════════════════════════════════════════════════════════════════════════════\n\n");

            // Handle empty report
            if report.total_weeks == 0 {
                output.push_str("No Bitcoin Stamps transactions found.\n");
                return Ok(output);
            }

            // Summary section
            let summary = &report.summary;
            output.push_str(&format!(
                "Date Range: {} to {}\n",
                summary.date_range_start, summary.date_range_end
            ));
            output.push_str(&format!(
                "Total Transactions: {}\n",
                format_number(report.total_transactions)
            ));
            output.push_str(&format!(
                "Total Fees: {} BTC ({} sats)\n",
                format_sats_as_btc(report.total_fees_sats),
                format_number(report.total_fees_sats as usize)
            ));
            output.push_str(&format!(
                "Average Fee/Tx: {} sats\n",
                format_number(summary.avg_fee_per_tx_sats as usize)
            ));
            output.push_str(&format!(
                "Average Fee/Byte: {:.2} sats\n\n",
                summary.avg_fee_per_byte_sats
            ));

            // Weekly breakdown table
            output.push_str("WEEKLY BREAKDOWN\n");
            output.push_str("───────────────────────────────────────────────────────────────────────────────────────────────────\n");
            output.push_str(&format!(
                "{:<12} │ {:>10} │ {:>16} │ {:>14} │ {:>11} │ {:>10}\n",
                "Week Start",
                "Tx Count",
                "Total Fees (BTC)",
                "Avg Fee (sats)",
                "Script KB",
                "sats/byte"
            ));
            output.push_str("─────────────┼────────────┼──────────────────┼────────────────┼─────────────┼────────────\n");

            for week in &report.weekly_data {
                let script_kb = week.total_script_bytes as f64 / 1024.0;
                output.push_str(&format!(
                    "{:<12} │ {:>10} │ {:>16} │ {:>14} │ {:>10.2} │ {:>10.2}\n",
                    week.week_start_iso,
                    format_number(week.transaction_count),
                    format_sats_as_btc(week.total_fees_sats),
                    format_number(week.avg_fee_sats.round() as usize),
                    script_kb,
                    week.avg_fee_per_byte_sats
                ));
            }

            output.push('\n');
            output.push_str(&format!(
                "Total Weeks: {}\n",
                format_number(report.total_weeks)
            ));
            output.push_str(
                "\nNote: Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).\n",
            );
            output.push_str("      For Plotly-compatible JSON output, use --format plotly\n");

            Ok(output)
        }
    }
}

/// Format Bitcoin Stamps variant temporal distribution report
///
/// Displays temporal distribution of Bitcoin Stamps variants with:
/// - Console: Human-readable summary with variant totals and first appearances
/// - JSON: Full structured data with all weekly breakdowns
/// - Plotly: Stacked area chart data for visualisation
pub fn format_stamps_variant_temporal(
    report: &StampsVariantTemporalReport,
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
            output.push_str("\n📊 Bitcoin Stamps Variant Temporal Distribution\n");
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

            // Handle empty report
            if report.total_outputs == 0 {
                output.push_str("No Bitcoin Stamps outputs found.\n");
                return Ok(output);
            }

            // Summary section
            output.push_str("Summary:\n");
            output.push_str(&format!(
                "  Total outputs (valid variants): {}\n",
                format_number(report.total_outputs)
            ));
            output.push_str(&format!(
                "  Total value: {}\n",
                format_sats_as_btc(report.total_value_sats)
            ));
            output.push_str(&format!(
                "  Date range: {} to {}\n",
                report.date_range_start, report.date_range_end
            ));
            output.push_str(&format!(
                "  NULL variants (bug indicator): {}\n\n",
                format_number(report.null_variant_count)
            ));

            // Variant Totals
            output.push_str("Variant Totals:\n");
            output.push_str(&format!(
                "  {:<15} {:>10} {:>8} {:>16}\n",
                "Variant", "Count", "%", "Value (BTC)"
            ));
            output.push_str(&format!(
                "  {:-<15} {:->10} {:->8} {:->16}\n",
                "", "", "", ""
            ));

            for variant in &report.variant_totals {
                output.push_str(&format!(
                    "  {:<15} {:>10} {:>7.2}% {:>16}\n",
                    variant.variant,
                    format_number(variant.count),
                    variant.percentage,
                    format_sats_as_btc(variant.total_value_sats)
                ));
            }
            output.push('\n');

            // First Appearances
            output.push_str("First Appearances:\n");
            output.push_str(&format!(
                "  {:<15} {:>10} {:>12} {:>16}\n",
                "Variant", "Height", "Date", "TXID"
            ));
            output.push_str(&format!(
                "  {:-<15} {:->10} {:->12} {:->16}\n",
                "", "", "", ""
            ));

            for first in &report.first_appearances {
                let txid_short = if first.first_txid.len() > 12 {
                    format!("{}...", &first.first_txid[..12])
                } else {
                    first.first_txid.clone()
                };
                output.push_str(&format!(
                    "  {:<15} {:>10} {:>12} {:>16}\n",
                    first.variant,
                    format_number(first.first_height as usize),
                    first.first_date,
                    txid_short
                ));
            }
            output.push('\n');

            // Weekly Distribution (last 10 weeks only for console)
            let recent_weeks: Vec<_> = {
                let mut weeks_seen = std::collections::HashSet::new();
                report
                    .weekly_data
                    .iter()
                    .rev()
                    .filter(|w| weeks_seen.insert(w.week_bucket))
                    .take(10)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect()
            };

            if !recent_weeks.is_empty() {
                let start_week = recent_weeks.first().map(|w| w.week_bucket);
                let relevant_data: Vec<_> = report
                    .weekly_data
                    .iter()
                    .filter(|w| start_week.is_some_and(|sw| w.week_bucket >= sw))
                    .collect();

                output.push_str("Weekly Distribution (last 10 weeks):\n");
                output.push_str(&format!(
                    "  {:<12} {:<15} {:>10} {:>16}\n",
                    "Week", "Variant", "Count", "Value (sats)"
                ));
                output.push_str(&format!(
                    "  {:-<12} {:-<15} {:->10} {:->16}\n",
                    "", "", "", ""
                ));

                for week_stat in relevant_data.iter().take(50) {
                    output.push_str(&format!(
                        "  {:<12} {:<15} {:>10} {:>16}\n",
                        week_stat.week_start_iso,
                        week_stat.variant,
                        format_number(week_stat.count),
                        format_number(week_stat.value_sats as usize)
                    ));
                }
                if relevant_data.len() > 50 {
                    output.push_str(&format!(
                        "  ... and {} more entries\n",
                        relevant_data.len() - 50
                    ));
                }
            }

            output.push('\n');
            output.push_str(
                "Note: Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).\n",
            );
            output.push_str("      For full weekly data, use --format json\n");
            output.push_str("      For stacked area chart data, use --format plotly\n");

            Ok(output)
        }
    }
}
