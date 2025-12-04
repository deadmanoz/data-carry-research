//! Value and economic analysis report formatters
//!
//! Provides formatting for value distribution analysis, including
//! per-protocol breakdowns and Plotly-compatible visualisation data.

use super::utils::{export_json, format_number};
use super::OutputFormat;
use crate::errors::AppResult;
use crate::types::analysis_results::{ValueAnalysisReport, ValueDistributionReport};
use crate::types::visualisation::{get_protocol_colour, PlotlyChart, PlotlyLayout, PlotlyTrace};
use crate::utils::currency::{format_rate_as_btc, format_sats_as_btc, format_sats_as_btc_f64};

/// Format value analysis for console output
///
/// This provides comprehensive value distribution analysis showing BTC value locked
/// in P2MS outputs per protocol with economic insights.
pub fn format_value_analysis(
    report: &ValueAnalysisReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Console => {
            let mut output = String::new();

            // Header
            output.push_str("=== PROTOCOL VALUE DISTRIBUTION ===\n\n");

            // Table header
            output.push_str(&format!(
                "{:<28} | {:>10} | {:>14} | {:>16} | {:>14} | {:>14} |\n",
                "Protocol/Use", "Outputs", "Total BTC", "Avg BTC/Output", "Min BTC", "Max BTC"
            ));
            output.push_str(&format!("{}\n", "-".repeat(120)));

            // Protocol rows
            for protocol_stats in &report.protocol_value_breakdown {
                output.push_str(&format!(
                    "{:<28} | {:>10} | {:>14} | {:>16} | {:>14} | {:>14} |\n",
                    protocol_stats.protocol.display_name(),
                    format_number(protocol_stats.output_count),
                    format_sats_as_btc(protocol_stats.total_btc_value_sats),
                    format_sats_as_btc_f64(protocol_stats.average_btc_per_output),
                    format_sats_as_btc(protocol_stats.min_btc_value_sats),
                    format_sats_as_btc(protocol_stats.max_btc_value_sats),
                ));
            }

            // Variant value distribution section
            // Only show protocols that have variant breakdown data
            let has_variant_data = report
                .protocol_value_breakdown
                .iter()
                .any(|p| !p.variant_breakdown.is_empty() || p.null_variant_value_sats > 0);

            if has_variant_data {
                output.push_str("\n=== VARIANT VALUE DISTRIBUTION ===\n");

                for protocol_stats in &report.protocol_value_breakdown {
                    // Skip protocols with no variant data
                    if protocol_stats.variant_breakdown.is_empty()
                        && protocol_stats.null_variant_value_sats == 0
                    {
                        continue;
                    }

                    output.push_str(&format!("\n{}:\n", protocol_stats.protocol.display_name()));
                    output.push_str(&format!(
                        "  {:<28} {:>10} {:>14} {:>10}\n",
                        "Variant", "Outputs", "Total BTC", "%"
                    ));
                    output.push_str(&format!("  {}\n", "-".repeat(66)));

                    // Show non-NULL variants
                    for variant in &protocol_stats.variant_breakdown {
                        output.push_str(&format!(
                            "  {:<28} {:>10} {:>14} {:>9.2}%\n",
                            variant.variant,
                            format_number(variant.output_count),
                            format_sats_as_btc(variant.total_btc_value_sats),
                            variant.percentage,
                        ));
                    }

                    // Show NULL/unclassified variant value if non-zero
                    if protocol_stats.null_variant_value_sats > 0 {
                        let null_pct = if protocol_stats.total_btc_value_sats > 0 {
                            (protocol_stats.null_variant_value_sats as f64
                                / protocol_stats.total_btc_value_sats as f64)
                                * 100.0
                        } else {
                            0.0
                        };
                        output.push_str(&format!(
                            "  {:<28} {:>10} {:>14} {:>9.2}%\n",
                            "(unclassified)",
                            "-",
                            format_sats_as_btc(protocol_stats.null_variant_value_sats),
                            null_pct,
                        ));
                    }
                }
            }

            // Summary statistics
            output.push_str(&format!("\n{}\n", "=".repeat(120)));
            output.push_str(&format!(
                "Total BTC in P2MS outputs: {}\n",
                format_sats_as_btc(report.overall_statistics.total_btc_locked_in_p2ms)
            ));
            output.push_str(&format!(
                "Total outputs analysed:    {}\n",
                format_number(report.overall_statistics.total_outputs_analysed)
            ));
            output.push_str(&format!(
                "Total protocols:           {}\n",
                report.overall_statistics.total_protocols
            ));

            // Per-protocol fee breakdown
            output.push_str("\n=== FEE BREAKDOWN BY PROTOCOL ===\n\n");
            output.push_str(&format!(
                "{:<28} | {:>14} | {:>14} | {:>18} | {:>20} |\n",
                "Protocol", "Total Fees", "Avg Fee/Tx", "Avg Fee/Byte", "Avg Storage Cost"
            ));
            output.push_str(&format!("{}\n", "-".repeat(120)));

            for protocol_stats in &report.protocol_value_breakdown {
                output.push_str(&format!(
                    "{:<28} | {:>14} | {:>14} | {:>18} | {:>20} |\n",
                    protocol_stats.protocol.display_name(),
                    format_sats_as_btc(protocol_stats.fee_stats.total_fees_paid_sats),
                    format_sats_as_btc_f64(protocol_stats.fee_stats.average_fee_sats),
                    format_rate_as_btc(protocol_stats.fee_stats.average_fee_per_byte, "byte"),
                    format_rate_as_btc(
                        protocol_stats.fee_stats.average_storage_cost_per_byte,
                        "byte"
                    ),
                ));
            }

            // Overall fee summary
            output.push_str("\n=== OVERALL FEE SUMMARY ===\n\n");
            output.push_str(&format!(
                "Total fees paid (all protocols): {}\n",
                format_sats_as_btc(report.fee_context.fee_statistics.total_fees_paid)
            ));
            output.push_str(&format!(
                "Average fee across all tx:       {}\n",
                format_sats_as_btc_f64(report.fee_context.fee_statistics.average_fee)
            ));
            output.push_str(&format!(
                "Median fee per byte:             {}\n",
                format_rate_as_btc(
                    report.fee_context.fee_statistics.median_fee_per_byte,
                    "byte"
                )
            ));

            Ok(output)
        }
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
    }
}

/// Format value distributions for plotting (JSON output)
pub fn format_value_distributions(
    report: &ValueDistributionReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Console => {
            // For console, provide a summary view
            let mut output = String::new();
            output.push_str("=== VALUE DISTRIBUTION ANALYSIS ===\n\n");

            // Global summary
            output.push_str("GLOBAL DISTRIBUTION SUMMARY:\n");
            output.push_str(&format!(
                "Total Outputs: {}\n",
                format_number(report.global_distribution.total_outputs)
            ));
            output.push_str(&format!(
                "Total Value: {} BTC\n",
                format_sats_as_btc(report.global_distribution.total_value_sats)
            ));
            output.push_str(&format!(
                "Min/Max: {} - {} sats\n",
                report.global_distribution.min_value, report.global_distribution.max_value
            ));
            output.push_str(&format!(
                "Mean: {:.2} sats, Median: {} sats\n\n",
                report.global_distribution.mean_value, report.global_distribution.median_value
            ));

            // Show percentiles
            output.push_str("PERCENTILES:\n");
            output.push_str(&format!(
                "  25th: {} sats\n",
                report.global_distribution.percentiles.p25
            ));
            output.push_str(&format!(
                "  50th: {} sats (median)\n",
                report.global_distribution.percentiles.p50
            ));
            output.push_str(&format!(
                "  75th: {} sats\n",
                report.global_distribution.percentiles.p75
            ));
            output.push_str(&format!(
                "  90th: {} sats\n",
                report.global_distribution.percentiles.p90
            ));
            output.push_str(&format!(
                "  95th: {} sats\n",
                report.global_distribution.percentiles.p95
            ));
            output.push_str(&format!(
                "  99th: {} sats\n\n",
                report.global_distribution.percentiles.p99
            ));

            // Show top bucket distributions
            output.push_str("TOP VALUE BUCKETS (by output count):\n");
            let mut sorted_buckets = report.global_distribution.buckets.clone();
            sorted_buckets.sort_by(|a, b| b.count.cmp(&a.count));

            for bucket in sorted_buckets.iter().take(5) {
                if bucket.count > 0 {
                    let max_display = if bucket.range_max >= i64::MAX as u64 {
                        "10+ BTC".to_string()
                    } else {
                        bucket.range_max.to_string()
                    };
                    output.push_str(&format!(
                        "  {}-{} sats: {} outputs ({:.2}%), {} BTC total\n",
                        bucket.range_min,
                        max_display,
                        format_number(bucket.count),
                        bucket.pct_count,
                        format_sats_as_btc(bucket.value)
                    ));
                }
            }

            output.push_str(
                "\nNote: For full distribution data suitable for plotting, use --format json\n",
            );
            Ok(output)
        }
        OutputFormat::Json => {
            // Full JSON output for plotting
            export_json(report)
        }
        OutputFormat::Plotly => {
            // Plotly-compatible JSON for web visualisation
            export_plotly_value_distributions(report)
        }
    }
}

/// Export value distributions as Plotly-compatible JSON
///
/// Uses typed Plotly structs for type safety and consistency.
fn export_plotly_value_distributions(report: &ValueDistributionReport) -> AppResult<String> {
    // Helper to format value with K/M abbreviations or BTC for large values
    let format_value_label = |sats: u64| -> String {
        if sats >= 100_000_000 {
            // >= 1 BTC: show as BTC
            let btc = sats as f64 / 100_000_000.0;
            if btc >= 10.0 {
                format!("{:.0} BTC", btc)
            } else {
                format!("{:.1} BTC", btc)
            }
        } else if sats >= 1_000_000 {
            // >= 1M: show as M
            let m = sats as f64 / 1_000_000.0;
            if m >= 10.0 {
                format!("{}M", (sats / 1_000_000))
            } else {
                format!("{:.1}M", m)
            }
        } else if sats >= 1_000 {
            // >= 1K: show as K
            let k = sats as f64 / 1_000.0;
            if k >= 10.0 {
                format!("{}K", (sats / 1_000))
            } else {
                format!("{:.1}K", k)
            }
        } else {
            // < 1K: show as-is
            format!("{}", sats)
        }
    };

    // Create bucket labels (X-axis) with abbreviated format
    let bucket_labels: Vec<String> = report
        .bucket_ranges
        .iter()
        .map(|(min, max)| {
            if *max >= i64::MAX as u64 {
                // Top bucket: "1+ BTC" format
                format!("{}+", format_value_label(*min))
            } else if *min >= 100_000_000 {
                // BTC range: "0.1-0.5 BTC"
                format!(
                    "{}-{}",
                    format_value_label(*min).replace(" BTC", ""),
                    format_value_label(*max)
                )
            } else {
                // Satoshi ranges: "546-1K sats", "1K-2.7K sats"
                format!(
                    "{}-{} sats",
                    format_value_label(*min),
                    format_value_label(*max)
                )
            }
        })
        .collect();

    // Create traces: one for global, then one per protocol
    let mut traces = Vec::new();

    // Global distribution trace
    let global_counts: Vec<f64> = report
        .global_distribution
        .buckets
        .iter()
        .map(|b| b.count as f64)
        .collect();

    traces.push(PlotlyTrace::bar(
        bucket_labels.clone(),
        global_counts,
        "All P2MS Outputs",
        "#34495E",
    ));

    // Per-protocol traces (sorted by canonical ProtocolType enum order)
    let mut protocol_dists = report.protocol_distributions.clone();
    protocol_dists.sort_by_key(|p| p.protocol as u8);

    for protocol_dist in &protocol_dists {
        let protocol_counts: Vec<f64> = protocol_dist
            .buckets
            .iter()
            .map(|b| b.count as f64)
            .collect();

        // Use display_name() directly (no parsing needed)
        let display_name = protocol_dist.protocol.display_name();

        let colour = get_protocol_colour(protocol_dist.protocol);

        traces.push(
            PlotlyTrace::bar(bucket_labels.clone(), protocol_counts, display_name, colour)
                .hidden_by_default(),
        );
    }

    // Create layout using typed builders
    let mut layout = PlotlyLayout::basic(
        "P2MS Output Value Distribution",
        "Value Range (satoshis)",
        "Number of Outputs",
    )
    .with_title_font_size(16)
    .with_legend("v", 1.02, 1.0, "left")
    .with_log_toggle();

    // Set axis types
    layout.xaxis.axis_type = Some("category".to_string());
    layout.yaxis.axis_type = Some("log".to_string());
    layout.barmode = Some("overlay".to_string());

    // Create chart
    let chart = PlotlyChart {
        data: traces,
        layout,
    };

    serde_json::to_string_pretty(&chart)
        .map_err(|e| crate::errors::AppError::Config(format!("Plotly JSON export failed: {}", e)))
}
