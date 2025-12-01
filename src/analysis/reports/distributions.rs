//! Distribution analysis report formatters
//!
//! Provides formatting for transaction sizes, P2MS output counts, dust analysis,
//! and multisig configuration reports.

use super::utils::{export_json, format_bytes, format_number};
use super::OutputFormat;
use crate::analysis::tx_size_analysis::TX_SIZE_BUCKET_RANGES;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    DustAnalysisReport, MultisigConfigReport, OutputCountDistributionReport,
    TxSizeDistributionReport,
};
use crate::utils::currency::format_sats_as_btc;

/// Format transaction size distribution report
///
/// Displays transaction size analysis for P2MS transactions with:
/// - Global distribution with histogram buckets
/// - Per-protocol breakdown with size and fee statistics
/// - Percentile analysis for understanding size distributions
pub fn format_tx_sizes(
    report: &TxSizeDistributionReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json => export_json(report),
        OutputFormat::Plotly => {
            let chart = report.to_plotly_chart();
            export_json(&chart)
        }
        OutputFormat::Console => {
            let mut output = String::new();
            let global = &report.global_distribution;

            // Header
            output.push_str("\n=== TRANSACTION SIZE DISTRIBUTION ===\n\n");

            // Global distribution
            output.push_str(&format!(
                "GLOBAL DISTRIBUTION ({} transactions)\n",
                format_number(global.total_transactions)
            ));
            output.push_str(&format!(
                "Excluded: {} transactions (NULL/zero size or NULL fee)\n",
                format_number(global.excluded_null_count)
            ));
            output.push_str(&format!(
                "Total Fees Paid: {}\n",
                format_sats_as_btc(global.total_fees_sats)
            ));

            // Size range
            if let (Some(min), Some(max)) = (global.min_size_bytes, global.max_size_bytes) {
                output.push_str(&format!(
                    "Size Range: {} - {} bytes\n",
                    format_number(min as usize),
                    format_number(max as usize)
                ));
            }
            output.push_str(&format!(
                "Average: {} bytes\n\n",
                format_number(global.avg_size_bytes.round() as usize)
            ));

            // Percentiles
            if let Some(p) = &global.percentiles {
                output.push_str("PERCENTILES:\n");
                output.push_str(&format!(
                    "  25th:  {} bytes\n",
                    format_number(p.p25 as usize)
                ));
                output.push_str(&format!(
                    "  50th:  {} bytes (median)\n",
                    format_number(p.p50 as usize)
                ));
                output.push_str(&format!(
                    "  75th:  {} bytes\n",
                    format_number(p.p75 as usize)
                ));
                output.push_str(&format!(
                    "  90th:  {} bytes\n",
                    format_number(p.p90 as usize)
                ));
                output.push_str(&format!(
                    "  95th:  {} bytes\n",
                    format_number(p.p95 as usize)
                ));
                output.push_str(&format!(
                    "  99th:  {} bytes\n\n",
                    format_number(p.p99 as usize)
                ));
            }

            // Bucket distribution
            output.push_str("BUCKET DISTRIBUTION:\n");
            output.push_str(&format!(
                "  {:<22} │ {:>12} │ {:>7} │ {:>14} │\n",
                "Range (bytes)", "Transactions", "%", "Total Fees"
            ));
            output
                .push_str("  ───────────────────────┼──────────────┼─────────┼────────────────┤\n");

            for (i, bucket) in global.buckets.iter().enumerate() {
                // Use stored percentage computed during analysis
                let pct = bucket.pct_count;

                // Format range - last bucket shows "100,000+" instead of max u32
                let is_last = i == TX_SIZE_BUCKET_RANGES.len() - 1;
                let range_str = if is_last {
                    format!("{}+", format_number(bucket.range_min as usize))
                } else {
                    format!(
                        "{} - {}",
                        format_number(bucket.range_min as usize),
                        format_number(bucket.range_max as usize)
                    )
                };

                output.push_str(&format!(
                    "  {:<22} │ {:>12} │ {:>6.1}% │ {:>14} │\n",
                    range_str,
                    format_number(bucket.count),
                    pct,
                    format_sats_as_btc(bucket.value)
                ));
            }
            output.push('\n');

            // Per-protocol breakdown
            if !report.protocol_distributions.is_empty() {
                output.push_str("=== PER-PROTOCOL BREAKDOWN ===\n");
                output.push_str(
                    "(NOTE: Fees may double-count transactions with multiple protocols)\n",
                );
                output.push_str(
                    "(Excluded rows: NULL/zero size or NULL fee, per-protocol counts shown)\n\n",
                );
                output.push_str(&format!(
                    "{:<28} │ {:>12} │ {:>10} │ {:>10} │ {:>12} │\n",
                    "Protocol", "Transactions", "Excluded", "Avg Size", "Avg Fee/Byte"
                ));
                output.push_str("─────────────────────────────┼──────────────┼────────────┼────────────┼──────────────┤\n");

                for dist in &report.protocol_distributions {
                    output.push_str(&format!(
                        "{:<28} │ {:>12} │ {:>10} │ {:>8} B │ {:>10.1} sat/B │\n",
                        dist.protocol.display_name(),
                        format_number(dist.total_transactions),
                        format_number(dist.excluded_null_count),
                        format_number(dist.avg_size_bytes.round() as usize),
                        dist.avg_fee_per_byte
                    ));
                }
                output.push('\n');
            }

            Ok(output)
        }
    }
}

/// Format P2MS output count distribution report
///
/// Displays analysis of how many P2MS outputs each transaction has:
/// - Global distribution with histogram buckets
/// - Per-protocol breakdown with output count statistics
/// - Percentile analysis for understanding output patterns
pub fn format_output_count_distribution(
    report: &OutputCountDistributionReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json => export_json(report),
        OutputFormat::Plotly => {
            let chart = report.to_plotly_chart();
            export_json(&chart)
        }
        OutputFormat::Console => {
            let mut output = String::new();
            let global = &report.global_distribution;

            // Header
            output.push_str("\n=== P2MS OUTPUT COUNT DISTRIBUTION ===\n\n");

            // Global distribution
            output.push_str(&format!(
                "GLOBAL DISTRIBUTION ({} transactions)\n",
                format_number(global.total_transactions)
            ));
            output.push_str(&format!(
                "Total P2MS Outputs: {}\n",
                format_number(global.total_p2ms_outputs)
            ));
            output.push_str(&format!(
                "Total Value: {}\n",
                format_sats_as_btc(global.total_value_sats)
            ));

            // Output count range
            if let (Some(min), Some(max)) = (global.min_output_count, global.max_output_count) {
                output.push_str(&format!(
                    "Output Count Range: {} - {} outputs per tx\n",
                    format_number(min as usize),
                    format_number(max as usize)
                ));
            }
            output.push_str(&format!(
                "Average: {:.2} outputs per tx\n\n",
                global.avg_output_count
            ));

            // Percentiles
            if let Some(p) = &global.percentiles {
                output.push_str("PERCENTILES (Output Counts):\n");
                output.push_str(&format!(
                    "  25th:  {} outputs\n",
                    format_number(p.p25 as usize)
                ));
                output.push_str(&format!(
                    "  50th:  {} outputs (median)\n",
                    format_number(p.p50 as usize)
                ));
                output.push_str(&format!(
                    "  75th:  {} outputs\n",
                    format_number(p.p75 as usize)
                ));
                output.push_str(&format!(
                    "  90th:  {} outputs\n",
                    format_number(p.p90 as usize)
                ));
                output.push_str(&format!(
                    "  95th:  {} outputs\n",
                    format_number(p.p95 as usize)
                ));
                output.push_str(&format!(
                    "  99th:  {} outputs\n\n",
                    format_number(p.p99 as usize)
                ));
            }

            // Bucket distribution
            output.push_str("BUCKET DISTRIBUTION:\n");
            output.push_str(&format!(
                "  {:<15} │ {:>12} │ {:>7} │ {:>14} │ {:>7} │\n",
                "Outputs/Tx", "Transactions", "Tx %", "Total Value", "Value %"
            ));
            output.push_str(
                "  ────────────────┼──────────────┼─────────┼────────────────┼─────────┤\n",
            );

            for bucket in global.buckets.iter() {
                let range_str =
                    OutputCountDistributionReport::bucket_label(bucket.range_min, bucket.range_max);

                output.push_str(&format!(
                    "  {:<15} │ {:>12} │ {:>6.1}% │ {:>14} │ {:>6.1}% │\n",
                    range_str,
                    format_number(bucket.count),
                    bucket.pct_count,
                    format_sats_as_btc(bucket.value),
                    bucket.pct_value
                ));
            }
            output.push('\n');

            // Per-protocol breakdown
            if !report.protocol_distributions.is_empty() {
                output.push_str("=== PER-PROTOCOL BREAKDOWN ===\n");
                output.push_str("(NOTE: Transactions with multiple protocols counted in each)\n\n");
                output.push_str(&format!(
                    "{:<28} │ {:>12} │ {:>10} │ {:>10} │ {:>14} │\n",
                    "Protocol", "Transactions", "Outputs", "Avg/Tx", "Total Value"
                ));
                output.push_str("─────────────────────────────┼──────────────┼────────────┼────────────┼────────────────┤\n");

                for dist in &report.protocol_distributions {
                    output.push_str(&format!(
                        "{:<28} │ {:>12} │ {:>10} │ {:>10.2} │ {:>14} │\n",
                        dist.protocol.display_name(),
                        format_number(dist.total_transactions),
                        format_number(dist.total_p2ms_outputs),
                        dist.avg_output_count,
                        format_sats_as_btc(dist.total_value_sats)
                    ));
                }
                output.push('\n');
            }

            // Unclassified count
            if report.unclassified_transaction_count > 0 {
                output.push_str(&format!(
                    "Unclassified Transactions: {}\n",
                    format_number(report.unclassified_transaction_count)
                ));
            }

            Ok(output)
        }
    }
}

/// Format dust threshold analysis report
///
/// Displays Bitcoin Core spending dust thresholds (546/294 sats) with:
/// - Global statistics showing cumulative buckets
/// - Per-protocol breakdown sorted by canonical ProtocolType enum order
/// - Unclassified output reconciliation notes
pub fn format_dust_analysis(
    report: &DustAnalysisReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
        OutputFormat::Console => {
            let mut output = String::new();

            // Header
            output.push_str("\nDUST THRESHOLD ANALYSIS\n");
            output.push_str("═══════════════════════════════════════════════════════════════════════════════\n\n");

            // Thresholds explanation
            output.push_str("Thresholds (Bitcoin Core defaults for SPENDING P2MS outputs):\n");
            output.push_str(&format!(
                "  • Spend to non-segwit (P2PKH): {} sats\n",
                report.thresholds.non_segwit_destination_sats
            ));
            output.push_str(&format!(
                "  • Spend to segwit (P2WPKH):    {} sats\n\n",
                report.thresholds.segwit_destination_sats
            ));
            output.push_str("Note: These are destination-based spending thresholds, not creation dust limits.\n\n");

            // Global statistics
            let global = &report.global_stats;
            output.push_str(&format!(
                "GLOBAL STATISTICS ({} outputs, {})\n",
                format_number(global.total_outputs),
                format_sats_as_btc(global.total_value_sats)
            ));
            output.push_str(
                "───────────────────────────────────────────────────────────────────────────────\n",
            );

            // Below 546 (cumulative)
            output.push_str(&format!(
                "  Below {} sats (dust for non-segwit):  {} ({:>5.1}%)   {} ({:>5.1}%)\n",
                report.thresholds.non_segwit_destination_sats,
                format_number(global.below_non_segwit_threshold.count),
                global.below_non_segwit_threshold.pct_count,
                format_sats_as_btc(global.below_non_segwit_threshold.value),
                global.below_non_segwit_threshold.pct_value
            ));

            // Below 294 (subset)
            output.push_str(&format!(
                "    ├─ Below {} sats (dust for all):    {} ({:>5.1}%)   {} ({:>5.1}%)\n",
                report.thresholds.segwit_destination_sats,
                format_number(global.below_segwit_threshold.count),
                global.below_segwit_threshold.pct_count,
                format_sats_as_btc(global.below_segwit_threshold.value),
                global.below_segwit_threshold.pct_value
            ));

            // Mid-band (294-545 sats) - calculated as difference
            let mid_band_count = global
                .below_non_segwit_threshold
                .count
                .saturating_sub(global.below_segwit_threshold.count);
            let mid_band_value = global
                .below_non_segwit_threshold
                .value
                .saturating_sub(global.below_segwit_threshold.value);
            let mid_band_pct_outputs = global.below_non_segwit_threshold.pct_count
                - global.below_segwit_threshold.pct_count;
            let mid_band_pct_value = global.below_non_segwit_threshold.pct_value
                - global.below_segwit_threshold.pct_value;

            output.push_str(&format!(
                "    └─ {}-{} sats (segwit-only):      {} ({:>5.1}%)   {} ({:>5.1}%)\n",
                report.thresholds.segwit_destination_sats,
                report.thresholds.non_segwit_destination_sats - 1,
                format_number(mid_band_count),
                mid_band_pct_outputs.max(0.0),
                format_sats_as_btc(mid_band_value),
                mid_band_pct_value.max(0.0)
            ));

            // Above dust
            output.push_str(&format!(
                "  At or above {} sats (not dust):     {} ({:>5.1}%)   {} ({:>5.1}%)\n\n",
                report.thresholds.non_segwit_destination_sats,
                format_number(global.above_dust.count),
                global.above_dust.pct_count,
                format_sats_as_btc(global.above_dust.value),
                global.above_dust.pct_value
            ));

            // Per-protocol breakdown
            if !report.protocol_breakdown.is_empty() {
                output.push_str("PER-PROTOCOL BREAKDOWN\n");
                output.push_str("───────────────────────────────────────────────────────────────────────────────────────────────────\n");
                output.push_str(&format!(
                    "{:<28} │ {:>10} │ {:>14} │ {:>14} │ {:>14} │\n",
                    "Protocol", "Total", "<546 sats", "<294 sats", "≥546 sats"
                ));
                output.push_str("─────────────────────────────┼────────────┼────────────────┼────────────────┼────────────────┤\n");

                for protocol_stats in &report.protocol_breakdown {
                    output.push_str(&format!(
                        "{:<28} │ {:>10} │ {:>6} ({:>4.0}%) │ {:>6} ({:>4.0}%) │ {:>6} ({:>4.0}%) │\n",
                        protocol_stats.protocol.display_name(),
                        format_number(protocol_stats.total_outputs),
                        format_number(protocol_stats.below_non_segwit_threshold.count),
                        protocol_stats.below_non_segwit_threshold.pct_count,
                        format_number(protocol_stats.below_segwit_threshold.count),
                        protocol_stats.below_segwit_threshold.pct_count,
                        format_number(protocol_stats.above_dust.count),
                        protocol_stats.above_dust.pct_count,
                    ));
                }
                output.push('\n');
            }

            // Unclassified outputs note
            if report.unclassified_count > 0 {
                let unclassified_pct = if global.total_outputs > 0 {
                    (report.unclassified_count as f64 / global.total_outputs as f64) * 100.0
                } else {
                    0.0
                };
                output.push_str(&format!(
                    "Note: {} outputs ({:.2}%) not yet classified. Run Stage 3 to classify.\n",
                    format_number(report.unclassified_count),
                    unclassified_pct
                ));
            }

            Ok(output)
        }
    }
}

/// Format multisig configuration report
pub fn format_multisig_config_report(
    report: &MultisigConfigReport,
    format: &OutputFormat,
) -> AppResult<String> {
    match format {
        OutputFormat::Json | OutputFormat::Plotly => export_json(report),
        OutputFormat::Console => {
            let mut output = String::new();
            output.push_str("\n🔑 MULTISIG CONFIGURATION ANALYSIS\n");
            output.push_str(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
            );

            // Overall summary
            output.push_str("\n📊 Overall Statistics:\n");
            output.push_str(&format!(
                "  Total Outputs:        {}\n",
                format_number(report.total_outputs as usize)
            ));
            output.push_str(&format!(
                "  Total Script Bytes:   {}\n",
                format_bytes(report.total_script_bytes)
            ));
            output.push_str(&format!(
                "  Total Data Capacity:  {}\n",
                format_bytes(report.total_data_capacity)
            ));
            output.push_str(&format!(
                "  Overall Efficiency:   {:.1}%\n",
                report.overall_efficiency
            ));
            output.push_str(&format!(
                "  Overhead Factor:      {}\n",
                if report.total_data_capacity > 0 {
                    format!(
                        "{:.2}x",
                        report.total_script_bytes as f64 / report.total_data_capacity as f64
                    )
                } else {
                    "N/A".to_string()
                }
            ));

            // Detailed configurations table
            output.push_str("\n📋 Detailed Configurations:\n");
            output.push_str("┌────────┬──────┬───────────┬─────────┬──────────┬──────────┬───────────────┬──────────┐\n");
            output.push_str("│ M-of-N │ Keys │ Script(B) │ Data(B) │   Eff%   │ Outputs  │   Total MB    │    %     │\n");
            output.push_str("├────────┼──────┼───────────┼─────────┼──────────┼──────────┼───────────────┼──────────┤\n");

            for config in &report.configurations {
                let pct_of_total =
                    (config.output_count as f64 / report.total_outputs as f64) * 100.0;
                output.push_str(&format!(
                    "│ {:<6} │ {:<4} │ {:>9} │ {:>7} │ {:>7.1}% │ {:>8} │ {:>13} │ {:>7.2}% │\n",
                    format!("{}-of-{}", config.m, config.n),
                    config.key_config,
                    config.script_size,
                    config.data_capacity_bytes,
                    config.efficiency_pct,
                    format_number(config.output_count as usize),
                    format_bytes(config.total_script_bytes),
                    pct_of_total
                ));
            }
            output.push_str("└────────┴──────┴───────────┴─────────┴──────────┴──────────┴───────────────┴──────────┘\n");

            // Summary by type
            output.push_str("\n📈 Summary by Configuration Type:\n");
            for (config_type, count) in &report.type_summary {
                let pct = (*count as f64 / report.total_outputs as f64) * 100.0;
                output.push_str(&format!(
                    "  {:<7} {:>10} outputs ({:>6.2}%)\n",
                    config_type,
                    format_number(*count as usize),
                    pct
                ));
            }

            // Key insights
            output.push_str("\n💡 Key Insights:\n");

            // Find dominant configuration
            if let Some(dominant) = report.configurations.first() {
                let pct = (dominant.output_count as f64 / report.total_outputs as f64) * 100.0;
                output.push_str(&format!(
                    "  • Dominant: {}-of-{} {} ({:.1}% of all outputs)\n",
                    dominant.m, dominant.n, dominant.key_config, pct
                ));
            }

            // Compressed vs uncompressed
            let compressed_only: u64 = report
                .configurations
                .iter()
                .filter(|c| !c.key_config.contains('U'))
                .map(|c| c.output_count)
                .sum();
            let has_uncompressed: u64 = report
                .configurations
                .iter()
                .filter(|c| c.key_config.contains('U'))
                .map(|c| c.output_count)
                .sum();

            output.push_str(&format!(
                "  • Compressed-only: {:.1}% | Mixed/Uncompressed: {:.1}%\n",
                (compressed_only as f64 / report.total_outputs as f64) * 100.0,
                (has_uncompressed as f64 / report.total_outputs as f64) * 100.0
            ));

            Ok(output)
        }
    }
}
