//! Report formatting and output generation
//!
//! This module provides formatting functionality for analysis results,
//! replacing the echo statements in justfile commands with structured output.

use super::tx_size_analysis::TX_SIZE_BUCKET_RANGES;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    BurnPatternAnalysis, ClassificationStatsReport, ComprehensiveDataSizeReport,
    ContentTypeSpendabilityReport, DustAnalysisReport, FeeAnalysisReport, FileExtensionReport,
    FullAnalysisReport, MultisigConfigReport, OutputCountDistributionReport,
    ProtocolDataSizeReport, SignatureAnalysisReport, SpendabilityDataSizeReport,
    SpendabilityStatsReport, StampsWeeklyFeeReport, TxSizeDistributionReport, ValueAnalysisReport,
    ValueDistributionReport,
};
use crate::types::visualisation::{get_protocol_colour, PlotlyChart};
use crate::utils::currency::{format_rate_as_btc, format_sats_as_btc, format_sats_as_btc_f64};
use serde::Serialize;
use std::str::FromStr;

/// Output format options for analysis reports
#[derive(Debug, Clone, Default)]
pub enum OutputFormat {
    /// Human-readable console output (matches current justfile output)
    #[default]
    Console,
    /// JSON format for programmatic use
    Json,
    /// Plotly-compatible JSON format for web visualisation
    Plotly,
}

/// Report formatter for analysis results
pub struct ReportFormatter;

impl ReportFormatter {
    /// Format number with thousand separators for console output
    ///
    /// # Arguments
    ///
    /// * `n` - Number to format
    ///
    /// # Returns
    ///
    /// String with comma separators (e.g., "1,234,567")
    ///
    /// # Examples
    ///
    /// ```
    /// # use data_carry_research::analysis::ReportFormatter;
    /// assert_eq!(ReportFormatter::format_number(1234), "1,234");
    /// assert_eq!(ReportFormatter::format_number(1234567), "1,234,567");
    /// assert_eq!(ReportFormatter::format_number(904233), "904,233");
    /// ```
    pub fn format_number(n: usize) -> String {
        let s = n.to_string();
        let mut result = String::new();
        let chars: Vec<char> = s.chars().collect();

        for (i, c) in chars.iter().enumerate() {
            if i > 0 && (chars.len() - i) % 3 == 0 {
                result.push(',');
            }
            result.push(*c);
        }

        result
    }

    /// Format byte counts using conventional units (KB, MB, GB)
    pub fn format_bytes(bytes: u64) -> String {
        const KB: f64 = 1024.0;
        const MB: f64 = KB * 1024.0;
        const GB: f64 = MB * 1024.0;

        if bytes == 0 {
            "0 B".to_string()
        } else if bytes as f64 >= GB {
            format!("{:.2} GB", bytes as f64 / GB)
        } else if bytes as f64 >= MB {
            format!("{:.2} MB", bytes as f64 / MB)
        } else if bytes as f64 >= KB {
            format!("{:.2} KB", bytes as f64 / KB)
        } else {
            format!("{} B", bytes)
        }
    }

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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(analysis),
        }
    }

    /// Format fee analysis results for console output
    pub fn format_fee_analysis(
        report: &FeeAnalysisReport,
        format: &OutputFormat,
    ) -> AppResult<String> {
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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
        }
    }

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
                        Self::format_protocol_name(&protocol_stats.protocol),
                        Self::format_number(protocol_stats.output_count),
                        format_sats_as_btc(protocol_stats.total_btc_value_sats),
                        format_sats_as_btc_f64(protocol_stats.average_btc_per_output),
                        format_sats_as_btc(protocol_stats.min_btc_value_sats),
                        format_sats_as_btc(protocol_stats.max_btc_value_sats),
                    ));
                }

                // Summary statistics
                output.push_str(&format!("\n{}\n", "=".repeat(120)));
                output.push_str(&format!(
                    "Total BTC in P2MS outputs: {}\n",
                    format_sats_as_btc(report.overall_statistics.total_btc_locked_in_p2ms)
                ));
                output.push_str(&format!(
                    "Total outputs analysed:    {}\n",
                    Self::format_number(report.overall_statistics.total_outputs_analysed)
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
                        Self::format_protocol_name(&protocol_stats.protocol),
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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
        }
    }

    /// Format protocol name for display (convert internal names to readable format)
    fn format_protocol_name(protocol: &str) -> String {
        match protocol {
            "BitcoinStamps" => "Bitcoin Stamps".to_string(),
            "Counterparty" => "Counterparty".to_string(),
            "OmniLayer" => "Omni Layer".to_string(),
            "LikelyLegitimateMultisig" => "Likely Legitimate Multisig".to_string(),
            "DataStorage" => "Data Storage".to_string(),
            "LikelyDataStorage" => "Likely Data Storage".to_string(),
            "Chancecoin" => "Chancecoin".to_string(),
            "AsciiIdentifierProtocols" => "ASCII Identifier Protocols".to_string(),
            "Unknown" => "Unknown".to_string(),
            _ => protocol.to_string(),
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
                    Self::format_number(report.global_distribution.total_outputs)
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
                            Self::format_number(bucket.count),
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
                Self::export_json(report)
            }
            OutputFormat::Plotly => {
                // Plotly-compatible JSON for web visualisation
                Self::export_plotly_value_distributions(report)
            }
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
                            sample.protocol,
                            sample.variant,
                            sample.classification_method,
                            sample.count
                        ));
                    }
                }

                Ok(output)
            }
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
        }
    }

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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
        }
    }

    /// Format file extension statistics for console or JSON output
    pub fn format_file_extension_report(
        report: &FileExtensionReport,
        format: &OutputFormat,
    ) -> AppResult<String> {
        match format {
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
            OutputFormat::Console => {
                if report.total_transactions == 0 {
                    return Ok("=== FILE TYPE BREAKDOWN ===\nNo classified transactions with content types.\n".to_string());
                }

                let mut output = String::new();
                output.push_str("=== FILE TYPE BREAKDOWN ===\n");
                output.push_str(&format!(
                    "Totals: {} transactions, {} outputs, {}\n\n",
                    Self::format_number(report.total_transactions),
                    Self::format_number(report.total_outputs),
                    Self::format_bytes(report.total_bytes)
                ));

                for category in &report.categories {
                    let totals = &category.category_totals;
                    output.push_str(&format!(
                        "{}: {:.1}% ({})\n",
                        category.category,
                        totals.byte_percentage,
                        Self::format_bytes(totals.total_bytes)
                    ));

                    for ext in &category.extensions {
                        output.push_str(&format!(
                            "  {:<10} {:>8} outputs {:>10}  (tx {:.1}%, out {:.1}%, bytes {:.1}%)\n",
                            ext.extension,
                            Self::format_number(ext.output_count),
                            Self::format_bytes(ext.total_bytes),
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
    pub fn format_full_report(
        report: &FullAnalysisReport,
        format: &OutputFormat,
    ) -> AppResult<String> {
        match format {
            OutputFormat::Console => {
                let mut output = format!(
                    "Full Analysis Report\nGenerated: {}\n\n",
                    report.generated_at
                );

                // Burn patterns section
                output.push_str("=== BURN PATTERNS ===\n");
                output.push_str(&Self::format_burn_patterns(
                    &report.burn_patterns,
                    &OutputFormat::Console,
                )?);
                output.push('\n');

                // Fee analysis section
                output.push_str("=== FEE ANALYSIS ===\n");
                output.push_str(&Self::format_fee_analysis(
                    &report.fee_analysis,
                    &OutputFormat::Console,
                )?);
                output.push('\n');

                // Classification stats section
                output.push_str("=== CLASSIFICATION STATISTICS ===\n");
                output.push_str(&Self::format_classification_stats(
                    &report.classifications,
                    &OutputFormat::Console,
                )?);
                output.push('\n');

                // Signature analysis section
                output.push_str("=== SIGNATURE ANALYSIS ===\n");
                output.push_str(&Self::format_signature_analysis(
                    &report.signatures,
                    &OutputFormat::Console,
                )?);
                output.push('\n');

                // Spendability analysis section
                output.push_str("=== SPENDABILITY ANALYSIS ===\n");
                output.push_str(&Self::format_spendability_report(
                    &report.spendability,
                    &OutputFormat::Console,
                )?);

                // Data size analysis section (optional)
                if let Some(ref data_size) = report.data_size {
                    output.push('\n');
                    output.push_str("=== DATA SIZE ANALYSIS ===\n");
                    output.push_str(&Self::format_comprehensive_data_size_report(
                        data_size,
                        &OutputFormat::Console,
                    )?);
                }

                if let Some(ref file_extensions) = report.file_extensions {
                    output.push('\n');
                    output.push_str(&Self::format_file_extension_report(
                        file_extensions,
                        &OutputFormat::Console,
                    )?);
                }

                // Bitcoin Stamps transport section (optional)
                if let Some(ref transport_stats) = report.stamps_transport {
                    output.push('\n');
                    output.push_str(&Self::format_stamps_transport(
                        transport_stats,
                        &OutputFormat::Console,
                    )?);
                }

                // Bitcoin Stamps signature variants section (optional)
                if let Some(ref signature_stats) = report.stamps_signatures {
                    output.push('\n');
                    output.push_str(&Self::format_stamps_signatures(
                        signature_stats,
                        &OutputFormat::Console,
                    )?);
                }

                Ok(output)
            }
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
        }
    }

    /// Format Bitcoin Stamps transport mechanism statistics
    ///
    /// This shows the breakdown of Pure vs Counterparty transport mechanisms
    /// for Bitcoin Stamps transactions, including spendability analysis.
    pub fn format_stamps_transport(
        stats: &super::stamps_transport_stats::StampsTransportAnalysis,
        format: &OutputFormat,
    ) -> AppResult<String> {
        match format {
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(stats),
            OutputFormat::Console => {
                let mut output = String::new();
                output.push_str("\n📊 Bitcoin Stamps Transport Analysis\n");
                output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                output.push_str(&format!(
                    "Total Transactions:     {}\n",
                    Self::format_number(stats.total_transactions)
                ));
                output.push_str(&format!(
                    "Total Outputs:          {}\n\n",
                    Self::format_number(stats.total_outputs)
                ));

                // Pure Stamps section
                output.push_str(&format!(
                    "Pure Bitcoin Stamps:    {} ({:.1}%)\n",
                    Self::format_number(stats.pure_stamps.transaction_count),
                    stats.pure_stamps.transaction_percentage
                ));
                output.push_str(&format!(
                    "  └─ Outputs:           {} ({} spendable, {} unspendable)\n\n",
                    Self::format_number(stats.pure_stamps.total_outputs),
                    Self::format_number(stats.pure_stamps.spendable_outputs),
                    Self::format_number(stats.pure_stamps.unspendable_outputs)
                ));

                // Counterparty transport section
                output.push_str(&format!(
                    "Counterparty Transport: {} ({:.1}%)\n",
                    Self::format_number(stats.counterparty_transport.transaction_count),
                    stats.counterparty_transport.transaction_percentage
                ));
                output.push_str(&format!(
                    "  ├─ Spendable:         {}\n",
                    Self::format_number(stats.counterparty_transport.spendable_outputs)
                ));
                output.push_str(&format!(
                    "  └─ Unspendable:       {}\n\n",
                    Self::format_number(stats.counterparty_transport.unspendable_outputs)
                ));

                // Variant breakdown (only if non-empty)
                if !stats.counterparty_transport.variant_breakdown.is_empty() {
                    output.push_str("Counterparty-Transported Variants:\n");
                    for variant in &stats.counterparty_transport.variant_breakdown {
                        output.push_str(&format!(
                            "  {:<20} {} ({:.1}%)\n",
                            variant.variant,
                            Self::format_number(variant.count),
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
        stats: &super::stamps_signature_stats::StampsSignatureAnalysis,
        format: &OutputFormat,
    ) -> AppResult<String> {
        match format {
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(stats),
            OutputFormat::Console => {
                let mut output = String::new();
                output.push_str("\n📊 Bitcoin Stamps Signature Variants\n");
                output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                output.push_str(&format!(
                    "Total Classified: {}\n\n",
                    Self::format_number(stats.total_stamps)
                ));

                // Overall distribution
                if !stats.signature_distribution.is_empty() {
                    output.push_str("Overall Distribution:\n");
                    for sig in &stats.signature_distribution {
                        output.push_str(&format!(
                            "  {:<10} {} ({:.2}%)\n",
                            sig.variant,
                            Self::format_number(sig.count),
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
                            Self::format_number(sig.count),
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
                            Self::format_number(sig.count),
                            sig.percentage
                        ));
                    }
                }

                Ok(output)
            }
        }
    }

    /// Export data as JSON for programmatic use
    pub fn export_json<T: Serialize>(data: &T) -> AppResult<String> {
        serde_json::to_string_pretty(data)
            .map_err(|e| crate::errors::AppError::Config(format!("JSON export failed: {}", e)))
    }

    /// Export value distributions as Plotly-compatible JSON
    fn export_plotly_value_distributions(report: &ValueDistributionReport) -> AppResult<String> {
        use serde_json::json;

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
        let global_counts: Vec<usize> = report
            .global_distribution
            .buckets
            .iter()
            .map(|b| b.count)
            .collect();

        traces.push(json!({
            "x": bucket_labels,
            "y": global_counts,
            "name": "All P2MS Outputs",
            "type": "bar",
            "marker": {
                "color": "#34495E"
            }
        }));

        // Per-protocol traces (sorted by canonical ProtocolType enum order)
        let mut protocol_dists = report.protocol_distributions.clone();
        protocol_dists.sort_by(|a, b| {
            use crate::types::ProtocolType;
            use std::str::FromStr;
            let a_order = ProtocolType::from_str(&a.protocol)
                .map(|p| p as u8)
                .unwrap_or(u8::MAX);
            let b_order = ProtocolType::from_str(&b.protocol)
                .map(|p| p as u8)
                .unwrap_or(u8::MAX);
            a_order.cmp(&b_order)
        });

        for protocol_dist in &protocol_dists {
            let protocol_counts: Vec<usize> =
                protocol_dist.buckets.iter().map(|b| b.count).collect();

            // Use display_name() for user-facing trace names, fall back to raw string
            let display_name = crate::types::ProtocolType::from_str(&protocol_dist.protocol)
                .map(|p| p.display_name().to_string())
                .unwrap_or_else(|_| protocol_dist.protocol.clone());

            traces.push(json!({
                "x": bucket_labels,
                "y": protocol_counts,
                "name": display_name,
                "type": "bar",
                "marker": {
                    // Use raw protocol string for colour lookup (matches get_protocol_colour keys)
                    "color": get_protocol_colour(&protocol_dist.protocol)
                },
                "visible": "legendonly"  // Hidden by default, show in legend
            }));
        }

        // Create layout
        let layout = json!({
            "title": {
                "text": "P2MS Output Value Distribution",
                "font": {"size": 16}
            },
            "xaxis": {
                "title": "Value Range (satoshis)",
                "type": "category"
            },
            "yaxis": {
                "title": "Number of Outputs",
                "type": "log"  // Log scale for better visibility
            },
            "barmode": "overlay",
            "legend": {
                "orientation": "v",
                "x": 1.02,
                "y": 1,
                "xanchor": "left"
            },
            "hovermode": "x unified"
        });

        // Combine into Plotly format
        let plotly_data = json!({
            "data": traces,
            "layout": layout
        });

        serde_json::to_string_pretty(&plotly_data).map_err(|e| {
            crate::errors::AppError::Config(format!("Plotly JSON export failed: {}", e))
        })
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Data Size Analysis Formatters
    // ═══════════════════════════════════════════════════════════════════════════

    /// Format protocol-level data size report
    pub fn format_protocol_data_size_report(
        report: &ProtocolDataSizeReport,
        format: &OutputFormat,
    ) -> AppResult<String> {
        match format {
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
            OutputFormat::Console => {
                let mut output = String::new();
                output.push_str("\n📊 PROTOCOL DATA SIZES\n");
                output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                output.push_str(&format!(
                    "Total P2MS Data:  {} across {} outputs ({} transactions)\n\n",
                    Self::format_bytes(report.total_bytes),
                    Self::format_number(report.total_outputs),
                    Self::format_number(report.total_transactions)
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
                        Self::format_bytes(protocol.total_bytes),
                        protocol.percentage_of_total
                    ));
                    output.push_str(&format!(
                        "  Outputs:        {} ({} transactions)\n",
                        Self::format_number(protocol.output_count),
                        Self::format_number(protocol.transaction_count)
                    ));
                    output.push_str(&format!(
                        "  Avg/Min/Max:    {} / {} / {}\n",
                        Self::format_bytes(protocol.average_bytes as u64),
                        Self::format_bytes(protocol.min_bytes),
                        Self::format_bytes(protocol.max_bytes)
                    ));
                    output.push_str(&format!(
                        "  Spendable:      {} ({:.1}%)\n",
                        Self::format_bytes(protocol.spendable_bytes),
                        protocol.spendable_percentage
                    ));
                    output.push_str(&format!(
                        "  Unspendable:    {}\n\n",
                        Self::format_bytes(protocol.unspendable_bytes)
                    ));
                }

                Ok(output)
            }
        }
    }

    /// Format spendability-focused data size report
    pub fn format_spendability_data_size_report(
        report: &SpendabilityDataSizeReport,
        format: &OutputFormat,
    ) -> AppResult<String> {
        match format {
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
            OutputFormat::Console => {
                let mut output = String::new();
                output.push_str("\n📊 DATA SIZE BY SPENDABILITY\n");
                output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

                let overall = &report.overall;
                output.push_str(&format!(
                    "Total P2MS Data:    {} ({} transactions)\n\n",
                    Self::format_bytes(overall.total_bytes),
                    Self::format_number(overall.total_transactions)
                ));

                output.push_str(&format!(
                    "✅ Spendable:       {} ({:.1}%) - {} outputs\n",
                    Self::format_bytes(overall.spendable_bytes),
                    overall.spendable_percentage,
                    Self::format_number(overall.spendable_output_count)
                ));
                output.push_str(&format!(
                    "🔒 Unspendable:     {} ({:.1}%) - {} outputs\n\n",
                    Self::format_bytes(overall.unspendable_bytes),
                    100.0 - overall.spendable_percentage,
                    Self::format_number(overall.unspendable_output_count)
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
                            Self::format_bytes(protocol_data.spendable_bytes),
                            spendable_pct,
                            Self::format_bytes(protocol_data.unspendable_bytes)
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
                            Self::format_bytes(reason_data.total_bytes),
                            reason_data.percentage_of_total,
                            Self::format_number(reason_data.output_count)
                        ));
                    }
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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
            OutputFormat::Console => {
                let mut output = String::new();
                output.push_str("\n📊 CONTENT TYPE × SPENDABILITY ANALYSIS\n");
                output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                output.push_str(&format!(
                    "Total P2MS Data:  {} ({} transactions)\n\n",
                    Self::format_bytes(report.total_bytes),
                    Self::format_number(report.total_transactions)
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
                        Self::format_bytes(totals.total_bytes),
                        spendable_pct,
                        Self::format_number(totals.transaction_count),
                        Self::format_number(totals.output_count)
                    ));

                    // Show content types within category
                    for ct in &category.content_types {
                        output.push_str(&format!(
                            "  {:<25} {} (spendable: {}, unspendable: {})\n",
                            format!("{} ({})", ct.extension, ct.mime_type),
                            Self::format_bytes(ct.total_bytes),
                            Self::format_bytes(ct.spendable_bytes),
                            Self::format_bytes(ct.unspendable_bytes)
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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
            OutputFormat::Console => {
                let mut output = String::new();
                output.push_str("\n📊 COMPREHENSIVE DATA SIZE ANALYSIS\n");
                output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

                let summary = &report.overall_summary;
                output.push_str("\n🔍 Overall Summary:\n");
                output.push_str(&format!(
                    "  Total P2MS Data:           {}\n",
                    Self::format_bytes(summary.total_p2ms_bytes)
                ));
                output.push_str(&format!(
                    "  Total Outputs:             {}\n",
                    Self::format_number(summary.total_outputs)
                ));
                output.push_str(&format!(
                    "  Total Transactions:        {}\n",
                    Self::format_number(summary.total_transactions)
                ));
                output.push_str(&format!(
                    "  Average Bytes per Output:  {}\n",
                    Self::format_bytes(summary.average_bytes_per_output as u64)
                ));
                output.push_str(&format!(
                    "  Spendable Percentage:      {:.1}%\n",
                    summary.spendable_percentage
                ));

                // Protocol breakdown
                output.push_str("\n\n");
                output.push_str(&Self::format_protocol_data_size_report(
                    &report.protocol_breakdown,
                    &OutputFormat::Console,
                )?);

                // Spendability breakdown
                output.push('\n');
                output.push_str(&Self::format_spendability_data_size_report(
                    &report.spendability_breakdown,
                    &OutputFormat::Console,
                )?);

                // Content type breakdown
                output.push('\n');
                output.push_str(&Self::format_content_type_spendability_report(
                    &report.content_type_breakdown,
                    &OutputFormat::Console,
                )?);

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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
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
                    Self::format_number(report.total_outputs as usize)
                ));
                output.push_str(&format!(
                    "  Total Script Bytes:   {}\n",
                    Self::format_bytes(report.total_script_bytes)
                ));
                output.push_str(&format!(
                    "  Total Data Capacity:  {}\n",
                    Self::format_bytes(report.total_data_capacity)
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
                        Self::format_number(config.output_count as usize),
                        Self::format_bytes(config.total_script_bytes),
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
                        Self::format_number(*count as usize),
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

    // ═══════════════════════════════════════════════════════════════════════════
    // Dust Threshold Analysis Formatter
    // ═══════════════════════════════════════════════════════════════════════════

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
            OutputFormat::Json | OutputFormat::Plotly => Self::export_json(report),
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
                    Self::format_number(global.total_outputs),
                    format_sats_as_btc(global.total_value_sats)
                ));
                output.push_str("───────────────────────────────────────────────────────────────────────────────\n");

                // Below 546 (cumulative)
                output.push_str(&format!(
                    "  Below {} sats (dust for non-segwit):  {} ({:>5.1}%)   {} ({:>5.1}%)\n",
                    report.thresholds.non_segwit_destination_sats,
                    Self::format_number(global.below_non_segwit_threshold.count),
                    global.below_non_segwit_threshold.pct_count,
                    format_sats_as_btc(global.below_non_segwit_threshold.value),
                    global.below_non_segwit_threshold.pct_value
                ));

                // Below 294 (subset)
                output.push_str(&format!(
                    "    ├─ Below {} sats (dust for all):    {} ({:>5.1}%)   {} ({:>5.1}%)\n",
                    report.thresholds.segwit_destination_sats,
                    Self::format_number(global.below_segwit_threshold.count),
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
                    Self::format_number(mid_band_count),
                    mid_band_pct_outputs.max(0.0),
                    format_sats_as_btc(mid_band_value),
                    mid_band_pct_value.max(0.0)
                ));

                // Above dust
                output.push_str(&format!(
                    "  At or above {} sats (not dust):     {} ({:>5.1}%)   {} ({:>5.1}%)\n\n",
                    report.thresholds.non_segwit_destination_sats,
                    Self::format_number(global.above_dust.count),
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
                            Self::format_protocol_name(&protocol_stats.protocol.to_string()),
                            Self::format_number(protocol_stats.total_outputs),
                            Self::format_number(protocol_stats.below_non_segwit_threshold.count),
                            protocol_stats.below_non_segwit_threshold.pct_count,
                            Self::format_number(protocol_stats.below_segwit_threshold.count),
                            protocol_stats.below_segwit_threshold.pct_count,
                            Self::format_number(protocol_stats.above_dust.count),
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
                        Self::format_number(report.unclassified_count),
                        unclassified_pct
                    ));
                }

                Ok(output)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Bitcoin Stamps Weekly Fee Analysis Formatter
    // ═══════════════════════════════════════════════════════════════════════════

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
            OutputFormat::Json => Self::export_json(report),
            OutputFormat::Plotly => {
                let chart: PlotlyChart = report.to_plotly_chart();
                Self::export_json(&chart)
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
                    Self::format_number(report.total_transactions)
                ));
                output.push_str(&format!(
                    "Total Fees: {} BTC ({} sats)\n",
                    format_sats_as_btc(report.total_fees_sats),
                    Self::format_number(report.total_fees_sats as usize)
                ));
                output.push_str(&format!(
                    "Average Fee/Tx: {} sats\n",
                    Self::format_number(summary.avg_fee_per_tx_sats as usize)
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
                        Self::format_number(week.transaction_count),
                        format_sats_as_btc(week.total_fees_sats),
                        Self::format_number(week.avg_fee_sats.round() as usize),
                        script_kb,
                        week.avg_fee_per_byte_sats
                    ));
                }

                output.push('\n');
                output.push_str(&format!(
                    "Total Weeks: {}\n",
                    Self::format_number(report.total_weeks)
                ));
                output.push_str(
                    "\nNote: Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).\n",
                );
                output.push_str("      For Plotly-compatible JSON output, use --format plotly\n");

                Ok(output)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transaction Size Distribution Formatter
    // ═══════════════════════════════════════════════════════════════════════════

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
            OutputFormat::Json => Self::export_json(report),
            OutputFormat::Plotly => {
                let chart = report.to_plotly_chart();
                Self::export_json(&chart)
            }
            OutputFormat::Console => {
                let mut output = String::new();
                let global = &report.global_distribution;

                // Header
                output.push_str("\n=== TRANSACTION SIZE DISTRIBUTION ===\n\n");

                // Global distribution
                output.push_str(&format!(
                    "GLOBAL DISTRIBUTION ({} transactions)\n",
                    Self::format_number(global.total_transactions)
                ));
                output.push_str(&format!(
                    "Excluded: {} transactions (NULL/zero size or NULL fee)\n",
                    Self::format_number(global.excluded_null_count)
                ));
                output.push_str(&format!(
                    "Total Fees Paid: {}\n",
                    format_sats_as_btc(global.total_fees_sats)
                ));

                // Size range
                if let (Some(min), Some(max)) = (global.min_size_bytes, global.max_size_bytes) {
                    output.push_str(&format!(
                        "Size Range: {} - {} bytes\n",
                        Self::format_number(min as usize),
                        Self::format_number(max as usize)
                    ));
                }
                output.push_str(&format!(
                    "Average: {} bytes\n\n",
                    Self::format_number(global.avg_size_bytes.round() as usize)
                ));

                // Percentiles
                if let Some(p) = &global.percentiles {
                    output.push_str("PERCENTILES:\n");
                    output.push_str(&format!(
                        "  25th:  {} bytes\n",
                        Self::format_number(p.p25 as usize)
                    ));
                    output.push_str(&format!(
                        "  50th:  {} bytes (median)\n",
                        Self::format_number(p.p50 as usize)
                    ));
                    output.push_str(&format!(
                        "  75th:  {} bytes\n",
                        Self::format_number(p.p75 as usize)
                    ));
                    output.push_str(&format!(
                        "  90th:  {} bytes\n",
                        Self::format_number(p.p90 as usize)
                    ));
                    output.push_str(&format!(
                        "  95th:  {} bytes\n",
                        Self::format_number(p.p95 as usize)
                    ));
                    output.push_str(&format!(
                        "  99th:  {} bytes\n\n",
                        Self::format_number(p.p99 as usize)
                    ));
                }

                // Bucket distribution
                output.push_str("BUCKET DISTRIBUTION:\n");
                output.push_str(&format!(
                    "  {:<22} │ {:>12} │ {:>7} │ {:>14} │\n",
                    "Range (bytes)", "Transactions", "%", "Total Fees"
                ));
                output.push_str(
                    "  ───────────────────────┼──────────────┼─────────┼────────────────┤\n",
                );

                for (i, bucket) in global.buckets.iter().enumerate() {
                    // Use stored percentage computed during analysis
                    let pct = bucket.pct_count;

                    // Format range - last bucket shows "100,000+" instead of max u32
                    let is_last = i == TX_SIZE_BUCKET_RANGES.len() - 1;
                    let range_str = if is_last {
                        format!("{}+", Self::format_number(bucket.range_min as usize))
                    } else {
                        format!(
                            "{} - {}",
                            Self::format_number(bucket.range_min as usize),
                            Self::format_number(bucket.range_max as usize)
                        )
                    };

                    output.push_str(&format!(
                        "  {:<22} │ {:>12} │ {:>6.1}% │ {:>14} │\n",
                        range_str,
                        Self::format_number(bucket.count),
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
                    output.push_str("(Excluded rows: NULL/zero size or NULL fee, per-protocol counts shown)\n\n");
                    output.push_str(&format!(
                        "{:<28} │ {:>12} │ {:>10} │ {:>10} │ {:>12} │\n",
                        "Protocol", "Transactions", "Excluded", "Avg Size", "Avg Fee/Byte"
                    ));
                    output.push_str("─────────────────────────────┼──────────────┼────────────┼────────────┼──────────────┤\n");

                    for dist in &report.protocol_distributions {
                        output.push_str(&format!(
                            "{:<28} │ {:>12} │ {:>10} │ {:>8} B │ {:>10.1} sat/B │\n",
                            Self::format_protocol_name(&dist.protocol.to_string()),
                            Self::format_number(dist.total_transactions),
                            Self::format_number(dist.excluded_null_count),
                            Self::format_number(dist.avg_size_bytes.round() as usize),
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
            OutputFormat::Json => Self::export_json(report),
            OutputFormat::Plotly => {
                let chart = report.to_plotly_chart();
                Self::export_json(&chart)
            }
            OutputFormat::Console => {
                let mut output = String::new();
                let global = &report.global_distribution;

                // Header
                output.push_str("\n=== P2MS OUTPUT COUNT DISTRIBUTION ===\n\n");

                // Global distribution
                output.push_str(&format!(
                    "GLOBAL DISTRIBUTION ({} transactions)\n",
                    Self::format_number(global.total_transactions)
                ));
                output.push_str(&format!(
                    "Total P2MS Outputs: {}\n",
                    Self::format_number(global.total_p2ms_outputs)
                ));
                output.push_str(&format!(
                    "Total Value: {}\n",
                    format_sats_as_btc(global.total_value_sats)
                ));

                // Output count range
                if let (Some(min), Some(max)) = (global.min_output_count, global.max_output_count) {
                    output.push_str(&format!(
                        "Output Count Range: {} - {} outputs per tx\n",
                        Self::format_number(min as usize),
                        Self::format_number(max as usize)
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
                        Self::format_number(p.p25 as usize)
                    ));
                    output.push_str(&format!(
                        "  50th:  {} outputs (median)\n",
                        Self::format_number(p.p50 as usize)
                    ));
                    output.push_str(&format!(
                        "  75th:  {} outputs\n",
                        Self::format_number(p.p75 as usize)
                    ));
                    output.push_str(&format!(
                        "  90th:  {} outputs\n",
                        Self::format_number(p.p90 as usize)
                    ));
                    output.push_str(&format!(
                        "  95th:  {} outputs\n",
                        Self::format_number(p.p95 as usize)
                    ));
                    output.push_str(&format!(
                        "  99th:  {} outputs\n\n",
                        Self::format_number(p.p99 as usize)
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
                    let range_str = OutputCountDistributionReport::bucket_label(
                        bucket.range_min,
                        bucket.range_max,
                    );

                    output.push_str(&format!(
                        "  {:<15} │ {:>12} │ {:>6.1}% │ {:>14} │ {:>6.1}% │\n",
                        range_str,
                        Self::format_number(bucket.count),
                        bucket.pct_count,
                        format_sats_as_btc(bucket.value),
                        bucket.pct_value
                    ));
                }
                output.push('\n');

                // Per-protocol breakdown
                if !report.protocol_distributions.is_empty() {
                    output.push_str("=== PER-PROTOCOL BREAKDOWN ===\n");
                    output.push_str(
                        "(NOTE: Transactions with multiple protocols counted in each)\n\n",
                    );
                    output.push_str(&format!(
                        "{:<28} │ {:>12} │ {:>10} │ {:>10} │ {:>14} │\n",
                        "Protocol", "Transactions", "Outputs", "Avg/Tx", "Total Value"
                    ));
                    output.push_str("─────────────────────────────┼──────────────┼────────────┼────────────┼────────────────┤\n");

                    for dist in &report.protocol_distributions {
                        output.push_str(&format!(
                            "{:<28} │ {:>12} │ {:>10} │ {:>10.2} │ {:>14} │\n",
                            Self::format_protocol_name(&dist.protocol.to_string()),
                            Self::format_number(dist.total_transactions),
                            Self::format_number(dist.total_p2ms_outputs),
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
                        Self::format_number(report.unclassified_transaction_count)
                    ));
                }

                Ok(output)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::analysis_results::{
        CategoryBreakdown, CategoryTotals, ExtensionStats, FileExtensionReport,
    };

    #[test]
    fn test_format_number() {
        // Small numbers
        assert_eq!(ReportFormatter::format_number(0), "0");
        assert_eq!(ReportFormatter::format_number(1), "1");
        assert_eq!(ReportFormatter::format_number(99), "99");
        assert_eq!(ReportFormatter::format_number(123), "123");

        // Thousands
        assert_eq!(ReportFormatter::format_number(1_000), "1,000");
        assert_eq!(ReportFormatter::format_number(1_234), "1,234");
        assert_eq!(ReportFormatter::format_number(9_999), "9,999");

        // Ten thousands
        assert_eq!(ReportFormatter::format_number(10_000), "10,000");
        assert_eq!(ReportFormatter::format_number(12_345), "12,345");
        assert_eq!(ReportFormatter::format_number(99_999), "99,999");

        // Hundreds of thousands
        assert_eq!(ReportFormatter::format_number(100_000), "100,000");
        assert_eq!(ReportFormatter::format_number(123_456), "123,456");
        assert_eq!(ReportFormatter::format_number(999_999), "999,999");

        // Millions
        assert_eq!(ReportFormatter::format_number(1_000_000), "1,000,000");
        assert_eq!(ReportFormatter::format_number(1_234_567), "1,234,567");
        assert_eq!(ReportFormatter::format_number(12_345_678), "12,345,678");

        // Real-world examples from Bitcoin Stamps data
        assert_eq!(ReportFormatter::format_number(904_233), "904,233");
        assert_eq!(ReportFormatter::format_number(78_263), "78,263");
        assert_eq!(ReportFormatter::format_number(825_899), "825,899");
        assert_eq!(ReportFormatter::format_number(2_700_000), "2,700,000");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(ReportFormatter::format_bytes(0), "0 B");
        assert_eq!(ReportFormatter::format_bytes(999), "999 B");
        assert_eq!(ReportFormatter::format_bytes(1_024), "1.00 KB");
        assert_eq!(ReportFormatter::format_bytes(5_242_880), "5.00 MB");
        assert_eq!(ReportFormatter::format_bytes(3_221_225_472), "3.00 GB");
    }

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

        let output = ReportFormatter::format_file_extension_report(&report, &OutputFormat::Console)
            .expect("console formatting should succeed");

        assert!(output.contains("FILE TYPE BREAKDOWN"));
        assert!(output.contains("Images"));
        assert!(output.contains(".png"));
    }
}
