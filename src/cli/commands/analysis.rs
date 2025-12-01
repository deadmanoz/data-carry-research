use crate::config::AppConfig;
use crate::errors::{AppError, AppResult};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::analysis::{AnalysisEngine, OutputFormat, ReportFormatter};

// ===== Helper Functions =====

/// Get database path from CLI argument or config file
fn get_db_path_from_config(
    cli_path: &Option<PathBuf>,
    app_config: &Option<AppConfig>,
) -> AppResult<String> {
    if let Some(path) = cli_path {
        Ok(path.to_string_lossy().to_string())
    } else if let Some(config) = app_config {
        Ok(config.database.default_path.to_string_lossy().to_string())
    } else {
        Err(AppError::Config(
            "No database path provided. Use --database-path or configure database.default_path in config.toml".to_string()
        ))
    }
}

/// Parse output format string to OutputFormat enum
fn parse_format(format_str: &str) -> OutputFormat {
    match format_str.to_lowercase().as_str() {
        "json" => OutputFormat::Json,
        "plotly" => OutputFormat::Plotly,
        _ => OutputFormat::Console,
    }
}

/// Write output to file with safe directory creation
fn write_output_to_file(path: &PathBuf, content: &str, description: &str) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    println!("{} written to: {}", description, path.display());
    Ok(())
}

/// Run a simple analysis command (database_path + format only)
fn run_simple_analysis<T, F, G>(
    database_path: &Option<PathBuf>,
    format: &str,
    app_config: &Option<AppConfig>,
    analyse_fn: F,
    format_fn: G,
) -> AppResult<()>
where
    F: FnOnce(&AnalysisEngine) -> AppResult<T>,
    G: FnOnce(&T, &OutputFormat) -> AppResult<String>,
{
    let db_path = get_db_path_from_config(database_path, app_config)?;
    let engine = AnalysisEngine::new(&db_path)?;
    let analysis = analyse_fn(&engine)?;
    let output = format_fn(&analysis, &parse_format(format))?;
    print!("{}", output);
    Ok(())
}

/// Run an analysis command with file output support
#[allow(clippy::too_many_arguments)]
fn run_analysis_with_file_output<T, F, G>(
    database_path: &Option<PathBuf>,
    format: &str,
    output_path: &Option<PathBuf>,
    default_filename: &str,
    description: &str,
    app_config: &Option<AppConfig>,
    analyse_fn: F,
    format_fn: G,
) -> AppResult<()>
where
    F: FnOnce(&AnalysisEngine) -> AppResult<T>,
    G: FnOnce(&T, &OutputFormat) -> AppResult<String>,
{
    let db_path = get_db_path_from_config(database_path, app_config)?;
    let engine = AnalysisEngine::new(&db_path)?;
    let analysis = analyse_fn(&engine)?;
    let parsed_format = parse_format(format);
    let formatted_output = format_fn(&analysis, &parsed_format)?;

    if let Some(path) = output_path {
        write_output_to_file(path, &formatted_output, description)?;
    } else if matches!(parsed_format, OutputFormat::Json | OutputFormat::Plotly) {
        let default_path = PathBuf::from(format!("./output_data/plots/{}", default_filename));
        write_output_to_file(&default_path, &formatted_output, description)?;
    } else {
        print!("{}", formatted_output);
    }
    Ok(())
}

// ===== Command Definitions =====

/// Analysis commands for database statistics and reports
#[derive(Args)]
pub struct AnalyseCommand {
    #[command(subcommand)]
    pub analysis_type: AnalysisCommands,
}

impl AnalyseCommand {
    pub fn run(&self) -> AppResult<()> {
        run_analysis(&self.analysis_type)
    }
}

/// Analysis command types
#[derive(Subcommand)]
pub enum AnalysisCommands {
    /// Analyse burn patterns detected in P2MS transactions
    BurnPatterns {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse transaction fees and storage costs
    Fees {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse value distribution across protocols (comprehensive economic analysis)
    Value {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse detailed value distribution histograms for plotting
    ValueDistributions {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console, json, or plotly)
        #[arg(long, default_value = "plotly")]
        format: String,

        /// Output file path (if not specified, outputs to stdout)
        /// Recommended: ./output_data/analysis/value_distributions.json
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Analyse protocol classification statistics
    Classifications {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse protocol signature detection
    Signatures {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse P2MS output spendability
    Spendability {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Generate full analysis report (all analyses combined)
    Full {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse Bitcoin Stamps signature variant distribution
    StampsSignatures {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse content type distribution across protocols
    ContentTypes {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,

        /// Filter by protocol (e.g., BitcoinStamps, DataStorage)
        #[arg(long)]
        protocol: Option<String>,

        /// Show only specific MIME type
        #[arg(long)]
        mime_type: Option<String>,
    },

    /// Analyse protocol-level data sizes
    ProtocolDataSizes {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse data sizes by spendability
    SpendabilityDataSizes {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse content type spendability with data sizes
    ContentTypeSpendability {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse comprehensive data sizes across all dimensions
    ComprehensiveDataSizes {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse multisig configurations with exhaustive breakdown
    MultisigConfigurations {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse P2MS outputs against Bitcoin dust thresholds
    ///
    /// Reports outputs below Bitcoin Core's dust limits when spending to different
    /// destination types:
    /// - 546 sats: threshold when spending to non-segwit destination (e.g., P2PKH)
    /// - 294 sats: threshold when spending to segwit destination (e.g., P2WPKH)
    ///
    /// Works without Stage 3 (outputs shown as unclassified); run Stage 3 for
    /// per-protocol breakdown.
    DustThresholds {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console or json)
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Analyse transaction size distribution for P2MS transactions
    ///
    /// Provides histogram distribution of transaction sizes (bytes) with:
    /// - Global distribution across all P2MS transactions
    /// - Per-protocol breakdown sorted by canonical protocol order
    /// - Percentiles (p25, p50, p75, p90, p95, p99)
    /// - Fee statistics per size bucket
    ///
    /// Uses enriched_transactions table; requires Stage 2 completion.
    TxSizes {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console, json, or plotly)
        #[arg(long, default_value = "console")]
        format: String,

        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Analyse Bitcoin Stamps transaction fees aggregated by week
    ///
    /// Produces temporal fee analysis for Bitcoin Stamps transactions with weekly
    /// aggregation. Output formats:
    /// - console: Human-readable table with BTC values
    /// - json: Raw structured data with satoshi values
    /// - plotly: Plotly-native trace format for web visualisation
    ///
    /// Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).
    /// Fees are counted per transaction (not per output) to avoid double-counting.
    StampsWeeklyFees {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console, json, or plotly)
        #[arg(long, default_value = "console")]
        format: String,

        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Analyse Bitcoin Stamps variant distribution over time
    ///
    /// Shows temporal distribution of Stamps variants (Classic, SRC-20, SRC-721, etc.)
    /// with weekly aggregation. Useful for understanding adoption patterns.
    ///
    /// Output formats:
    /// - console: Human-readable summary with variant totals and first appearances
    /// - json: Full structured data with all weekly breakdowns
    /// - plotly: Stacked area chart data for visualisation
    ///
    /// Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).
    /// NULL variants are reported separately as they indicate classification bugs.
    StampsVariantTemporal {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console, json, or plotly)
        #[arg(long, default_value = "console")]
        format: String,

        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Analyse P2MS output count distribution per transaction
    ///
    /// Provides histogram distribution of P2MS output counts per transaction with:
    /// - Global distribution across all transactions with unspent P2MS outputs
    /// - Per-protocol breakdown sorted by canonical protocol order
    /// - Percentiles (p25, p50, p75, p90, p95, p99)
    /// - Total satoshi value per bucket (USER DIRECTIVE: track P2MS output value)
    ///
    /// Bucket ranges: 1, 2, 3, 4-5, 6-10, 11-20, 21-50, 51-100, 101+
    /// Requires Stage 3 for per-protocol breakdown (works without, shows unclassified).
    OutputCounts {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console, json, or plotly)
        #[arg(long, default_value = "console")]
        format: String,

        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Analyse protocol distribution over time
    ///
    /// Shows temporal distribution of P2MS protocols (Bitcoin Stamps, Counterparty, etc.)
    /// with weekly aggregation. Useful for understanding protocol adoption patterns.
    ///
    /// Output formats:
    /// - console: Human-readable summary with protocol totals
    /// - json: Full structured data with all weekly breakdowns
    /// - plotly: Stacked bar chart data for visualisation
    ///
    /// Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).
    ProtocolTemporal {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console, json, or plotly)
        #[arg(long, default_value = "console")]
        format: String,

        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Analyse spendability distribution over time
    ///
    /// Shows temporal distribution of spendable vs unspendable P2MS outputs
    /// with weekly aggregation. Useful for understanding data vs legitimate multisig patterns.
    ///
    /// Output formats:
    /// - console: Human-readable summary with spendability percentages
    /// - json: Full structured data with all weekly breakdowns
    /// - plotly: Stacked area chart data for visualisation
    ///
    /// Week boundaries are Thursday-to-Wednesday (fixed 7-day buckets).
    SpendabilityTemporal {
        /// Database path (overrides config.toml)
        #[arg(long)]
        database_path: Option<PathBuf>,

        /// Output format (console, json, or plotly)
        #[arg(long, default_value = "console")]
        format: String,

        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
}

pub fn run_analysis(analysis_type: &AnalysisCommands) -> AppResult<()> {
    // Load configuration for default database path
    let app_config = AppConfig::load().ok();

    match analysis_type {
        AnalysisCommands::BurnPatterns {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_burn_patterns(),
            ReportFormatter::format_burn_patterns,
        ),

        AnalysisCommands::Fees {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_fees(),
            ReportFormatter::format_fee_analysis,
        ),

        AnalysisCommands::Value {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_value(),
            ReportFormatter::format_value_analysis,
        ),

        AnalysisCommands::ValueDistributions {
            database_path,
            format,
            output,
        } => run_analysis_with_file_output(
            database_path,
            format,
            output,
            "value_distributions.json",
            "Value distribution analysis",
            &app_config,
            |e| e.analyse_value_distributions(),
            ReportFormatter::format_value_distributions,
        ),

        AnalysisCommands::Classifications {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_classifications(),
            ReportFormatter::format_classification_stats,
        ),

        AnalysisCommands::Signatures {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_signatures(),
            ReportFormatter::format_signature_analysis,
        ),

        AnalysisCommands::Spendability {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_spendability(),
            ReportFormatter::format_spendability_report,
        ),

        AnalysisCommands::Full {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.generate_full_report(),
            ReportFormatter::format_full_report,
        ),

        AnalysisCommands::StampsSignatures {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_stamps_signatures(),
            ReportFormatter::format_stamps_signatures,
        ),

        AnalysisCommands::ContentTypes {
            database_path,
            format,
            protocol,
            mime_type,
        } => {
            let db_path = get_db_path_from_config(database_path, &app_config)?;
            use crate::analysis::ContentTypeAnalyser;
            use crate::database::Database;
            let db = Database::new(&db_path)?;

            // Handle filtering modes
            if let Some(protocol_str) = protocol {
                // Protocol-specific analysis
                let analysis =
                    ContentTypeAnalyser::analyse_protocol_content_types(&db, protocol_str)?;
                match parse_format(format) {
                    OutputFormat::Json | OutputFormat::Plotly => {
                        println!("{}", serde_json::to_string_pretty(&analysis)?);
                    }
                    OutputFormat::Console => {
                        println!("📊 Content Type Analysis - {}", protocol_str);
                        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        println!();
                        println!("Total outputs: {}", analysis.total_outputs);
                        println!("With content type: {}", analysis.with_content_type);
                        println!("Without content type: {}", analysis.without_content_type);
                        println!("Coverage: {:.2}%", analysis.coverage_percentage);
                        println!();
                        if !analysis.content_types.is_empty() {
                            println!("{:<40} {:>10} {:>11}", "MIME Type", "Count", "% of Total");
                            println!("{:-<40} {:->10} {:->11}", "", "", "");
                            for ct in &analysis.content_types {
                                println!(
                                    "{:<40} {:>10} {:>10.2}%",
                                    ct.mime_type, ct.count, ct.percentage
                                );
                            }
                        }
                    }
                }
            } else if let Some(mime_str) = mime_type {
                // MIME type usage analysis
                let analysis = ContentTypeAnalyser::analyse_mime_type_usage(&db, mime_str)?;
                match parse_format(format) {
                    OutputFormat::Json | OutputFormat::Plotly => {
                        println!("{}", serde_json::to_string_pretty(&analysis)?);
                    }
                    OutputFormat::Console => {
                        println!("📊 MIME Type Usage - {}", mime_str);
                        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        println!();
                        for protocol_stats in &analysis {
                            println!(
                                "{}: {} outputs ({:.2}%)",
                                protocol_stats.protocol,
                                protocol_stats.with_content_type,
                                protocol_stats.coverage_percentage
                            );
                        }
                    }
                }
            } else {
                // Full content type analysis
                let analysis = ContentTypeAnalyser::analyse_content_types(&db)?;
                match parse_format(format) {
                    OutputFormat::Json | OutputFormat::Plotly => {
                        println!("{}", serde_json::to_string_pretty(&analysis)?);
                    }
                    OutputFormat::Console => {
                        println!("📊 Content Type Distribution (Unspent P2MS Outputs Only)");
                        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        println!();
                        println!("Total outputs: {}", analysis.total_outputs);
                        println!(
                            "With content type: {} ({:.2}%)",
                            analysis.outputs_with_content_type, analysis.content_type_percentage
                        );
                        println!(
                            "Without content type: {}",
                            analysis.outputs_without_content_type
                        );
                        println!();

                        // Valid None cases
                        println!("Valid None Cases (Architecturally Correct):");
                        println!(
                            "  LikelyDataStorage: {}",
                            analysis.valid_none_stats.likely_data_storage
                        );
                        println!(
                            "  LikelyLegitimateMultisig: {}",
                            analysis.valid_none_stats.likely_legitimate_multisig
                        );
                        println!(
                            "  StampsUnknown: {}",
                            analysis.valid_none_stats.stamps_unknown
                        );
                        println!(
                            "  OmniFailedDeobfuscation: {}",
                            analysis.valid_none_stats.omni_failed_deobfuscation
                        );
                        println!(
                            "  Total valid None: {}",
                            analysis.valid_none_stats.total_valid_none
                        );
                        println!();

                        // Invalid None cases
                        if !analysis.invalid_none_stats.is_empty() {
                            println!("Invalid None Cases (Missing Content Types):");
                            for protocol_stats in &analysis.invalid_none_stats {
                                println!(
                                    "  {}: {} outputs missing content types",
                                    protocol_stats.protocol, protocol_stats.without_content_type
                                );
                            }
                            println!();
                        }

                        // Category breakdown
                        println!("Content Type Categories:");
                        println!("{:<20} {:>10} {:>11}", "Category", "Count", "% of Total");
                        println!("{:-<20} {:->10} {:->11}", "", "", "");
                        for category in &analysis.category_breakdown {
                            println!(
                                "{:<20} {:>10} {:>10.2}%",
                                category.category, category.count, category.percentage
                            );
                        }
                        println!();

                        // Top content types
                        println!("Top Content Types:");
                        println!("{:<40} {:>10} {:>11}", "MIME Type", "Count", "% of Total");
                        println!("{:-<40} {:->10} {:->11}", "", "", "");
                        for (i, ct) in analysis.content_type_breakdown.iter().enumerate() {
                            if i >= 15 {
                                break;
                            } // Show top 15
                            println!(
                                "{:<40} {:>10} {:>10.2}%",
                                ct.mime_type, ct.count, ct.percentage
                            );
                        }
                        if analysis.content_type_breakdown.len() > 15 {
                            println!(
                                "  ... and {} more",
                                analysis.content_type_breakdown.len() - 15
                            );
                        }
                    }
                }
            }
            Ok(())
        }

        AnalysisCommands::ProtocolDataSizes {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_protocol_data_sizes(),
            ReportFormatter::format_protocol_data_size_report,
        ),

        AnalysisCommands::SpendabilityDataSizes {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_spendability_data_sizes(),
            ReportFormatter::format_spendability_data_size_report,
        ),

        AnalysisCommands::ContentTypeSpendability {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_content_type_spendability(),
            ReportFormatter::format_content_type_spendability_report,
        ),

        AnalysisCommands::ComprehensiveDataSizes {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_comprehensive_data_sizes(),
            ReportFormatter::format_comprehensive_data_size_report,
        ),

        AnalysisCommands::MultisigConfigurations {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_multisig_configurations(),
            ReportFormatter::format_multisig_config_report,
        ),

        AnalysisCommands::DustThresholds {
            database_path,
            format,
        } => run_simple_analysis(
            database_path,
            format,
            &app_config,
            |e| e.analyse_dust_thresholds(),
            ReportFormatter::format_dust_analysis,
        ),

        AnalysisCommands::TxSizes {
            database_path,
            format,
            output,
        } => run_analysis_with_file_output(
            database_path,
            format,
            output,
            "tx_sizes.json",
            "Transaction size analysis",
            &app_config,
            |e| e.analyse_tx_sizes(),
            ReportFormatter::format_tx_sizes,
        ),

        AnalysisCommands::StampsWeeklyFees {
            database_path,
            format,
            output,
        } => run_analysis_with_file_output(
            database_path,
            format,
            output,
            "stamps_weekly_fees.json",
            "Stamps weekly fee analysis",
            &app_config,
            |e| e.analyse_stamps_weekly_fees(),
            ReportFormatter::format_stamps_weekly_fees,
        ),

        AnalysisCommands::StampsVariantTemporal {
            database_path,
            format,
            output,
        } => run_analysis_with_file_output(
            database_path,
            format,
            output,
            "stamps_variant_temporal.json",
            "Stamps variant temporal analysis",
            &app_config,
            |e| e.analyse_stamps_variant_temporal(),
            ReportFormatter::format_stamps_variant_temporal,
        ),

        AnalysisCommands::OutputCounts {
            database_path,
            format,
            output,
        } => run_analysis_with_file_output(
            database_path,
            format,
            output,
            "output_counts.json",
            "P2MS output count distribution",
            &app_config,
            |e| e.analyse_output_counts(),
            ReportFormatter::format_output_count_distribution,
        ),

        AnalysisCommands::ProtocolTemporal {
            database_path,
            format,
            output,
        } => run_analysis_with_file_output(
            database_path,
            format,
            output,
            "protocol_temporal.json",
            "Protocol temporal distribution",
            &app_config,
            |e| e.analyse_protocol_temporal(),
            ReportFormatter::format_protocol_temporal,
        ),

        AnalysisCommands::SpendabilityTemporal {
            database_path,
            format,
            output,
        } => run_analysis_with_file_output(
            database_path,
            format,
            output,
            "spendability_temporal.json",
            "Spendability temporal distribution",
            &app_config,
            |e| e.analyse_spendability_temporal(),
            ReportFormatter::format_spendability_temporal,
        ),
    }
}
