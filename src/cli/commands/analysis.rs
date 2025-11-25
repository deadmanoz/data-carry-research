use crate::config::AppConfig;
use crate::errors::{AppError, AppResult};
use clap::{Args, Subcommand};
use std::path::PathBuf;

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
}

pub fn run_analysis(analysis_type: &AnalysisCommands) -> AppResult<()> {
    use crate::analysis::{AnalysisEngine, OutputFormat, ReportFormatter};

    // Load configuration for default database path
    let app_config = AppConfig::load().ok();

    // Helper to get database path (CLI arg or config default)
    let get_db_path = |cli_path: &Option<PathBuf>| -> AppResult<String> {
        if let Some(path) = cli_path {
            Ok(path.to_string_lossy().to_string())
        } else if let Some(config) = &app_config {
            Ok(config.database.default_path.to_string_lossy().to_string())
        } else {
            Err(AppError::Config(
                "No database path provided. Use --database-path or configure database.default_path in config.toml".to_string()
            ))
        }
    };

    // Helper to parse output format
    let parse_format = |format_str: &str| -> OutputFormat {
        match format_str.to_lowercase().as_str() {
            "json" => OutputFormat::Json,
            "plotly" => OutputFormat::Plotly,
            _ => OutputFormat::Console,
        }
    };

    match analysis_type {
        AnalysisCommands::BurnPatterns {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_burn_patterns()?;
            let output = ReportFormatter::format_burn_patterns(&analysis, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::Fees {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_fees()?;
            let output = ReportFormatter::format_fee_analysis(&analysis, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::Value {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_value()?;
            let output = ReportFormatter::format_value_analysis(&analysis, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::ValueDistributions {
            database_path,
            format,
            output,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_value_distributions()?;
            let formatted_output =
                ReportFormatter::format_value_distributions(&analysis, &parse_format(format))?;

            // Default output path for JSON/Plotly formats
            let default_output_path =
                std::path::PathBuf::from("./output_data/plots/value_distributions.json");

            if let Some(output_path) = output {
                std::fs::write(&output_path, formatted_output)?;
                println!(
                    "Value distribution analysis written to: {}",
                    output_path.display()
                );
            } else if matches!(parse_format(format), OutputFormat::Json | OutputFormat::Plotly) {
                // Auto-write JSON/Plotly output to default path
                std::fs::create_dir_all(default_output_path.parent().unwrap())?;
                std::fs::write(&default_output_path, formatted_output)?;
                println!(
                    "Value distribution analysis written to: {}",
                    default_output_path.display()
                );
            } else {
                // Console format: print to stdout
                print!("{}", formatted_output);
            }
            Ok(())
        }

        AnalysisCommands::Classifications {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_classifications()?;
            let output =
                ReportFormatter::format_classification_stats(&analysis, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::Signatures {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_signatures()?;
            let output =
                ReportFormatter::format_signature_analysis(&analysis, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::Spendability {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_spendability()?;
            let output =
                ReportFormatter::format_spendability_report(&analysis, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::Full {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let report = engine.generate_full_report()?;
            let output = ReportFormatter::format_full_report(&report, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::StampsSignatures {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_stamps_signatures()?;
            let output =
                ReportFormatter::format_stamps_signatures(&analysis, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::ContentTypes {
            database_path,
            format,
            protocol,
            mime_type,
        } => {
            let db_path = get_db_path(database_path)?;
            use crate::database::Database;
            use crate::analysis::ContentTypeAnalyser;
            let db = Database::new_v2(&db_path)?;

            // Handle filtering modes
            if let Some(protocol_str) = protocol {
                // Protocol-specific analysis
                let analysis = ContentTypeAnalyser::analyse_protocol_content_types(&db, protocol_str)?;
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
                                println!("{:<40} {:>10} {:>10.2}%", ct.mime_type, ct.count, ct.percentage);
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
                            println!("{}: {} outputs ({:.2}%)",
                                protocol_stats.protocol,
                                protocol_stats.with_content_type,
                                protocol_stats.coverage_percentage);
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
                        println!("With content type: {} ({:.2}%)",
                            analysis.outputs_with_content_type,
                            analysis.content_type_percentage);
                        println!("Without content type: {}", analysis.outputs_without_content_type);
                        println!();

                        // Valid None cases
                        println!("Valid None Cases (Architecturally Correct):");
                        println!("  LikelyDataStorage: {}", analysis.valid_none_stats.likely_data_storage);
                        println!("  LikelyLegitimateMultisig: {}", analysis.valid_none_stats.likely_legitimate_multisig);
                        println!("  StampsUnknown: {}", analysis.valid_none_stats.stamps_unknown);
                        println!("  OmniFailedDeobfuscation: {}", analysis.valid_none_stats.omni_failed_deobfuscation);
                        println!("  Total valid None: {}", analysis.valid_none_stats.total_valid_none);
                        println!();

                        // Invalid None cases
                        if !analysis.invalid_none_stats.is_empty() {
                            println!("Invalid None Cases (Missing Content Types):");
                            for protocol_stats in &analysis.invalid_none_stats {
                                println!("  {}: {} outputs missing content types",
                                    protocol_stats.protocol,
                                    protocol_stats.without_content_type);
                            }
                            println!();
                        }

                        // Category breakdown
                        println!("Content Type Categories:");
                        println!("{:<20} {:>10} {:>11}", "Category", "Count", "% of Total");
                        println!("{:-<20} {:->10} {:->11}", "", "", "");
                        for category in &analysis.category_breakdown {
                            println!("{:<20} {:>10} {:>10.2}%",
                                category.category,
                                category.count,
                                category.percentage);
                        }
                        println!();

                        // Top content types
                        println!("Top Content Types:");
                        println!("{:<40} {:>10} {:>11}", "MIME Type", "Count", "% of Total");
                        println!("{:-<40} {:->10} {:->11}", "", "", "");
                        for (i, ct) in analysis.content_type_breakdown.iter().enumerate() {
                            if i >= 15 { break; } // Show top 15
                            println!("{:<40} {:>10} {:>10.2}%", ct.mime_type, ct.count, ct.percentage);
                        }
                        if analysis.content_type_breakdown.len() > 15 {
                            println!("  ... and {} more", analysis.content_type_breakdown.len() - 15);
                        }
                    }
                }
            }
            Ok(())
        }

        AnalysisCommands::ProtocolDataSizes {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_protocol_data_sizes()?;
            let output = ReportFormatter::format_protocol_data_size_report(
                &analysis,
                &parse_format(format),
            )?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::SpendabilityDataSizes {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_spendability_data_sizes()?;
            let output = ReportFormatter::format_spendability_data_size_report(
                &analysis,
                &parse_format(format),
            )?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::ContentTypeSpendability {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_content_type_spendability()?;
            let output = ReportFormatter::format_content_type_spendability_report(
                &analysis,
                &parse_format(format),
            )?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::ComprehensiveDataSizes {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_comprehensive_data_sizes()?;
            let output = ReportFormatter::format_comprehensive_data_size_report(
                &analysis,
                &parse_format(format),
            )?;
            print!("{}", output);
            Ok(())
        }

        AnalysisCommands::MultisigConfigurations {
            database_path,
            format,
        } => {
            let db_path = get_db_path(database_path)?;
            let engine = AnalysisEngine::new(&db_path)?;
            let analysis = engine.analyse_multisig_configurations()?;
            let output =
                ReportFormatter::format_multisig_config_report(&analysis, &parse_format(format))?;
            print!("{}", output);
            Ok(())
        }
    }
}

