use crate::config::AppConfig;
use crate::database::stage3::operations::NO_MIME_TYPE_SENTINEL;
use crate::errors::{AppError, AppResult};
use crate::types::content_detection::ContentType;
use clap::{Args, Subcommand};
use serde::Serialize;
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

            if let Some(output_path) = output {
                std::fs::write(&output_path, formatted_output)?;
                println!("Value distribution analysis written to: {}", output_path.display());
            } else {
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
            run_content_type_analysis(
                &db_path,
                &parse_format(format),
                protocol.as_deref(),
                mime_type.as_deref(),
            )
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
            let output = ReportFormatter::format_multisig_config_report(
                &analysis,
                &parse_format(format),
            )?;
            print!("{}", output);
            Ok(())
        }
    }
}

use crate::analysis::OutputFormat;

/// Analyse content type distribution
fn run_content_type_analysis(
    db_path: &str,
    format: &OutputFormat,
    protocol_filter: Option<&str>,
    mime_type_filter: Option<&str>,
) -> AppResult<()> {
    use crate::database::traits::Stage3Operations;
    use crate::database::Database;
    use crate::types::ProtocolType;

    let db = Database::new_v2(db_path)?;

    let fetch_transactions_for_mime = |mime: &str| -> AppResult<(Vec<String>, bool)> {
        let is_missing = mime == NO_MIME_TYPE_SENTINEL
            || mime.eq_ignore_ascii_case("none")
            || mime.eq_ignore_ascii_case("no-mime-type")
            || mime.eq_ignore_ascii_case("missing")
            || mime.eq_ignore_ascii_case("null");

        if is_missing {
            let mut stmt = db
                .connection()
                .prepare(
                    r#"
                        SELECT txid
                        FROM transaction_classifications
                        WHERE content_type IS NULL
                        ORDER BY id
                        "#,
                )
                .map_err(AppError::Database)?;

            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(AppError::Database)?;

            let mut txids = Vec::new();
            for row_result in rows {
                txids.push(row_result.map_err(AppError::Database)?);
            }

            Ok((txids, true))
        } else {
            Ok((db.get_transactions_by_content_type(mime)?, false))
        }
    };

    #[derive(Debug, Clone, Serialize)]
    struct ContentTypeSummary {
        mime_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw_mime_type: Option<String>,
        category: String,
        count: u64,
        percentage: f64,
        is_missing: bool,
    }

    #[derive(Debug, Clone, Serialize)]
    struct CategorySummary {
        category: String,
        count: u64,
        percentage: f64,
    }

    let build_summaries = |distribution: &std::collections::HashMap<String, u64>| -> (
        Vec<ContentTypeSummary>,
        Vec<CategorySummary>,
        u64,
    ) {
        let total: u64 = distribution.values().sum();
        let mut entries: Vec<ContentTypeSummary> = Vec::new();
        let mut category_totals: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();

        for (mime_type, count) in distribution.iter() {
            let is_missing = mime_type == NO_MIME_TYPE_SENTINEL;
            let (display_mime, raw_mime) = if is_missing {
                ("No MIME Type".to_string(), None)
            } else {
                (mime_type.clone(), Some(mime_type.clone()))
            };

            let category = if is_missing {
                "No Category".to_string()
            } else {
                ContentType::from_mime_type(mime_type)
                    .as_ref()
                    .map(|ct| ct.category().to_string())
                    .unwrap_or_else(|| "Other".to_string())
            };

            let percentage = if total == 0 {
                0.0
            } else {
                (*count as f64 * 100.0) / total as f64
            };

            *category_totals.entry(category.clone()).or_insert(0) += *count;

            entries.push(ContentTypeSummary {
                mime_type: display_mime,
                raw_mime_type: raw_mime,
                category,
                count: *count,
                percentage,
                is_missing,
            });
        }

        entries.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.mime_type.cmp(&b.mime_type))
        });

        let mut categories: Vec<CategorySummary> = category_totals
            .into_iter()
            .map(|(category, count)| {
                let percentage = if total == 0 {
                    0.0
                } else {
                    (count as f64 * 100.0) / total as f64
                };
                CategorySummary {
                    category,
                    count,
                    percentage,
                }
            })
            .collect();

        categories.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.category.cmp(&b.category))
        });

        (entries, categories, total)
    };

    // Helper function to parse protocol string
    let parse_protocol_type = |s: &str| -> Result<ProtocolType, AppError> {
        match s.to_lowercase().as_str() {
            "bitcoinstamps" | "stamps" => Ok(ProtocolType::BitcoinStamps),
            "counterparty" | "cp" => Ok(ProtocolType::Counterparty),
            "asciiidentifierprotocols" | "ascii" | "aip" => {
                Ok(ProtocolType::AsciiIdentifierProtocols)
            }
            "omni" | "omnilayer" => Ok(ProtocolType::OmniLayer),
            "chancecoin" => Ok(ProtocolType::Chancecoin),
            "opreturnsignalled" | "opreturn" | "protocol47930" | "47930" | "bb3a" | "rt"
            | "clipperz" => Ok(ProtocolType::OpReturnSignalled),
            "datastorage" | "data" => Ok(ProtocolType::DataStorage),
            "likelydatastorage" | "lds" => Ok(ProtocolType::LikelyDataStorage),
            "likelylegitimate" | "legitimate" => Ok(ProtocolType::LikelyLegitimateMultisig),
            "unknown" => Ok(ProtocolType::Unknown),
            _ => Err(AppError::Config(format!("Unknown protocol type: {}", s))),
        }
    };

    match format {
        OutputFormat::Json | OutputFormat::Plotly => {
            // JSON output
            if let Some(mime_type) = mime_type_filter {
                // Show transactions with specific MIME type
                let (txids, is_missing) = fetch_transactions_for_mime(mime_type)?;
                let count = txids.len();
                let category = if is_missing {
                    "No Category"
                } else {
                    ContentType::from_mime_type(mime_type)
                        .as_ref()
                        .map(|ct| ct.category())
                        .unwrap_or("Other")
                };

                let output = serde_json::json!({
                    "mime_type": if is_missing { "No MIME Type" } else { mime_type },
                    "raw_mime_type": if is_missing { serde_json::Value::Null } else { serde_json::Value::String(mime_type.to_string()) },
                    "category": category,
                    "count": count,
                    "is_missing": is_missing,
                    "transactions": txids
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else if let Some(protocol_str) = protocol_filter {
                // Show content types for specific protocol
                let protocol = parse_protocol_type(protocol_str)?;
                let distribution = db.get_content_type_distribution_by_protocol(protocol)?;
                let (summaries, category_totals, total) = build_summaries(&distribution);

                let output = serde_json::json!({
                    "protocol": protocol_str,
                    "total_classifications": total,
                    "category_totals": category_totals,
                    "content_types": summaries
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            } else {
                // Show all content types
                let distribution = db.get_content_type_distribution()?;
                let (summaries, category_totals, total) = build_summaries(&distribution);

                let output = serde_json::json!({
                    "total_classifications": total,
                    "category_totals": category_totals,
                    "content_types": summaries
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            }
        }
        OutputFormat::Console => {
            // Console output
            if let Some(mime_type) = mime_type_filter {
                // Show transactions with specific MIME type
                let (txids, is_missing) = fetch_transactions_for_mime(mime_type)?;
                let count = txids.len();
                let display_mime = if is_missing {
                    "No MIME Type"
                } else {
                    mime_type
                };
                let category = if is_missing {
                    "No Category"
                } else {
                    ContentType::from_mime_type(mime_type)
                        .as_ref()
                        .map(|ct| ct.category())
                        .unwrap_or("Other")
                };

                println!("📊 Content Type Analysis - {}", display_mime);
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!();
                println!("Total transactions: {}", count);
                println!("Category: {}", category);
                println!();

                if !txids.is_empty() {
                    println!("Transactions:");
                    for txid in txids.iter().take(100) {
                        println!("  {}", txid);
                    }
                    if txids.len() > 100 {
                        println!("  ... and {} more", txids.len() - 100);
                    }
                }
            } else if let Some(protocol_str) = protocol_filter {
                // Show content types for specific protocol
                let protocol = parse_protocol_type(protocol_str)?;
                let distribution =
                    db.get_content_type_distribution_by_protocol(protocol.clone())?;
                let (summaries, category_totals, total) = build_summaries(&distribution);

                println!("📊 Content Type Analysis - {:?}", protocol);
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!();

                if summaries.is_empty() {
                    println!("No content types found for this protocol");
                } else {
                    println!("Category Totals:");
                    println!("{:<20} {:>10} {:>11}", "Category", "Count", "Share");
                    println!("{:-<20} {:->10} {:->11}", "", "", "");
                    for category in &category_totals {
                        println!(
                            "{:<20} {:>10} {:>10.2}%",
                            category.category, category.count, category.percentage
                        );
                    }

                    println!();
                    println!("Detailed Content Types:");
                    println!(
                        "{:<20} {:<40} {:>10} {:>11}",
                        "Category", "MIME Type", "Count", "Share"
                    );
                    println!("{:-<20} {:-<40} {:->10} {:->11}", "", "", "", "");

                    for entry in summaries {
                        println!(
                            "{:<20} {:<40} {:>10} {:>10.2}%",
                            entry.category, entry.mime_type, entry.count, entry.percentage
                        );
                    }

                    println!();
                    println!("Total classified outputs: {}", total);
                }
            } else {
                // Show all content types
                let distribution = db.get_content_type_distribution()?;
                let (summaries, category_totals, total) = build_summaries(&distribution);

                println!("📊 Content Type Distribution");
                println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                println!();

                if summaries.is_empty() {
                    println!("No content types found");
                } else {
                    println!("Category Totals:");
                    println!("{:<20} {:>10} {:>11}", "Category", "Count", "Share");
                    println!("{:-<20} {:->10} {:->11}", "", "", "");
                    for category in &category_totals {
                        println!(
                            "{:<20} {:>10} {:>10.2}%",
                            category.category, category.count, category.percentage
                        );
                    }

                    println!();
                    println!("Detailed Content Types:");
                    println!(
                        "{:<20} {:<40} {:>10} {:>11}",
                        "Category", "MIME Type", "Count", "Share"
                    );
                    println!("{:-<20} {:-<40} {:->10} {:->11}", "", "", "", "");

                    for entry in summaries {
                        println!(
                            "{:<20} {:<40} {:>10} {:>10.2}%",
                            entry.category, entry.mime_type, entry.count, entry.percentage
                        );
                    }

                    println!();
                    println!("Total classified outputs: {}", total);
                }
            }
        }
    }

    Ok(())
}
