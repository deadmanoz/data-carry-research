use crate::config::AppConfig;
use crate::errors::{AppError, AppResult};
use crate::types::Stage3Config;
use clap::Args;
use std::path::PathBuf;
use tracing::{error, info, warn};

#[derive(Args)]
pub struct Stage3Command {
    /// Database path (overrides config.toml)
    #[arg(long)]
    database_path: Option<PathBuf>,

    /// Batch size for classification processing (overrides config.toml)
    #[arg(long)]
    batch_size: Option<usize>,
}

impl Stage3Command {
    pub async fn run(&self) -> AppResult<()> {
        info!("=== P2MS Analyser - Stage 3 ===");

        // Load configuration from file/environment
        let app_config = match AppConfig::load() {
            Ok(config) => {
                info!("Configuration loaded successfully");
                config
            }
            Err(e) => {
                warn!("Failed to load configuration: {}", e);
                info!("Using default Stage 3 configuration");
                AppConfig::get_defaults().unwrap_or_else(|_| {
                    // Fallback to minimal config if defaults fail
                    AppConfig {
                        paths: crate::config::PathsConfig {
                            utxo_csv: "./utxodump.csv".into(),
                        },
                        database: crate::config::DatabaseConfig {
                            default_path: "./test_output/testing.db".into(),
                        },
                        processing: crate::config::ProcessingConfig {
                            batch_size: 10_000,
                            progress_interval: 100_000,
                            checkpoint_interval: 1_000_000,
                        },
                        bitcoin_rpc: crate::config::BitcoinRpcConfig::default(),
                    }
                })
            }
        };

        // Create Stage 3 configuration with overrides
        let stage3_config = Stage3Config {
            database_path: self
                .database_path
                .clone()
                .unwrap_or_else(|| app_config.database.default_path.clone()),
            batch_size: self.batch_size.unwrap_or(100),
            progress_interval: 1000,
        };

        info!("Stage 3 Configuration:");
        info!("  Database path: {:?}", stage3_config.database_path);
        info!("  Batch size: {}", stage3_config.batch_size);
        info!("  Classification: Signature-based (no height filtering)");

        // Create and run Stage 3 processor
        let database_path_clone = stage3_config.database_path.clone();
        let database_path_str = database_path_clone
            .to_str()
            .ok_or_else(|| AppError::Config("Invalid database path".to_string()))?;

        let mut processor =
            crate::processor::stage3::Stage3Processor::new(database_path_str, stage3_config)?;

        match processor.run().await {
            Ok(results) => {
                info!("Stage 3 processing completed successfully!");
                info!("Final statistics:");
                info!("  Total classified: {}", results.total_classified());
                let (
                    stamps_pct,
                    cp_pct,
                    cpv_pct,
                    omni_pct,
                    chancecoin_pct,
                    ppk_pct,
                    opreturn_signalled_pct,
                    datastorage_pct,
                    likely_data_storage_pct,
                    legitimate_pct,
                    unknown_pct,
                ) = results.classification_breakdown();
                info!(
                    "  Bitcoin Stamps: {} ({:.1}%)",
                    results.stamps_classified, stamps_pct
                );
                info!(
                    "  Counterparty:        {} ({:.1}%)",
                    results.counterparty_classified, cp_pct
                );
                info!(
                    "  ASCII ID Protocols:  {} ({:.1}%)",
                    results.ascii_identifier_protocols_classified, cpv_pct
                );
                info!(
                    "  Omni Layer:          {} ({:.1}%)",
                    results.omni_classified, omni_pct
                );
                info!(
                    "  Chancecoin:     {} ({:.1}%)",
                    results.chancecoin_classified, chancecoin_pct
                );
                info!(
                    "  PPk:                 {} ({:.1}%)",
                    results.ppk_classified, ppk_pct
                );
                info!(
                    "  OP_RETURN Signalled: {} ({:.1}%)",
                    results.opreturn_signalled_classified, opreturn_signalled_pct
                );
                info!(
                    "  DataStorage:    {} ({:.1}%)",
                    results.datastorage_classified, datastorage_pct
                );
                info!(
                    "  LikelyDataStorage: {} ({:.1}%)",
                    results.likely_data_storage_classified, likely_data_storage_pct
                );
                info!(
                    "  Likely Legit:   {} ({:.1}%)",
                    results.legitimate_classified, legitimate_pct
                );
                info!(
                    "  Unknown:        {} ({:.1}%)",
                    results.unknown_classified, unknown_pct
                );

                if results.errors_encountered > 0 {
                    warn!(
                        "Errors encountered during processing: {}",
                        results.errors_encountered
                    );
                }
            }
            Err(e) => {
                error!("Stage 3 processing failed: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }
}
