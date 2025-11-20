use crate::config::AppConfig;
use crate::errors::AppResult;
use crate::processor::{CsvProcessor, ProgressReporter};
use crate::types::statistics::StatisticsCollector;
use crate::types::Stage1Config;
use clap::Args;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Args)]
#[command(author, version, about, long_about = None)]
pub struct Stage1Command {
    /// Path to UTXO CSV file (overrides config.toml and env vars)
    #[arg(long)]
    csv_path: Option<PathBuf>,

    /// Database path (overrides config.toml and env vars)
    #[arg(long)]
    database_path: Option<PathBuf>,

    /// Batch size for database inserts (overrides config.toml)
    #[arg(long)]
    batch_size: Option<usize>,

    /// Resume from specific count (for recovery)
    #[arg(long)]
    resume_from: Option<u64>,

    /// Progress report interval (records) (overrides config.toml)
    #[arg(long)]
    progress_interval: Option<usize>,

    /// Checkpoint interval (records) (overrides config.toml)
    #[arg(long)]
    checkpoint_interval: Option<usize>,
}

impl Stage1Command {
    pub fn run(&self) -> AppResult<()> {
        info!("=== P2MS Analyser - Stage 1 ===");

        // Load configuration from file/environment
        let app_config = match AppConfig::load() {
            Ok(config) => {
                info!("Configuration loaded successfully");
                config
            }
            Err(e) => {
                warn!("Failed to load configuration: {}", e);
                info!(
                    "Please check that UTXO_CSV_PATH environment variable is set or create config.toml"
                );
                info!("You can copy config.toml.example as a starting point");
                return Err(crate::errors::AppError::Config(format!(
                    "Configuration error: {}. Please set UTXO_CSV_PATH environment variable or configure paths.utxo_csv in config.toml",
                    e
                )));
            }
        };

        // CLI arguments override config values
        let final_csv_path = self
            .csv_path
            .clone()
            .unwrap_or(app_config.paths.utxo_csv.clone());
        let final_database_path = self
            .database_path
            .clone()
            .unwrap_or(app_config.database.default_path.clone());
        let final_batch_size = self.batch_size.unwrap_or(app_config.processing.batch_size);
        let final_progress_interval = self
            .progress_interval
            .unwrap_or(app_config.processing.progress_interval);
        let final_checkpoint_interval = self
            .checkpoint_interval
            .unwrap_or(app_config.processing.checkpoint_interval);

        let config = Stage1Config {
            csv_path: final_csv_path,
            database_path: final_database_path,
            batch_size: final_batch_size,
            resume_from_count: self.resume_from,
            progress_interval: final_progress_interval,
            checkpoint_interval: final_checkpoint_interval,
        };

        // Validate inputs
        if !config.csv_path.exists() {
            return Err(crate::errors::AppError::Config(format!(
                "CSV file does not exist: {}",
                config.csv_path.display()
            )));
        }

        info!("Configuration:");
        info!("  CSV file: {}", config.csv_path.display());
        info!("  Database: {}", config.database_path.display());
        info!("  Batch size: {}", config.batch_size);
        info!("  Progress interval: {}", config.progress_interval);
        info!("  Checkpoint interval: {}", config.checkpoint_interval);
        if let Some(resume) = config.resume_from_count {
            info!("  Resume from count: {}", resume);
        }

        // Create processor
        let mut processor = CsvProcessor::new(config.clone())?;

        // Check for existing checkpoint if no explicit resume point
        processor.check_for_checkpoint()?;

        // Process the CSV
        let stats = processor.process_csv()?;

        // Print summary
        println!(
            "
=== STAGE 1 COMPLETE ==="
        );
        println!("Total records processed: {}", stats.total_records);
        println!("P2MS outputs found: {}", stats.p2ms_found);
        println!("P2MS rate: {:.4}%", stats.p2ms_rate());
        println!("Malformed records: {}", stats.malformed_records);
        println!("Error rate: {:.4}%", stats.error_rate());
        println!(
            "Processing time: {}",
            ProgressReporter::format_elapsed_time(stats.timing.processing_duration.as_secs_f64())
        );
        println!(
            "Processing rate: {:.2} records/sec",
            stats.processing_rate()
        );
        println!("Batches processed: {}", stats.batches_processed);

        // Show database stats
        let db_stats = processor.get_database_stats()?;
        println!(
            "
=== DATABASE SUMMARY ==="
        );
        println!("Total P2MS outputs stored: {}", db_stats.total_outputs);
        println!("Coinbase outputs: {}", db_stats.coinbase_outputs);
        println!("Regular outputs: {}", db_stats.regular_outputs);
        if let (Some(min), Some(max)) = (db_stats.min_height, db_stats.max_height) {
            println!("Block height range: {} - {}", min, max);
        }

        println!(
            "
Database written to: {}",
            config.database_path.display()
        );

        Ok(())
    }
}
