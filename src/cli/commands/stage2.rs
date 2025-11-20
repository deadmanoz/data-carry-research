use crate::config::AppConfig;
use crate::errors::{AppError, AppResult};
use clap::Args;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Args)]
pub struct Stage2Command {
    /// Database path (overrides config.toml)
    #[arg(long)]
    database_path: Option<PathBuf>,

    /// Bitcoin RPC URL (overrides config.toml)
    #[arg(long)]
    rpc_url: Option<String>,

    /// Bitcoin RPC username (overrides config.toml)
    #[arg(long)]
    rpc_username: Option<String>,

    /// Bitcoin RPC password (overrides config.toml)
    #[arg(long)]
    rpc_password: Option<String>,

    /// Batch size for transaction processing (overrides config.toml)
    #[arg(long)]
    batch_size: Option<usize>,

    /// Progress report interval (transactions) (overrides config.toml)
    #[arg(long)]
    progress_interval: Option<usize>,

    /// Maximum RPC retries (overrides config.toml)
    #[arg(long)]
    max_retries: Option<usize>,

    /// Concurrent RPC requests limit (overrides config.toml)
    #[arg(long)]
    concurrent_requests: Option<usize>,
}

impl Stage2Command {
    pub async fn run(&self) -> AppResult<()> {
        info!("=== P2MS Analyser - Stage 2 ===");

        // Load configuration from file/environment
        let app_config = match AppConfig::load() {
            Ok(config) => {
                info!("Configuration loaded successfully");
                config
            }
            Err(e) => {
                warn!("Failed to load configuration: {}", e);
                info!("Using defaults and CLI arguments for Stage 2");
                // For Stage 2, we can work with defaults if config isn't available
                AppConfig::get_defaults().map_err(|e| AppError::Config(e.to_string()))?
            }
        };

        // CLI arguments override config values
        let final_database_path = self
            .database_path
            .clone()
            .unwrap_or(app_config.database.default_path);
        let mut rpc_config = app_config.bitcoin_rpc;

        // Override RPC settings with CLI arguments
        if let Some(url) = self.rpc_url.clone() {
            rpc_config.url = url;
        }
        if let Some(username) = self.rpc_username.clone() {
            rpc_config.username = username;
        }
        if let Some(password) = self.rpc_password.clone() {
            rpc_config.password = password;
        }
        if let Some(retries) = self.max_retries {
            rpc_config.max_retries = retries;
        }
        if let Some(concurrent) = self.concurrent_requests {
            rpc_config.concurrent_requests = concurrent;
        }

        let final_batch_size = self.batch_size.unwrap_or(50);
        let final_progress_interval = self.progress_interval.unwrap_or(100);

        info!("Configuration:");
        info!("  Database: {}", final_database_path.display());
        info!("  Bitcoin RPC: {}", rpc_config.url);
        info!("  RPC Username: {}", rpc_config.username);
        info!("  Batch size: {}", final_batch_size);
        info!("  Progress interval: {}", final_progress_interval);
        info!("  Max retries: {}", rpc_config.max_retries);
        info!("  Concurrent requests: {}", rpc_config.concurrent_requests);

        // Validate database exists
        if !final_database_path.exists() {
            return Err(crate::errors::AppError::Config(format!(
                "Database not found: {}",
                final_database_path.display()
            )));
        }

        // Create Stage 2 processor
        let mut processor = crate::processor::stage2::Stage2Processor::new(
            final_database_path.to_str().unwrap(),
            rpc_config,
            final_batch_size,
            final_progress_interval,
        )
        .await?;

        // Process transactions
        let _stats = processor.run().await?;

        // Show additional database stats
        let db_stats = processor.get_database_stats()?;

        println!("\n=== ADDITIONAL STATISTICS ===");
        if db_stats.total_enriched_transactions > 0 {
            println!(
                "Burn pattern coverage: {:.2}%",
                db_stats.burn_pattern_percentage()
            );
            if db_stats.transactions_with_burn_patterns > 0 {
                println!(
                    "Average burn patterns per flagged tx: {:.2}",
                    db_stats.average_patterns_per_transaction()
                );
            }
        }

        println!("\nStage 2 enrichment completed successfully!");
        println!("Database: {}", final_database_path.display());

        Ok(())
    }
}
