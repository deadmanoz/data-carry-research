use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

/// Application configuration loaded from config.toml or environment variables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub paths: PathsConfig,
    pub database: DatabaseConfig,
    pub processing: ProcessingConfig,
    pub bitcoin_rpc: BitcoinRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    pub utxo_csv: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub default_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingConfig {
    pub batch_size: usize,
    pub progress_interval: usize,
    pub checkpoint_interval: usize,
}

/// Bitcoin RPC configuration for Stage 2 transaction enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinRpcConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub timeout_seconds: u64,
    pub max_retries: usize,
    pub initial_backoff_ms: u64,
    pub backoff_multiplier: f64,
    pub max_backoff_seconds: u64,
    pub concurrent_requests: usize,
}

impl Default for BitcoinRpcConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8332".to_string(),
            username: "bitcoin".to_string(),
            password: "password".to_string(),
            timeout_seconds: 60,
            max_retries: 10,
            initial_backoff_ms: 100,
            backoff_multiplier: 2.0,
            max_backoff_seconds: 30,
            concurrent_requests: 10,
        }
    }
}

impl AppConfig {
    /// Load configuration from config.toml file and environment variables
    /// Environment variables take precedence over file configuration
    pub fn load() -> Result<Self, ConfigError> {
        let defaults = BitcoinRpcConfig::default();
        let config = Config::builder()
            // Start with default values
            .set_default("paths.utxo_csv", "/dev/null")? // Will be overridden
            .set_default("database.default_path", "./test_output/testing.db")?
            .set_default("processing.batch_size", 10000)?
            .set_default("processing.progress_interval", 100000)?
            .set_default("processing.checkpoint_interval", 1000000)?
            // Bitcoin RPC defaults
            .set_default("bitcoin_rpc.url", defaults.url)?
            .set_default("bitcoin_rpc.username", defaults.username)?
            .set_default("bitcoin_rpc.password", defaults.password)?
            .set_default("bitcoin_rpc.timeout_seconds", defaults.timeout_seconds)?
            .set_default("bitcoin_rpc.max_retries", defaults.max_retries as i64)?
            .set_default(
                "bitcoin_rpc.initial_backoff_ms",
                defaults.initial_backoff_ms,
            )?
            .set_default(
                "bitcoin_rpc.backoff_multiplier",
                defaults.backoff_multiplier,
            )?
            .set_default(
                "bitcoin_rpc.max_backoff_seconds",
                defaults.max_backoff_seconds,
            )?
            .set_default(
                "bitcoin_rpc.concurrent_requests",
                defaults.concurrent_requests as i64,
            )?
            // Load from config.toml if it exists
            .add_source(File::with_name("config").required(false))
            // Override with environment variables
            // UTXO_CSV_PATH env variable overrides paths.utxo_csv
            .add_source(config::Environment::with_prefix("UTXO"))
            // P2MS_DATABASE_PATH env variable can override database path
            .add_source(config::Environment::with_prefix("P2MS"))
            // BITCOIN_RPC_* env variables can override RPC settings
            .add_source(config::Environment::with_prefix("BITCOIN_RPC"))
            .build()?;

        let mut app_config: AppConfig = config.try_deserialize()?;

        // Check for specific environment variables with custom names
        if let Ok(csv_path) = env::var("UTXO_CSV_PATH") {
            app_config.paths.utxo_csv = PathBuf::from(csv_path);
        }

        if let Ok(db_path) = env::var("P2MS_DATABASE_PATH") {
            app_config.database.default_path = PathBuf::from(db_path);
        }

        // Validate that the CSV path was actually configured
        if app_config.paths.utxo_csv == PathBuf::from("/dev/null") {
            return Err(ConfigError::Message(
                "UTXO CSV path not configured. Please set UTXO_CSV_PATH environment variable or configure paths.utxo_csv in config.toml".to_string()
            ));
        }

        Ok(app_config)
    }

    /// Get default config values for CLI argument defaults
    pub fn get_defaults() -> Result<Self, ConfigError> {
        // Try to load config for defaults, but don't fail if not found
        match Self::load() {
            Ok(config) => Ok(config),
            Err(_) => {
                // Return sensible defaults if no config found
                Ok(Self {
                    paths: PathsConfig {
                        utxo_csv: PathBuf::from("./utxodump.csv"), // Local fallback
                    },
                    database: DatabaseConfig {
                        default_path: PathBuf::from("./test_output/testing.db"),
                    },
                    processing: ProcessingConfig {
                        batch_size: 10000,
                        progress_interval: 100000,
                        checkpoint_interval: 1000000,
                    },
                    bitcoin_rpc: BitcoinRpcConfig::default(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_config_with_env_vars() {
        // Set environment variables for testing
        env::set_var("UTXO_CSV_PATH", "/test/path/utxodump.csv");
        env::set_var("P2MS_DATABASE_PATH", "/test/db/test.db");

        // This test will only pass if environment variables are set
        if let Ok(config) = AppConfig::load() {
            assert_eq!(
                config.paths.utxo_csv,
                PathBuf::from("/test/path/utxodump.csv")
            );
            assert_eq!(
                config.database.default_path,
                PathBuf::from("/test/db/test.db")
            );
        }

        // Clean up
        env::remove_var("UTXO_CSV_PATH");
        env::remove_var("P2MS_DATABASE_PATH");
    }

    #[test]
    fn test_get_defaults() {
        // This should always work even without config file
        let defaults = AppConfig::get_defaults();
        assert!(defaults.is_ok());

        let config = defaults.unwrap();
        assert!(config.processing.batch_size > 0);
        assert!(config.processing.progress_interval > 0);
        assert!(config.processing.checkpoint_interval > 0);
    }
}
