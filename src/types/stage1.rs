//! Stage 1 specific types and configurations
//!
//! This module contains types specific to Stage 1 CSV processing,
//! including configuration and processing statistics.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for Stage 1 CSV processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage1Config {
    pub csv_path: PathBuf,
    pub database_path: PathBuf,
    pub batch_size: usize,
    pub progress_interval: usize,
    pub checkpoint_interval: usize,
    pub resume_from_count: Option<u64>,
}

impl Default for Stage1Config {
    fn default() -> Self {
        Self {
            csv_path: "./utxodump.csv".into(), // Local fallback - should be configured properly
            database_path: "./test_output/testing.db".into(), // Default to TESTING database
            batch_size: 10_000,                // Records per batch insert
            progress_interval: 100_000,        // Progress report every N records
            checkpoint_interval: 1_000_000,    // Checkpoint every N records
            resume_from_count: None,           // Resume from specific count if Some
        }
    }
}

/// Builder for Stage1Config with validation
#[derive(Debug, Default)]
pub struct Stage1ConfigBuilder {
    csv_path: Option<PathBuf>,
    database_path: Option<PathBuf>,
    batch_size: Option<usize>,
    progress_interval: Option<usize>,
    checkpoint_interval: Option<usize>,
    resume_from_count: Option<u64>,
}

impl Stage1ConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the CSV file path
    pub fn csv_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.csv_path = Some(path.into());
        self
    }

    /// Set the database file path
    pub fn database_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.database_path = Some(path.into());
        self
    }

    /// Set the batch size for database operations
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Set the progress reporting interval
    pub fn progress_interval(mut self, interval: usize) -> Self {
        self.progress_interval = Some(interval);
        self
    }

    /// Set the checkpoint interval
    pub fn checkpoint_interval(mut self, interval: usize) -> Self {
        self.checkpoint_interval = Some(interval);
        self
    }

    /// Set the resume point
    pub fn resume_from_count(mut self, count: u64) -> Self {
        self.resume_from_count = Some(count);
        self
    }

    /// Build the configuration with validation
    pub fn build(self) -> Result<Stage1Config, String> {
        let config = Stage1Config {
            csv_path: self.csv_path.unwrap_or_else(|| "./utxodump.csv".into()),
            database_path: self
                .database_path
                .unwrap_or_else(|| "./test_output/testing.db".into()),
            batch_size: self.batch_size.unwrap_or(10_000),
            progress_interval: self.progress_interval.unwrap_or(100_000),
            checkpoint_interval: self.checkpoint_interval.unwrap_or(1_000_000),
            resume_from_count: self.resume_from_count,
        };

        // Validate configuration
        if config.batch_size == 0 {
            return Err("Batch size cannot be zero".to_string());
        }

        if config.progress_interval == 0 {
            return Err("Progress interval cannot be zero".to_string());
        }

        if config.checkpoint_interval == 0 {
            return Err("Checkpoint interval cannot be zero".to_string());
        }

        if config.progress_interval > config.checkpoint_interval {
            return Err("Progress interval cannot be larger than checkpoint interval".to_string());
        }

        Ok(config)
    }
}

impl Stage1Config {
    /// Create a new builder
    #[allow(dead_code)]
    pub fn builder() -> Stage1ConfigBuilder {
        Stage1ConfigBuilder::new()
    }

    /// Validate the current configuration
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), String> {
        if self.batch_size == 0 {
            return Err("Batch size cannot be zero".to_string());
        }

        if self.progress_interval == 0 {
            return Err("Progress interval cannot be zero".to_string());
        }

        if self.checkpoint_interval == 0 {
            return Err("Checkpoint interval cannot be zero".to_string());
        }

        if self.progress_interval > self.checkpoint_interval {
            return Err("Progress interval cannot be larger than checkpoint interval".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage1_config_default() {
        let config = Stage1Config::default();
        assert_eq!(config.batch_size, 10_000);
        assert_eq!(config.progress_interval, 100_000);
        assert_eq!(config.checkpoint_interval, 1_000_000);
        assert!(config.resume_from_count.is_none());
    }

    #[test]
    fn test_stage1_config_builder() {
        let config = Stage1Config::builder()
            .csv_path("/path/to/utxo.csv")
            .database_path("/path/to/db.sqlite")
            .batch_size(5000)
            .progress_interval(50000)
            .checkpoint_interval(500000)
            .resume_from_count(1000)
            .build()
            .unwrap();

        assert_eq!(config.csv_path, PathBuf::from("/path/to/utxo.csv"));
        assert_eq!(config.database_path, PathBuf::from("/path/to/db.sqlite"));
        assert_eq!(config.batch_size, 5000);
        assert_eq!(config.progress_interval, 50000);
        assert_eq!(config.checkpoint_interval, 500000);
        assert_eq!(config.resume_from_count, Some(1000));
    }

    #[test]
    fn test_stage1_config_validation() {
        // Test invalid batch size
        let result = Stage1Config::builder().batch_size(0).build();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Batch size cannot be zero"));

        // Test invalid progress interval
        let result = Stage1Config::builder().progress_interval(0).build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Progress interval cannot be zero"));

        // Test invalid checkpoint interval
        let result = Stage1Config::builder().checkpoint_interval(0).build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Checkpoint interval cannot be zero"));

        // Test progress interval larger than checkpoint interval
        let result = Stage1Config::builder()
            .progress_interval(200_000)
            .checkpoint_interval(100_000)
            .build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Progress interval cannot be larger than checkpoint interval"));
    }

    #[test]
    fn test_config_validate() {
        let valid_config = Stage1Config::default();
        assert!(valid_config.validate().is_ok());

        let invalid_config = Stage1Config {
            batch_size: 0,
            ..Default::default()
        };
        assert!(invalid_config.validate().is_err());
    }
}
