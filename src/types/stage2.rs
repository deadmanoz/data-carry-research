//! Stage 2 specific types and configurations
//!
//! This module contains types specific to Stage 2 transaction enrichment and fee analysis,
//! including enriched transactions, configuration, and statistics.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::burn_patterns;
use super::common::{FeeAnalysis, TransactionInput, TransactionOutput};

/// Configuration for Stage 2 transaction enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage2Config {
    pub database_path: PathBuf,
    pub bitcoin_rpc: crate::config::BitcoinRpcConfig,
    pub batch_size: usize,
    pub progress_interval: usize,
}

impl Default for Stage2Config {
    fn default() -> Self {
        Self {
            database_path: "./test_output/testing.db".into(),
            bitcoin_rpc: crate::config::BitcoinRpcConfig::default(),
            batch_size: 50,         // Transactions per batch
            progress_interval: 100, // Progress report every N transactions
        }
    }
}

/// Builder for Stage2Config with validation
#[derive(Debug, Default)]
pub struct Stage2ConfigBuilder {
    database_path: Option<PathBuf>,
    bitcoin_rpc: Option<crate::config::BitcoinRpcConfig>,
    batch_size: Option<usize>,
    progress_interval: Option<usize>,
}

impl Stage2ConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the database file path
    pub fn database_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.database_path = Some(path.into());
        self
    }

    /// Set the Bitcoin RPC configuration
    pub fn bitcoin_rpc(mut self, config: crate::config::BitcoinRpcConfig) -> Self {
        self.bitcoin_rpc = Some(config);
        self
    }

    /// Set the batch size for processing
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Set the progress reporting interval
    pub fn progress_interval(mut self, interval: usize) -> Self {
        self.progress_interval = Some(interval);
        self
    }

    /// Build the configuration with validation
    pub fn build(self) -> Result<Stage2Config, String> {
        let config = Stage2Config {
            database_path: self
                .database_path
                .unwrap_or_else(|| "./test_output/testing.db".into()),
            bitcoin_rpc: self.bitcoin_rpc.unwrap_or_default(),
            batch_size: self.batch_size.unwrap_or(50),
            progress_interval: self.progress_interval.unwrap_or(100),
        };

        // Validate configuration
        if config.batch_size == 0 {
            return Err("Batch size cannot be zero".to_string());
        }

        if config.progress_interval == 0 {
            return Err("Progress interval cannot be zero".to_string());
        }

        Ok(config)
    }
}

impl Stage2Config {
    /// Create a new builder
    pub fn builder() -> Stage2ConfigBuilder {
        Stage2ConfigBuilder::new()
    }

    /// Validate the current configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.batch_size == 0 {
            return Err("Batch size cannot be zero".to_string());
        }

        if self.progress_interval == 0 {
            return Err("Progress interval cannot be zero".to_string());
        }

        Ok(())
    }
}

/// Enriched transaction with complete fee analysis and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedTransaction {
    pub txid: String,
    pub height: u32,

    // Complete fee analysis
    pub total_input_value: u64,
    pub total_output_value: u64,
    pub transaction_fee: u64,
    pub fee_per_byte: f64,
    pub transaction_size_bytes: u32,
    pub fee_per_kb: f64,

    // P2MS specific analysis
    pub total_p2ms_amount: u64,
    pub data_storage_fee_rate: f64, // sats per byte of P2MS data
    pub p2ms_outputs_count: usize,

    // Burn pattern analysis
    pub burn_patterns_detected: Vec<burn_patterns::BurnPattern>,

    // Transaction metadata
    pub input_count: usize,
    pub output_count: usize,
    pub is_coinbase: bool,

    // All transaction outputs (ALL types: P2MS, P2PKH, OP_RETURN, etc.)
    // Used for protocol detection (Exodus address, OP_RETURN markers)
    // Classifiers MUST filter to P2MS when inserting into p2ms_output_classifications
    pub outputs: Vec<TransactionOutput>,
}

impl EnrichedTransaction {
    /// Create from fee analysis and P2MS outputs
    #[allow(clippy::too_many_arguments)]
    pub fn from_fee_analysis(
        txid: String,
        height: u32,
        fee_analysis: FeeAnalysis,
        p2ms_outputs: Vec<TransactionOutput>,
        inputs: Vec<TransactionInput>,
        output_count: usize,
        is_coinbase: bool,
        burn_patterns: Vec<burn_patterns::BurnPattern>,
    ) -> Self {
        Self {
            txid,
            height,
            total_input_value: fee_analysis.total_input_value,
            total_output_value: fee_analysis.total_output_value,
            transaction_fee: fee_analysis.transaction_fee,
            fee_per_byte: fee_analysis.fee_per_byte,
            transaction_size_bytes: fee_analysis.transaction_size_bytes,
            fee_per_kb: fee_analysis.fee_per_kb,
            total_p2ms_amount: fee_analysis.total_p2ms_amount,
            data_storage_fee_rate: fee_analysis.data_storage_fee_rate,
            p2ms_outputs_count: fee_analysis.p2ms_outputs_count,
            burn_patterns_detected: burn_patterns,
            input_count: inputs.len(),
            output_count,
            is_coinbase,
            outputs: p2ms_outputs,
        }
    }

    /// Calculate the percentage of transaction value stored in P2MS outputs
    pub fn p2ms_value_percentage(&self) -> f64 {
        if self.total_output_value > 0 {
            (self.total_p2ms_amount as f64 / self.total_output_value as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Check if this transaction has significant P2MS usage (>10% of outputs)
    pub fn has_significant_p2ms(&self) -> bool {
        self.p2ms_value_percentage() > 10.0
    }

    /// Get the dominant burn pattern type if any
    pub fn dominant_burn_pattern(&self) -> Option<&burn_patterns::BurnPatternType> {
        if self.burn_patterns_detected.is_empty() {
            return None;
        }

        // Count occurrences of each pattern type
        let mut pattern_counts = std::collections::HashMap::new();
        for pattern in &self.burn_patterns_detected {
            *pattern_counts.entry(&pattern.pattern_type).or_insert(0) += 1;
        }

        // Return the most frequent pattern
        pattern_counts
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&pattern, _)| pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BitcoinRpcConfig;

    #[test]
    fn test_stage2_config_default() {
        let config = Stage2Config::default();
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.progress_interval, 100);
    }

    #[test]
    fn test_stage2_config_builder() {
        let rpc_config = BitcoinRpcConfig {
            url: "http://localhost:8332".to_string(),
            username: "test".to_string(),
            password: "test".to_string(),
            timeout_seconds: 30,
            max_retries: 3,
            initial_backoff_ms: 100,
            backoff_multiplier: 2.0,
            max_backoff_seconds: 10,
            concurrent_requests: 5,
        };

        let config = Stage2Config::builder()
            .database_path("/path/to/db.sqlite")
            .bitcoin_rpc(rpc_config.clone())
            .batch_size(100)
            .progress_interval(50)
            .build()
            .unwrap();

        assert_eq!(config.database_path, PathBuf::from("/path/to/db.sqlite"));
        assert_eq!(config.bitcoin_rpc.url, rpc_config.url);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.progress_interval, 50);
    }

    #[test]
    fn test_stage2_config_validation() {
        // Test invalid batch size
        let result = Stage2Config::builder().batch_size(0).build();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Batch size cannot be zero"));

        // Test invalid progress interval
        let result = Stage2Config::builder().progress_interval(0).build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Progress interval cannot be zero"));
    }

    #[test]
    fn test_enriched_transaction_from_fee_analysis() {
        let fee_analysis = FeeAnalysis {
            total_input_value: 1000000,
            total_output_value: 990000,
            transaction_fee: 10000,
            fee_per_byte: 100.0,
            transaction_size_bytes: 250,
            fee_per_kb: 40000.0,
            total_p2ms_amount: 100000,
            data_storage_fee_rate: 1000.0,
            p2ms_outputs_count: 2,
        };

        let enriched = EnrichedTransaction::from_fee_analysis(
            "test_txid".to_string(),
            700000,
            fee_analysis,
            vec![],
            vec![],
            3,
            false,
            vec![],
        );

        assert_eq!(enriched.txid, "test_txid");
        assert_eq!(enriched.height, 700000);
        assert_eq!(enriched.transaction_fee, 10000);
        assert_eq!(enriched.total_p2ms_amount, 100000);
        assert_eq!(enriched.input_count, 0);
        assert_eq!(enriched.output_count, 3);
        assert!(!enriched.is_coinbase);
        assert!(enriched.burn_patterns_detected.is_empty());
    }

    #[test]
    fn test_p2ms_value_percentage() {
        let mut enriched = EnrichedTransaction::from_fee_analysis(
            "test_txid".to_string(),
            700000,
            FeeAnalysis {
                total_input_value: 1000000,
                total_output_value: 1000000,
                transaction_fee: 0,
                fee_per_byte: 0.0,
                transaction_size_bytes: 250,
                fee_per_kb: 0.0,
                total_p2ms_amount: 100000, // 10% of output value
                data_storage_fee_rate: 0.0,
                p2ms_outputs_count: 1,
            },
            vec![],
            vec![],
            2,
            false,
            vec![],
        );

        assert!((enriched.p2ms_value_percentage() - 10.0).abs() < f64::EPSILON);
        assert!(!enriched.has_significant_p2ms());

        // Test with >10% P2MS
        enriched.total_p2ms_amount = 150000; // 15%
        assert!(enriched.has_significant_p2ms());
    }

    #[test]
    fn test_dominant_burn_pattern() {
        use super::burn_patterns::{BurnConfidence, BurnPattern, BurnPatternType};

        let patterns = vec![
            BurnPattern {
                pattern_type: BurnPatternType::Stamps22Pattern,
                vout: 0,
                pubkey_index: 0,
                pattern_data: "test".to_string(),
                confidence: BurnConfidence::High,
            },
            BurnPattern {
                pattern_type: BurnPatternType::Stamps22Pattern,
                vout: 0,
                pubkey_index: 1,
                pattern_data: "test".to_string(),
                confidence: BurnConfidence::High,
            },
            BurnPattern {
                pattern_type: BurnPatternType::ProofOfBurn,
                vout: 1,
                pubkey_index: 0,
                pattern_data: "test".to_string(),
                confidence: BurnConfidence::High,
            },
        ];

        let enriched = EnrichedTransaction::from_fee_analysis(
            "test_txid".to_string(),
            700000,
            FeeAnalysis {
                total_input_value: 0,
                total_output_value: 0,
                transaction_fee: 0,
                fee_per_byte: 0.0,
                transaction_size_bytes: 0,
                fee_per_kb: 0.0,
                total_p2ms_amount: 0,
                data_storage_fee_rate: 0.0,
                p2ms_outputs_count: 0,
            },
            vec![],
            vec![],
            0,
            false,
            patterns,
        );

        // Stamps22Pattern appears twice, should be dominant
        assert_eq!(
            enriched.dominant_burn_pattern(),
            Some(&BurnPatternType::Stamps22Pattern)
        );
    }
}
