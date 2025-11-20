//! Bitcoin P2MS Data-Carrying Protocol Analyser - Type System
//!
//! - `common`: Shared types used across all stages (UtxoRecord, TransactionOutput, etc.)
//! - `stage1`: Stage 1 specific types (Stage1Config, ProcessingStats)
//! - `stage2`: Stage 2 specific types (EnrichedTransaction, Stage2Stats, etc.)
//! - `stage3`: Stage 3 specific types (ClassificationResult, ProtocolType, etc.)
//! - `statistics`: Unified statistics framework with common traits
//! - `burn_patterns`: Centralised burn pattern definitions
//! - `chancecoin`: Chancecoin protocol specific types
//! - `counterparty`: Counterparty protocol specific types
//! - `omni`: Omni Layer protocol specific types
//! - `stamps`: Bitcoin Stamps protocol specific types

// Import all types from the modular structure
mod common;
pub mod script_metadata;
mod stage1;
mod stage2;
mod stage3;
pub mod statistics;

// Protocol-specific modules
pub mod burn_patterns;
pub mod chancecoin;
pub mod content_detection;
pub mod counterparty;
pub mod omni;
pub mod ppk;
pub mod spendability;
pub mod stamps;

// Re-export everything for backward compatibility
pub use common::*;
pub use stage1::*;
pub use stage2::*;
pub use stage3::*;

// Re-export shared parsing functions from script_metadata
pub use script_metadata::{
    is_multisig_script, is_opreturn_script, parse_multisig_anomaly, parse_nonstandard_script,
    parse_opreturn_script, parse_p2ms_script, OpReturnData, ScriptType,
};

// Re-export statistics types for convenience
pub use statistics::{ProcessingStats, Stage2Stats, Stage3Results};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_record_is_p2ms() {
        let p2ms_record = UtxoRecord {
            count: 1,
            txid: "test_txid".to_string(),
            vout: 0,
            height: 100000,
            coinbase: 0,
            amount: 1000,
            script: "5121...53ae".to_string(),
            script_type: "p2ms".to_string(),
            address: "".to_string(),
        };

        let non_p2ms_record = UtxoRecord {
            count: 2,
            txid: "test_txid2".to_string(),
            vout: 1,
            height: 100001,
            coinbase: 0,
            amount: 2000,
            script: "76a914...88ac".to_string(),
            script_type: "p2pkh".to_string(),
            address: "1ABC...".to_string(),
        };

        assert!(p2ms_record.is_p2ms());
        assert!(!non_p2ms_record.is_p2ms());
    }

    #[test]
    fn test_utxo_record_to_p2ms_output() {
        let p2ms_record = UtxoRecord {
            count: 1,
            txid: "test_txid".to_string(),
            vout: 0,
            height: 100000,
            coinbase: 1,
            amount: 1000,
            script: "5121...53ae".to_string(),
            script_type: "p2ms".to_string(),
            address: "".to_string(),
        };

        let p2ms_output = p2ms_record.to_p2ms_output().unwrap();
        assert_eq!(p2ms_output.txid, "test_txid");
        assert_eq!(p2ms_output.vout, 0);
        assert_eq!(p2ms_output.height, 100000);
        assert_eq!(p2ms_output.amount, 1000);
        assert_eq!(p2ms_output.script_hex, "5121...53ae");
        assert!(p2ms_output.is_coinbase);
        // Script parsing will fail for invalid hex, so metadata will have default values
        if let Some(info) = p2ms_output.multisig_info() {
            assert_eq!(info.required_sigs, 0);
            assert_eq!(info.total_pubkeys, 0);
            assert_eq!(info.pubkeys.len(), 0);
        }
        assert_eq!(p2ms_output.script_size, 5); // "5121...53ae".len() / 2
    }

    #[test]
    fn test_utxo_record_to_p2ms_output_fails_for_non_p2ms() {
        let non_p2ms_record = UtxoRecord {
            count: 2,
            txid: "test_txid2".to_string(),
            vout: 1,
            height: 100001,
            coinbase: 0,
            amount: 2000,
            script: "76a914...88ac".to_string(),
            script_type: "p2pkh".to_string(),
            address: "1ABC...".to_string(),
        };

        let result = non_p2ms_record.to_p2ms_output();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not P2MS type"));
    }

    #[test]
    fn test_p2ms_output_key() {
        let output = TransactionOutput {
            txid: "abc123".to_string(),
            vout: 5,
            height: 100000,
            amount: 1000,
            script_hex: "script".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: serde_json::json!({}),
            address: None,
        };

        assert_eq!(output.output_key(), "abc123:5");
    }

    #[test]
    fn test_p2ms_script_parsing() {
        // Test a valid 1-of-2 P2MS script: OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
        let valid_script = "51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179852ae";

        let result = parse_p2ms_script(valid_script);
        assert!(result.is_ok());

        let (pubkeys, required_sigs, total_pubkeys) = result.unwrap();
        assert_eq!(required_sigs, 1);
        assert_eq!(total_pubkeys, 2);
        assert_eq!(pubkeys.len(), 2);

        // Test invalid script
        let invalid_script = "invalid_hex";
        let result = parse_p2ms_script(invalid_script);
        assert!(result.is_err());
    }

    #[test]
    fn test_processing_stats() {
        let mut stats = ProcessingStats::new();
        assert_eq!(stats.total_records, 0);
        assert_eq!(stats.p2ms_found, 0);
        assert_eq!(stats.malformed_records, 0);

        stats.total_records = 100;
        stats.p2ms_found = 10;
        stats.malformed_records = 2;

        assert!((stats.p2ms_rate() - 10.0).abs() < f64::EPSILON);
        assert!((stats.error_rate() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stage3_config_default() {
        let config = Stage3Config::default();
        assert_eq!(config.batch_size, 100);
        // Test Tier 2 patterns are enabled by default
        assert!(config.tier2_patterns_config.enable_2_of_2);
        assert!(config.tier2_patterns_config.enable_2_of_3);
        assert!(config.tier2_patterns_config.enable_3_of_3);
        assert!(config.tier2_patterns_config.enable_3_of_2);
        assert!(config.tier2_patterns_config.enable_multi_output_tier2);
    }

    #[test]
    fn test_stage3_results() {
        let mut results = Stage3Results::new();
        assert_eq!(results.transactions_processed, 0);
        assert_eq!(results.total_classified(), 0);

        results.stamps_classified = 10;
        results.counterparty_classified = 5;
        results.omni_classified = 3;
        results.datastorage_classified = 4;
        results.unknown_classified = 2;

        assert_eq!(results.total_classified(), 24);

        let (
            stamps_pct,
            cp_pct,
            _cpv_pct,
            omni_pct,
            _chancecoin_pct,
            _ppk_pct,
            _opreturn_signalled_pct,
            datastorage_pct,
            _likely_data_pct,
            _legitimate_pct,
            unknown_pct,
        ) = results.classification_breakdown();
        assert!((stamps_pct - (10.0 / 24.0 * 100.0)).abs() < f64::EPSILON);
        assert!((cp_pct - (5.0 / 24.0 * 100.0)).abs() < f64::EPSILON);
        assert!((omni_pct - (3.0 / 24.0 * 100.0)).abs() < f64::EPSILON);
        // Note: chancecoin_pct and legitimate_pct not tested here (0 in test data)
        assert!((datastorage_pct - (4.0 / 24.0 * 100.0)).abs() < f64::EPSILON);
        assert!((unknown_pct - (2.0 / 24.0 * 100.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classification_result_creation() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let details = ClassificationDetails {
            burn_patterns_detected: vec![burn_patterns::BurnPatternType::Stamps22Pattern],
            height_check_passed: true,
            protocol_signature_found: true,
            classification_method: "Burn pattern match".to_string(),
            additional_metadata: None,
            content_type: None,
        };

        let result = ClassificationResult {
            txid: "test_txid".to_string(),
            protocol: ProtocolType::BitcoinStamps,
            variant: Some(ProtocolVariant::StampsClassic),
            classification_details: details,
            classification_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        assert_eq!(result.txid, "test_txid");
        assert_eq!(result.protocol, ProtocolType::BitcoinStamps);
        assert_eq!(result.variant, Some(ProtocolVariant::StampsClassic));
        assert!(result.classification_details.height_check_passed);
        assert!(result.classification_details.protocol_signature_found);
    }

    /// Test that the new builder patterns work correctly
    #[test]
    fn test_config_builders() {
        // Test Stage1Config builder
        let stage1_config = Stage1Config::builder()
            .batch_size(5000)
            .progress_interval(50000)
            .build()
            .unwrap();
        assert_eq!(stage1_config.batch_size, 5000);
        assert_eq!(stage1_config.progress_interval, 50000);

        // Test Stage2Config builder
        let stage2_config = Stage2Config::builder()
            .batch_size(25)
            .progress_interval(50)
            .build()
            .unwrap();
        assert_eq!(stage2_config.batch_size, 25);
        assert_eq!(stage2_config.progress_interval, 50);

        // Test Stage3Config builder
        let stage3_config = Stage3Config::builder().batch_size(150).build().unwrap();
        assert_eq!(stage3_config.batch_size, 150);
    }

    /// Test that the statistics framework works with the StatisticsCollector trait
    #[test]
    fn test_statistics_collector_trait() {
        use crate::types::statistics::StatisticsCollector;
        use std::thread;
        use std::time::Duration;

        let mut stats = ProcessingStats::new();
        let start = stats.start_time();

        // Add some data
        stats.total_records = 1000;
        stats.p2ms_found = 100;

        // Add a small delay to ensure time difference
        thread::sleep(Duration::from_millis(1));

        // Test the trait methods
        assert!(stats.duration().as_nanos() > 0);
        assert!(stats.processing_rate() >= 0.0);

        let summary = stats.summary();
        assert!(summary.contains("1000 total records"));
        assert!(summary.contains("100 P2MS found"));

        // Test reset
        stats.reset();
        assert_eq!(stats.total_records, 0);
        assert_eq!(stats.p2ms_found, 0);
        assert!(stats.start_time() > start);
    }
}
