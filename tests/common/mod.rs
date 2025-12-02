//! Common Test Utilities
//!
//! This module provides shared utilities and helper functions used across all test files
//! to reduce code duplication and ensure consistent test setup.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global test counter for generating unique test database paths
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique test database path for a given test
///
/// This function creates a unique database path by combining:
/// - Test name
/// - Process ID
/// - Atomic counter
/// - Current timestamp
///
/// This ensures no test conflicts even when running in parallel.
pub fn create_unique_test_db_path(test_name: &str) -> String {
    let test_dir = PathBuf::from("test_output/unit_tests");
    std::fs::create_dir_all(&test_dir).unwrap();

    let unique_id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let db_path = test_dir.join(format!(
        "{}_{}_{}_{}.db",
        test_name,
        std::process::id(),
        unique_id,
        timestamp
    ));
    db_path.to_str().unwrap().to_string()
}

/// Database setup and teardown utilities
pub mod database {
    use data_carry_research::database::Database;

    /// Test database wrapper that automatically cleans up on drop
    pub struct TestDatabase {
        pub db: Database,
        path: String,
    }

    impl TestDatabase {
        /// Create a new test database with automatic cleanup
        ///
        /// All test databases use the production schema.
        pub fn new(test_name: &str) -> anyhow::Result<Self> {
            let path = super::create_unique_test_db_path(test_name);
            let db = Database::new(&path)?;
            Ok(TestDatabase { db, path })
        }

        /// Get the database path
        pub fn path(&self) -> &str {
            &self.path
        }

        /// Get a reference to the inner database
        pub fn database(&self) -> &Database {
            &self.db
        }

        /// Get a mutable reference to the inner database
        pub fn database_mut(&mut self) -> &mut Database {
            &mut self.db
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            if std::path::Path::new(&self.path).exists() {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    /// Create a test database and ensure it's properly initialised
    pub fn setup_test_database(db_path: &str) -> anyhow::Result<Database> {
        let db = Database::new(db_path)?;
        Ok(db)
    }

    /// Clean up test database file
    pub fn cleanup_test_database(db_path: &str) {
        if std::path::Path::new(db_path).exists() {
            let _ = std::fs::remove_file(db_path);
        }
    }
}

/// Test fixture utilities
pub mod fixtures {
    use data_carry_research::types::burn_patterns::{BurnPattern, BurnPatternType};
    use data_carry_research::types::{EnrichedTransaction, TransactionInput, TransactionOutput};

    /// Create a minimal test P2MS output for testing
    pub fn create_test_p2ms_output(txid: &str, vout: u32, script_hex: &str) -> TransactionOutput {
        create_test_p2ms_output_with_height(txid, vout, script_hex, 0)
    }

    /// Create a minimal test P2MS output with specific height
    pub fn create_test_p2ms_output_with_height(
        txid: &str,
        vout: u32,
        script_hex: &str,
        height: u32,
    ) -> TransactionOutput {
        use data_carry_research::types::script_metadata::MultisigInfo;
        let info = MultisigInfo {
            pubkeys: vec![],
            required_sigs: 1,
            total_pubkeys: 1,
        };
        TransactionOutput {
            txid: txid.to_string(),
            vout,
            height,
            amount: 546, // Dust limit
            script_hex: script_hex.to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: script_hex.len() / 2,
            metadata: serde_json::to_value(info).unwrap(),
            address: None,
        }
    }

    /// Create a minimal test enriched transaction for testing
    pub fn create_test_enriched_transaction(txid: &str) -> EnrichedTransaction {
        EnrichedTransaction {
            txid: txid.to_string(),
            height: 0,
            total_input_value: 100000,
            total_output_value: 99454,
            transaction_fee: 546,
            fee_per_byte: 1.0,
            transaction_size_bytes: 546,
            fee_per_kb: 1000.0,
            total_p2ms_amount: 546,
            data_storage_fee_rate: 1.0,
            p2ms_outputs_count: 1,
            burn_patterns_detected: vec![],
            input_count: 1,
            output_count: 2,
            is_coinbase: false,
            outputs: vec![],
        }
    }

    /// Create a realistic Counterparty issuance transaction
    pub fn counterparty_issuance_tx() -> EnrichedTransaction {
        EnrichedTransaction {
            txid: "a63ee2b1e64d98784ba39c9e6738bc923fd88a808d618dd833254978247d66ea".to_string(),
            height: 0,
            total_input_value: 50000,
            total_output_value: 48500,
            transaction_fee: 1500,
            fee_per_byte: 5.0,
            transaction_size_bytes: 300,
            fee_per_kb: 5000.0,
            total_p2ms_amount: 1000,
            data_storage_fee_rate: 7.5,
            p2ms_outputs_count: 3, // Multi-output for modern Counterparty
            burn_patterns_detected: vec![],
            input_count: 2,
            output_count: 4,
            is_coinbase: false,
            outputs: vec![],
        }
    }

    /// Create a realistic Omni Layer USDT send transaction
    pub fn omni_usdt_send_tx() -> EnrichedTransaction {
        EnrichedTransaction {
            txid: "1caf04b6b0e4d8b0e9b6f5e4d3c2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a".to_string(),
            height: 0,
            total_input_value: 100000,
            total_output_value: 98500,
            transaction_fee: 1500,
            fee_per_byte: 3.0,
            transaction_size_bytes: 500,
            fee_per_kb: 3000.0,
            total_p2ms_amount: 2000,
            data_storage_fee_rate: 6.0,
            p2ms_outputs_count: 2, // Class B P2MS encoding
            burn_patterns_detected: vec![],
            input_count: 1,
            output_count: 3,
            is_coinbase: false,
            outputs: vec![],
        }
    }

    /// Create a realistic Bitcoin Stamps SRC-20 transaction
    pub fn stamps_src20_deploy() -> EnrichedTransaction {
        EnrichedTransaction {
            txid: "def123abc456def789abc012def345abc678def901abc234def567abc890def123".to_string(),
            height: 0,
            total_input_value: 25000,
            total_output_value: 23454,
            transaction_fee: 1546,
            fee_per_byte: 8.0,
            transaction_size_bytes: 193,
            fee_per_kb: 8000.0,
            total_p2ms_amount: 546,
            data_storage_fee_rate: 15.0, // Higher for image data
            p2ms_outputs_count: 1,
            burn_patterns_detected: vec![],
            input_count: 1,
            output_count: 2,
            is_coinbase: false,
            outputs: vec![],
        }
    }

    /// Create an enriched transaction with burn patterns
    pub fn enriched_tx_with_burns(txid: &str) -> EnrichedTransaction {
        EnrichedTransaction {
            txid: txid.to_string(),
            height: 0,
            total_input_value: 10000,
            total_output_value: 9000,
            transaction_fee: 1000,
            fee_per_byte: 10.0,
            transaction_size_bytes: 100,
            fee_per_kb: 10000.0,
            total_p2ms_amount: 1000,
            data_storage_fee_rate: 10.0,
            p2ms_outputs_count: 1,
            burn_patterns_detected: vec![],
            input_count: 1,
            output_count: 2,
            is_coinbase: false,
            outputs: vec![],
        }
    }

    /// Create typical Bitcoin Stamps burn patterns
    pub fn stamps_burn_patterns() -> Vec<BurnPattern> {
        vec![
            BurnPattern {
                pattern_type: BurnPatternType::Stamps22Pattern,
                vout: 0,
                pubkey_index: 0,
                pattern_data: "022222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            BurnPattern {
                pattern_type: BurnPatternType::Stamps33Pattern,
                vout: 0,
                pubkey_index: 1,
                pattern_data: "033333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        ]
    }

    /// Create Counterparty burn patterns
    pub fn counterparty_burn_patterns() -> Vec<BurnPattern> {
        vec![BurnPattern {
            pattern_type: BurnPatternType::ProofOfBurn,
            vout: 1,
            pubkey_index: 0,
            pattern_data: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                .to_string(),
        }]
    }

    /// Create a minimal test transaction input
    pub fn create_test_transaction_input(txid: &str, vout: u32, value: u64) -> TransactionInput {
        TransactionInput {
            txid: txid.to_string(),
            vout,
            value,
            script_sig: "test_script_sig".to_string(),
            sequence: 0xffffffff,
            source_address: Some("1TestInputAddress123456789".to_string()),
        }
    }

    /// Create realistic transaction inputs for protocol tests
    pub fn protocol_transaction_inputs(count: usize) -> Vec<TransactionInput> {
        (0..count)
            .map(|i| TransactionInput {
                txid: format!("input_tx_{:02x}", i),
                vout: i as u32,
                value: 10000 + (i as u64 * 1000),
                script_sig: format!("76a914{}88ac", "deadbeef".repeat(5)),
                sequence: 0xffffffff,
                source_address: Some(format!("1TestProtocolAddr{:02x}123456", i)),
            })
            .collect()
    }
}

/// Protocol test base utilities for standardised testing patterns
pub mod protocol_test_base;

/// Test output formatting utilities
pub mod test_output;

/// Bitcoin RPC test utilities and configuration
pub mod rpc_helpers;

/// Database seeding helpers for FK-safe test data insertion
pub mod db_seeding;

/// Analysis test setup helpers for FK-safe database seeding
pub mod analysis_test_setup;

/// Common assertion helpers for protocol tests
pub mod assertion_helpers;

/// Fixture registry for protocol classification tests
pub mod fixture_registry;

/// JSON fixture loading utilities
pub mod json_fixtures {
    use serde::de::DeserializeOwned;
    use std::fs;
    use std::path::Path;

    /// Load a JSON fixture from the tests/test_data directory
    pub fn load_fixture<T: DeserializeOwned>(name: &str) -> anyhow::Result<T> {
        let fixture_path = Path::new("tests/test_data").join(format!("{}.json", name));
        let json_content = fs::read_to_string(&fixture_path).map_err(|e| {
            anyhow::anyhow!("Failed to read fixture {}: {}", fixture_path.display(), e)
        })?;
        let parsed: T = serde_json::from_str(&json_content).map_err(|e| {
            anyhow::anyhow!("Failed to parse fixture {}: {}", fixture_path.display(), e)
        })?;
        Ok(parsed)
    }

    /// Load a JSON fixture from a specific subdirectory
    pub fn load_protocol_fixture<T: DeserializeOwned>(
        protocol: &str,
        name: &str,
    ) -> anyhow::Result<T> {
        let fixture_path = Path::new("tests/test_data")
            .join(protocol)
            .join(format!("{}.json", name));
        let json_content = fs::read_to_string(&fixture_path).map_err(|e| {
            anyhow::anyhow!("Failed to read fixture {}: {}", fixture_path.display(), e)
        })?;
        let parsed: T = serde_json::from_str(&json_content).map_err(|e| {
            anyhow::anyhow!("Failed to parse fixture {}: {}", fixture_path.display(), e)
        })?;
        Ok(parsed)
    }

    /// Check if a fixture file exists
    pub fn fixture_exists(name: &str) -> bool {
        let fixture_path = Path::new("tests/test_data").join(format!("{}.json", name));
        fixture_path.exists()
    }

    /// List all available fixtures in a directory
    pub fn list_fixtures(subdir: Option<&str>) -> anyhow::Result<Vec<String>> {
        let search_path = if let Some(dir) = subdir {
            Path::new("tests/test_data").join(dir)
        } else {
            Path::new("tests/test_data").to_path_buf()
        };

        let mut fixtures = Vec::new();
        if search_path.exists() && search_path.is_dir() {
            for entry in fs::read_dir(search_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        fixtures.push(stem.to_string());
                    }
                }
            }
        }
        fixtures.sort();
        Ok(fixtures)
    }
}
