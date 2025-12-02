//! Modular database operations for the P2MS protocol analyser.
//!
//! This module provides a clean interface to database operations
//! organised by processing stage and functionality.
//!
//! ## Architecture
//!
//! The `Database` struct directly implements all stage operation traits:
//! - `Stage1Operations` - P2MS detection and storage
//! - `Stage2Operations` - Transaction enrichment
//! - `Stage3Operations` - Protocol classification
//! - `StatisticsOperations` - Statistics and reporting

pub mod helpers; // Shared database helper functions
pub mod query_helper; // Query helper utilities for common patterns
pub mod schema;
mod stage1;
mod stage2;
mod stage3;
pub mod statistics;
pub mod traits;

// Re-export the main types and traits
pub use helpers::*; // Export helper functions for use across stages
pub use query_helper::QueryHelper; // Export QueryHelper trait for analysis modules
pub use schema::setup_schema;
pub use stage3::operations::NO_MIME_TYPE_SENTINEL; // Content type sentinel for analysis
pub use statistics::{DatabaseStats, EnrichedTransactionStats};
pub use traits::*;

use crate::errors::AppResult;
use rusqlite::Connection;
use tracing::info;

/// The main database interface that implements all stage operation traits.
///
/// This struct directly holds a SQLite connection and provides all database
/// operations through trait implementations organised by pipeline stage.
pub struct Database {
    connection: Connection,
}

impl Database {
    /// Create a new database instance
    ///
    /// Schema features:
    /// - Extracted P2MS metadata columns (5-10x query speedup)
    /// - Spending chain tracking for UTXO lifetime analysis
    /// - Block normalisation with stub approach
    /// - Unified burn patterns storage
    /// - FK constraints requiring proper stage ordering
    ///
    /// ## Stage 1 Requirement
    ///
    /// Stage 1 operations require the stub blocks table. The schema must be
    /// initialised before Stage 1 processing begins.
    pub fn new(database_path: &str) -> AppResult<Self> {
        let connection = Connection::open(database_path)?;

        // Initialise the schema
        setup_schema(&connection)?;

        info!("Database initialised at: {}", database_path);
        Ok(Self { connection })
    }

    /// Get a reference to the underlying connection
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Execute a function within a database transaction
    pub fn execute_transaction<F, R>(&mut self, f: F) -> AppResult<R>
    where
        F: FnOnce(&rusqlite::Transaction) -> AppResult<R>,
    {
        let tx = self.connection.transaction()?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TransactionOutput;

    fn create_test_output(txid: &str, vout: u32, height: u32) -> TransactionOutput {
        TransactionOutput {
            txid: txid.to_string(),
            vout,
            height,
            amount: 1000,
            script_hex: "test_script".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: serde_json::json!({}),
            address: None,
        }
    }

    #[test]
    fn test_database_creation() {
        let db = Database::new(":memory:").unwrap();

        // Test that the database was created and schema initialised
        let stats = db.get_database_stats().unwrap();
        assert_eq!(stats.total_outputs, 0);
    }

    #[test]
    fn test_modular_operations() {
        let mut db = Database::new(":memory:").unwrap();

        let batch = vec![
            create_test_output("txid1", 0, 100000),
            create_test_output("txid2", 1, 100001),
            create_test_output("txid3", 0, 100002),
        ];

        // Test Stage 1 operations
        db.insert_p2ms_batch(&batch).unwrap();

        let stats = db.get_database_stats().unwrap();
        assert_eq!(stats.total_outputs, 3);
        assert_eq!(stats.regular_outputs, 3);
        assert_eq!(stats.coinbase_outputs, 0);
        assert_eq!(stats.min_height, Some(100000));
        assert_eq!(stats.max_height, Some(100002));

        // Test Stage 2 operations
        let unprocessed = db.get_unprocessed_transactions(10).unwrap();
        assert_eq!(unprocessed.len(), 3); // txid1, txid2, and txid3 (distinct)

        let count = db.count_unprocessed_transactions().unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_checkpoint_operations() {
        let mut db = Database::new(":memory:").unwrap();

        // Initially no checkpoint
        assert!(db.get_checkpoint_enhanced().unwrap().is_none());

        // Save a checkpoint
        db.save_checkpoint_enhanced(12345, 100, 12346, 10).unwrap();

        // Retrieve checkpoint
        let checkpoint = db.get_checkpoint_enhanced().unwrap().unwrap();
        assert_eq!(checkpoint.last_processed_count, 12345);
        assert_eq!(checkpoint.total_processed, 100);
        assert_eq!(checkpoint.csv_line_number, 12346);
        assert_eq!(checkpoint.batch_number, 10);

        // Update checkpoint
        db.save_checkpoint_enhanced(67890, 200, 67891, 20).unwrap();

        let checkpoint = db.get_checkpoint_enhanced().unwrap().unwrap();
        assert_eq!(checkpoint.last_processed_count, 67890);
        assert_eq!(checkpoint.total_processed, 200);
        assert_eq!(checkpoint.csv_line_number, 67891);
        assert_eq!(checkpoint.batch_number, 20);
    }
}
