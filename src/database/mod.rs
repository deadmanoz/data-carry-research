//! Modular database operations for the P2MS protocol analyser.
//!
//! This module provides a clean, modular interface to database operations
//! organised by processing stage and functionality.

#![allow(dead_code)]

pub mod connection;
pub mod helpers; // Shared database helper functions
pub mod query_helper; // Query helper utilities for common patterns
pub mod schema_v2; // Schema V2 - Production-ready with extracted columns
pub mod stage1;
pub mod stage2;
pub mod stage3;
pub mod statistics;
pub mod traits;

// Re-export the main types and traits
pub use connection::DatabaseConnection;
pub use helpers::*; // Export helper functions for use across stages
pub use query_helper::QueryHelper; // Export QueryHelper trait for analysis modules
pub use schema_v2::setup_schema_v2; // Schema V2 setup function
pub use statistics::{ClassificationStats, DatabaseStats, EnrichedTransactionStats};
pub use traits::*;

use crate::errors::AppResult;
use tracing::info;

/// The main database interface that implements all traits
pub struct Database {
    connection: DatabaseConnection,
}

impl Database {
    /// Create a new database instance with Schema V2 (Production-Ready)
    ///
    /// **Recommended**: Use this for all new databases and production runs.
    ///
    /// Schema V2 features:
    /// - Extracted P2MS metadata columns (5-10x query speedup)
    /// - Spending chain tracking for UTXO lifetime analysis
    /// - Block normalisation with stub approach
    /// - Unified burn patterns storage
    ///
    /// ## Stage 1 Requirement
    ///
    /// Stage 1 operations REQUIRE Schema V2 (stub blocks table). Using Schema V1
    /// will fail with "no such table: blocks".
    pub fn new_v2(database_path: &str) -> AppResult<Self> {
        let connection = DatabaseConnection::new(database_path)?;

        // Initialise with Schema V2
        setup_schema_v2(connection.connection())?;

        info!(
            "Database initialised at: {} (Schema V2 - Production)",
            database_path
        );
        Ok(Self { connection })
    }

    /// Get a reference to the underlying connection
    pub fn connection(&self) -> &rusqlite::Connection {
        self.connection.connection()
    }
}

// Implement the DatabaseConnection trait by delegating to the inner connection
impl traits::DatabaseConnection for Database {
    fn connection(&self) -> &rusqlite::Connection {
        self.connection.connection()
    }
}

// Implement all stage operations by delegating to the connection
impl Stage1Operations for Database {
    fn insert_p2ms_batch(&mut self, batch: &[crate::types::TransactionOutput]) -> AppResult<()> {
        self.connection.insert_p2ms_batch(batch)
    }

    fn insert_transaction_output_batch(
        &mut self,
        batch: &[crate::types::TransactionOutput],
    ) -> AppResult<()> {
        self.connection.insert_transaction_output_batch(batch)
    }

    fn save_checkpoint(&mut self, last_count: u64, total_processed: usize) -> AppResult<()> {
        self.connection.save_checkpoint(last_count, total_processed)
    }

    fn get_last_checkpoint(&self) -> AppResult<Option<(u64, usize)>> {
        self.connection.get_last_checkpoint()
    }

    fn get_p2ms_outputs_for_transaction(
        &self,
        txid: &str,
    ) -> AppResult<Vec<crate::types::TransactionOutput>> {
        self.connection.get_p2ms_outputs_for_transaction(txid)
    }

    fn save_checkpoint_enhanced(
        &mut self,
        last_count: u64,
        total_processed: usize,
        csv_line_number: u64,
        batch_number: usize,
    ) -> AppResult<()> {
        self.connection.save_checkpoint_enhanced(
            last_count,
            total_processed,
            csv_line_number,
            batch_number,
        )
    }

    fn get_checkpoint_enhanced(&self) -> AppResult<Option<Stage1Checkpoint>> {
        self.connection.get_checkpoint_enhanced()
    }

    fn clear_checkpoint(&mut self) -> AppResult<()> {
        self.connection.clear_checkpoint()
    }
}

impl Stage2Operations for Database {
    fn get_unprocessed_transactions(&self, limit: usize) -> AppResult<Vec<String>> {
        self.connection.get_unprocessed_transactions(limit)
    }

    fn count_unprocessed_transactions(&self) -> AppResult<u64> {
        self.connection.count_unprocessed_transactions()
    }

    fn insert_enriched_transactions_batch(
        &mut self,
        items: &[(
            crate::types::EnrichedTransaction,
            Vec<crate::types::TransactionInput>,
            Vec<crate::types::TransactionOutput>,
        )],
    ) -> AppResult<()> {
        self.connection.insert_enriched_transactions_batch(items)
    }

    fn get_transaction_inputs(&self, txid: &str) -> AppResult<Vec<crate::types::TransactionInput>> {
        self.connection.get_transaction_inputs(txid)
    }

    fn get_first_input_txid(&self, txid: &str) -> AppResult<Option<String>> {
        self.connection.get_first_input_txid(txid)
    }

    fn get_sender_address_from_largest_input(&self, txid: &str) -> AppResult<Option<String>> {
        self.connection.get_sender_address_from_largest_input(txid)
    }

    fn has_output_to_address(&self, txid: &str, address: &str) -> AppResult<bool> {
        self.connection.has_output_to_address(txid, address)
    }
}

impl Stage3Operations for Database {
    fn get_unclassified_transactions_for_stage3(
        &self,
        limit: usize,
    ) -> AppResult<Vec<crate::types::EnrichedTransaction>> {
        self.connection
            .get_unclassified_transactions_for_stage3(limit)
    }

    fn count_unclassified_transactions_for_stage3(&self) -> AppResult<u64> {
        self.connection.count_unclassified_transactions_for_stage3()
    }

    fn count_classified_transactions_for_stage3(&self) -> AppResult<u64> {
        self.connection.count_classified_transactions_for_stage3()
    }

    fn get_classification_breakdown(
        &self,
    ) -> AppResult<std::collections::HashMap<crate::types::ProtocolType, u64>> {
        self.connection.get_classification_breakdown()
    }

    fn insert_classification_results_batch(
        &mut self,
        results: &[crate::types::ClassificationResult],
    ) -> AppResult<()> {
        self.connection.insert_classification_results_batch(results)
    }

    fn insert_output_classifications_batch(
        &mut self,
        txid: &str,
        outputs: &[crate::types::OutputClassificationData],
    ) -> AppResult<()> {
        self.connection
            .insert_output_classifications_batch(txid, outputs)
    }

    fn get_enriched_transaction(
        &self,
        txid: &str,
    ) -> AppResult<Option<crate::types::EnrichedTransaction>> {
        self.connection.get_enriched_transaction(txid)
    }

    fn get_content_type_distribution(&self) -> AppResult<std::collections::HashMap<String, u64>> {
        self.connection.get_content_type_distribution()
    }

    fn get_content_type_distribution_by_protocol(
        &self,
        protocol: crate::types::ProtocolType,
    ) -> AppResult<std::collections::HashMap<String, u64>> {
        self.connection
            .get_content_type_distribution_by_protocol(protocol)
    }

    fn get_transactions_by_content_type(&self, mime_type: &str) -> AppResult<Vec<String>> {
        self.connection.get_transactions_by_content_type(mime_type)
    }

    fn get_all_outputs_for_transaction(
        &self,
        txid: &str,
    ) -> AppResult<Vec<crate::types::TransactionOutput>> {
        self.connection.get_all_outputs_for_transaction(txid)
    }

    fn get_outputs_by_type(
        &self,
        txid: &str,
        script_type: &str,
    ) -> AppResult<Vec<crate::types::TransactionOutput>> {
        self.connection.get_outputs_by_type(txid, script_type)
    }
}

impl StatisticsOperations for Database {
    fn get_database_stats(&self) -> AppResult<DatabaseStats> {
        self.connection.get_database_stats()
    }

    fn get_enriched_transaction_stats(&self) -> AppResult<EnrichedTransactionStats> {
        self.connection.get_enriched_transaction_stats()
    }

    fn get_classification_stats(&self) -> AppResult<ClassificationStats> {
        self.connection.get_classification_stats()
    }
}

impl DatabaseInterface for Database {
    fn new_v2(database_path: &str) -> AppResult<Self> {
        Database::new_v2(database_path)
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
        let db = Database::new_v2(":memory:").unwrap();

        // Test that the database was created and schema initialised (Schema V2)
        let stats = db.get_database_stats().unwrap();
        assert_eq!(stats.total_outputs, 0);
    }

    #[test]
    fn test_modular_operations() {
        let mut db = Database::new_v2(":memory:").unwrap();

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
        let mut db = Database::new_v2(":memory:").unwrap();

        // Initially no checkpoint
        assert!(db.get_last_checkpoint().unwrap().is_none());

        // Save a checkpoint
        db.save_checkpoint(12345, 100).unwrap();

        // Retrieve checkpoint
        let checkpoint = db.get_last_checkpoint().unwrap().unwrap();
        assert_eq!(checkpoint.0, 12345); // last_count
        assert_eq!(checkpoint.1, 100); // total_processed

        // Update checkpoint
        db.save_checkpoint(67890, 200).unwrap();

        let checkpoint = db.get_last_checkpoint().unwrap().unwrap();
        assert_eq!(checkpoint.0, 67890);
        assert_eq!(checkpoint.1, 200);
    }
}
