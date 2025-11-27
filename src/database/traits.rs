//! Database trait abstractions for modular database operations.
//!
//! This module defines the core traits that abstract database operations
//! across different stages of the processing pipeline.

#![allow(dead_code)]

use crate::errors::AppResult;
use crate::types::{
    ClassificationResult, EnrichedTransaction, TransactionInput, TransactionOutput,
};

/// Core database connection and transaction management
pub trait DatabaseConnection {
    /// Get a reference to the underlying SQLite connection
    fn connection(&self) -> &rusqlite::Connection;
}

/// Stage 1 database operations - P2MS detection and storage
pub trait Stage1Operations {
    /// Insert a batch of P2MS outputs (legacy method)
    fn insert_p2ms_batch(&mut self, batch: &[TransactionOutput]) -> AppResult<()>;

    /// Insert a batch of transaction outputs (new generic method)
    fn insert_transaction_output_batch(&mut self, batch: &[TransactionOutput]) -> AppResult<()>;

    /// Save processing checkpoint (legacy method - kept for backward compatibility)
    fn save_checkpoint(&mut self, last_count: u64, total_processed: usize) -> AppResult<()>;

    /// Save enhanced checkpoint with CSV line number for Stage 1 resume
    fn save_checkpoint_enhanced(
        &mut self,
        last_count: u64,
        total_processed: usize,
        csv_line_number: u64,
        batch_number: usize,
    ) -> AppResult<()>;

    /// Get the last checkpoint (legacy method - returns simple tuple)
    fn get_last_checkpoint(&self) -> AppResult<Option<(u64, usize)>>;

    /// Get enhanced checkpoint with CSV line number for resuming
    fn get_checkpoint_enhanced(&self) -> AppResult<Option<Stage1Checkpoint>>;

    /// Clear checkpoint (call after successful completion)
    fn clear_checkpoint(&mut self) -> AppResult<()>;

    /// Get P2MS outputs for a specific transaction
    fn get_p2ms_outputs_for_transaction(&self, txid: &str) -> AppResult<Vec<TransactionOutput>>;
}

/// Enhanced checkpoint state for Stage 1 (CSV processing)
#[derive(Debug, Clone)]
pub struct Stage1Checkpoint {
    pub last_processed_count: u64,
    pub total_processed: usize,
    pub csv_line_number: u64,
    pub batch_number: usize,
    pub created_at: String,
}

/// Stage 2 database operations - Transaction enrichment
pub trait Stage2Operations {
    /// Get unprocessed transactions for enrichment
    fn get_unprocessed_transactions(&self, limit: usize) -> AppResult<Vec<String>>;

    /// Count unprocessed transactions
    fn count_unprocessed_transactions(&self) -> AppResult<u64>;

    /// Insert enriched transactions in batch
    /// Stage 2 writes ALL outputs for transactions containing P2MS outputs
    fn insert_enriched_transactions_batch(
        &mut self,
        items: &[(
            EnrichedTransaction,
            Vec<TransactionInput>,
            Vec<TransactionOutput>, // Changed from Vec<OpReturnOutput> - now accepts ALL outputs
        )],
    ) -> AppResult<()>;

    /// Get transaction inputs for a specific transaction
    fn get_transaction_inputs(&self, txid: &str) -> AppResult<Vec<TransactionInput>>;

    /// Get first input TXID (for Counterparty ARC4 decryption)
    fn get_first_input_txid(&self, txid: &str) -> AppResult<Option<String>>;

    /// Get sender address from largest input (for Omni deobfuscation)
    fn get_sender_address_from_largest_input(&self, txid: &str) -> AppResult<Option<String>>;

    /// Check if transaction has an output to a specific address
    /// Replaces: has_exodus_address_output, has_wikileaks_address_output, has_marker_output
    fn has_output_to_address(&self, txid: &str, address: &str) -> AppResult<bool>;

    /// Update blocks with hash and timestamp (Stage 2A backfill)
    /// Wraps all updates in single transaction for performance
    /// Uses UPDATE (stub blocks guaranteed by Stage 1)
    fn update_blocks_batch(&mut self, blocks: &[(u32, String, u64)]) -> AppResult<usize>;

    /// Get heights from list that still need block hash or timestamp (either NULL)
    /// Handles partial backfill cases where one field is set but not the other
    fn get_heights_needing_block_info(&self, heights: &[u32]) -> AppResult<Vec<u32>>;
}

/// Stage 3 database operations - Protocol classification
pub trait Stage3Operations {
    /// Get unclassified transactions for protocol classification
    fn get_unclassified_transactions_for_stage3(
        &self,
        limit: usize,
    ) -> AppResult<Vec<EnrichedTransaction>>;

    /// Count unclassified transactions
    fn count_unclassified_transactions_for_stage3(&self) -> AppResult<u64>;

    /// Count already-classified transactions
    fn count_classified_transactions_for_stage3(&self) -> AppResult<u64>;

    /// Get classification breakdown for already-classified transactions
    fn get_classification_breakdown(
        &self,
    ) -> AppResult<std::collections::HashMap<crate::types::ProtocolType, u64>>;

    /// Insert classification results in batch
    fn insert_classification_results_batch(
        &mut self,
        results: &[ClassificationResult],
    ) -> AppResult<()>;

    /// Insert output classifications in batch for a specific transaction
    ///
    /// This method should be called AFTER the transaction classification has been inserted
    /// to satisfy FK constraints (p2ms_output_classifications.txid -> transaction_classifications.txid).
    ///
    /// # Arguments
    /// * `txid` - The transaction ID for all output classifications
    /// * `outputs` - Vector of output classification data
    fn insert_output_classifications_batch(
        &mut self,
        txid: &str,
        outputs: &[crate::types::OutputClassificationData],
    ) -> AppResult<()>;

    /// Get enriched transaction by txid
    fn get_enriched_transaction(&self, txid: &str) -> AppResult<Option<EnrichedTransaction>>;

    /// Get content type distribution across all classifications.
    /// Returns a map of MIME type -> count. Implementations may use a sentinel
    /// value for records without a stored MIME type (see
    /// `stage3::operations::NO_MIME_TYPE_SENTINEL`).
    fn get_content_type_distribution(&self) -> AppResult<std::collections::HashMap<String, u64>>;

    /// Get content type distribution for a specific protocol.
    fn get_content_type_distribution_by_protocol(
        &self,
        protocol: crate::types::ProtocolType,
    ) -> AppResult<std::collections::HashMap<String, u64>>;

    /// Get all transactions with a specific content type
    fn get_transactions_by_content_type(&self, mime_type: &str) -> AppResult<Vec<String>>;

    /// Get ALL outputs for a transaction (used for comprehensive protocol analysis)
    fn get_all_outputs_for_transaction(&self, txid: &str) -> AppResult<Vec<TransactionOutput>>;

    /// Get outputs filtered by script type (e.g., "op_return", "multisig", "p2pkh")
    /// More efficient than get_all_outputs_for_transaction when you only need specific types
    fn get_outputs_by_type(
        &self,
        txid: &str,
        script_type: &str,
    ) -> AppResult<Vec<TransactionOutput>>;
}

/// Statistics and reporting operations
pub trait StatisticsOperations {
    /// Get basic database statistics
    fn get_database_stats(&self) -> AppResult<crate::database::DatabaseStats>;

    /// Get enriched transaction statistics
    fn get_enriched_transaction_stats(
        &self,
    ) -> AppResult<crate::database::EnrichedTransactionStats>;

    /// Get classification statistics
    fn get_classification_stats(&self) -> AppResult<crate::database::ClassificationStats>;
}

/// Combined database interface that includes all operations
pub trait DatabaseInterface:
    DatabaseConnection + Stage1Operations + Stage2Operations + Stage3Operations + StatisticsOperations
{
    /// Create a new database instance with Schema V2 (Production-Ready)
    ///
    /// **Required**: All databases must use Schema V2. Schema V1 has been removed.
    ///
    /// Schema V2 features:
    /// - Extracted P2MS metadata columns (5-10x query speedup)
    /// - Spending chain tracking for UTXO lifetime analysis
    /// - Block normalisation with stub approach
    /// - Unified burn patterns storage
    fn new_v2(database_path: &str) -> AppResult<Self>
    where
        Self: Sized;
}
