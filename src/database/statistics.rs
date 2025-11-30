//! Statistics and reporting operations.

use crate::database::connection::DatabaseConnection;
use crate::database::traits::StatisticsOperations;
use crate::errors::{AppError, AppResult};
use crate::utils::math::{safe_percentage, safe_ratio, safe_ratio_u64};

/// Database statistics for reporting
#[derive(Debug)]
pub struct DatabaseStats {
    pub total_outputs: usize,
    pub coinbase_outputs: usize,
    pub regular_outputs: usize,
    pub min_height: Option<u32>,
    pub max_height: Option<u32>,
}

/// Statistics for Stage 2 enriched transactions
#[derive(Debug)]
pub struct EnrichedTransactionStats {
    pub total_enriched_transactions: usize,
    pub transactions_with_burn_patterns: usize,
    pub total_burn_patterns_detected: usize,
    pub total_fees_analysed: u64,
    pub coinbase_transactions: usize,
    pub regular_transactions: usize,
}

impl EnrichedTransactionStats {
    pub fn burn_pattern_percentage(&self) -> f64 {
        safe_percentage(
            self.transactions_with_burn_patterns,
            self.total_enriched_transactions,
        )
    }

    pub fn average_patterns_per_transaction(&self) -> f64 {
        safe_ratio(
            self.total_burn_patterns_detected,
            self.transactions_with_burn_patterns,
        )
    }

    pub fn average_fee_per_transaction(&self) -> f64 {
        safe_ratio_u64(self.total_fees_analysed, self.regular_transactions as u64)
    }
}

impl StatisticsOperations for DatabaseConnection {
    fn get_database_stats(&self) -> AppResult<DatabaseStats> {
        let total_outputs: usize = self
            .connection()
            .query_row("SELECT COUNT(*) FROM transaction_outputs", [], |row| {
                row.get(0)
            })
            .map_err(AppError::Database)?;

        let coinbase_outputs: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_outputs WHERE is_coinbase = 1",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let regular_outputs = total_outputs - coinbase_outputs;

        let min_height: Option<u32> = self
            .connection()
            .query_row(
                "SELECT MIN(height) FROM transaction_outputs",
                [],
                |row| -> rusqlite::Result<Option<u32>> { row.get(0) },
            )
            .map_err(AppError::Database)?;

        let max_height: Option<u32> = self
            .connection()
            .query_row(
                "SELECT MAX(height) FROM transaction_outputs",
                [],
                |row| -> rusqlite::Result<Option<u32>> { row.get(0) },
            )
            .map_err(AppError::Database)?;

        Ok(DatabaseStats {
            total_outputs,
            coinbase_outputs,
            regular_outputs,
            min_height,
            max_height,
        })
    }

    fn get_enriched_transaction_stats(&self) -> AppResult<EnrichedTransactionStats> {
        let total_enriched: usize = self
            .connection()
            .query_row("SELECT COUNT(*) FROM enriched_transactions", [], |row| {
                row.get(0)
            })
            .map_err(AppError::Database)?;

        let transactions_with_burns: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(DISTINCT txid) FROM burn_patterns",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let total_burn_patterns: usize = self
            .connection()
            .query_row("SELECT COUNT(*) FROM burn_patterns", [], |row| row.get(0))
            .map_err(AppError::Database)?;

        let total_fees: u64 = self
            .connection()
            .query_row(
                "SELECT COALESCE(SUM(transaction_fee), 0) FROM enriched_transactions",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(AppError::Database)? as u64;

        let coinbase_enriched: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM enriched_transactions WHERE is_coinbase = 1",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        Ok(EnrichedTransactionStats {
            total_enriched_transactions: total_enriched,
            transactions_with_burn_patterns: transactions_with_burns,
            total_burn_patterns_detected: total_burn_patterns,
            total_fees_analysed: total_fees,
            coinbase_transactions: coinbase_enriched,
            regular_transactions: total_enriched - coinbase_enriched,
        })
    }
}
