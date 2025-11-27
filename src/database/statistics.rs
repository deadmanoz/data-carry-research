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

/// Statistics for Stage 3 protocol classifications
#[derive(Debug)]
pub struct ClassificationStats {
    pub total_classified: usize,
    #[allow(dead_code)]
    pub bitcoin_stamps: usize,
    #[allow(dead_code)]
    pub counterparty: usize,
    #[allow(dead_code)]
    pub ascii_identifier_protocols: usize,
    #[allow(dead_code)]
    pub omni_layer: usize,
    #[allow(dead_code)]
    pub chancecoin: usize,
    #[allow(dead_code)]
    pub ppk: usize,
    #[allow(dead_code)]
    pub opreturn_signalled: usize,
    #[allow(dead_code)]
    pub data_storage: usize,
    #[allow(dead_code)]
    pub likely_data_storage: usize,
    #[allow(dead_code)]
    pub likely_legitimate: usize,
    #[allow(dead_code)]
    pub unknown: usize,
    pub definitive_signatures: usize,
}

impl ClassificationStats {
    pub fn definitive_signature_rate(&self) -> f64 {
        safe_percentage(self.definitive_signatures, self.total_classified)
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

    fn get_classification_stats(&self) -> AppResult<ClassificationStats> {
        // Helper to count classifications by protocol name
        let count_by_protocol = |protocol: &str| -> AppResult<usize> {
            self.connection()
                .query_row(
                    "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = ?",
                    rusqlite::params![protocol],
                    |row| row.get(0),
                )
                .map_err(AppError::Database)
        };

        let total_classified: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let stamps_count = count_by_protocol("BitcoinStamps")?;
        let counterparty_count = count_by_protocol("Counterparty")?;
        let ascii_identifier_protocols_count = count_by_protocol("AsciiIdentifierProtocols")?;
        let omni_count = count_by_protocol("OmniLayer")?;
        let chancecoin_count = count_by_protocol("Chancecoin")?;
        let ppk_count = count_by_protocol("PPk")?;
        let opreturn_signalled_count = count_by_protocol("OpReturnSignalled")?;
        let datastorage_count = count_by_protocol("DataStorage")?;
        let likely_data_storage_count = count_by_protocol("LikelyDataStorage")?;
        let likely_legitimate_count = count_by_protocol("LikelyLegitimateMultisig")?;
        let unknown_count = count_by_protocol("Unknown")?;

        let signatures_found: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol_signature_found = 1",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        Ok(ClassificationStats {
            total_classified,
            bitcoin_stamps: stamps_count,
            counterparty: counterparty_count,
            ascii_identifier_protocols: ascii_identifier_protocols_count,
            omni_layer: omni_count,
            chancecoin: chancecoin_count,
            ppk: ppk_count,
            opreturn_signalled: opreturn_signalled_count,
            data_storage: datastorage_count,
            likely_data_storage: likely_data_storage_count,
            likely_legitimate: likely_legitimate_count,
            unknown: unknown_count,
            definitive_signatures: signatures_found,
        })
    }
}
