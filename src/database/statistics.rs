//! Statistics and reporting operations.

use crate::database::connection::DatabaseConnection;
use crate::database::traits::StatisticsOperations;
use crate::errors::{AppError, AppResult};

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
        if self.total_enriched_transactions > 0 {
            (self.transactions_with_burn_patterns as f64 / self.total_enriched_transactions as f64)
                * 100.0
        } else {
            0.0
        }
    }

    pub fn average_patterns_per_transaction(&self) -> f64 {
        if self.transactions_with_burn_patterns > 0 {
            self.total_burn_patterns_detected as f64 / self.transactions_with_burn_patterns as f64
        } else {
            0.0
        }
    }

    pub fn average_fee_per_transaction(&self) -> f64 {
        if self.regular_transactions > 0 {
            self.total_fees_analysed as f64 / self.regular_transactions as f64
        } else {
            0.0
        }
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
    #[allow(dead_code)]
    pub fn bitcoin_stamps_percentage(&self) -> f64 {
        if self.total_classified > 0 {
            (self.bitcoin_stamps as f64 / self.total_classified as f64) * 100.0
        } else {
            0.0
        }
    }

    #[allow(dead_code)]
    pub fn counterparty_percentage(&self) -> f64 {
        if self.total_classified > 0 {
            (self.counterparty as f64 / self.total_classified as f64) * 100.0
        } else {
            0.0
        }
    }

    #[allow(dead_code)]
    pub fn omni_layer_percentage(&self) -> f64 {
        if self.total_classified > 0 {
            (self.omni_layer as f64 / self.total_classified as f64) * 100.0
        } else {
            0.0
        }
    }

    #[allow(dead_code)]
    pub fn chancecoin_percentage(&self) -> f64 {
        if self.total_classified > 0 {
            (self.chancecoin as f64 / self.total_classified as f64) * 100.0
        } else {
            0.0
        }
    }

    #[allow(dead_code)]
    pub fn data_storage_percentage(&self) -> f64 {
        if self.total_classified > 0 {
            (self.data_storage as f64 / self.total_classified as f64) * 100.0
        } else {
            0.0
        }
    }

    #[allow(dead_code)]
    pub fn likely_legitimate_percentage(&self) -> f64 {
        if self.total_classified > 0 {
            (self.likely_legitimate as f64 / self.total_classified as f64) * 100.0
        } else {
            0.0
        }
    }

    #[allow(dead_code)]
    pub fn unknown_percentage(&self) -> f64 {
        if self.total_classified > 0 {
            (self.unknown as f64 / self.total_classified as f64) * 100.0
        } else {
            0.0
        }
    }

    pub fn definitive_signature_rate(&self) -> f64 {
        if self.total_classified > 0 {
            (self.definitive_signatures as f64 / self.total_classified as f64) * 100.0
        } else {
            0.0
        }
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
        let total_classified: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let stamps_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'BitcoinStamps'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let counterparty_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'Counterparty'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let ascii_identifier_protocols_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'AsciiIdentifierProtocols'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let omni_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'OmniLayer'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let chancecoin_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'Chancecoin'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let ppk_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'PPk'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let opreturn_signalled_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'OpReturnSignalled'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let datastorage_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'DataStorage'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let likely_data_storage_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'LikelyDataStorage'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let likely_legitimate_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'LikelyLegitimateMultisig'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        let unknown_count: usize = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'Unknown'",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

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
