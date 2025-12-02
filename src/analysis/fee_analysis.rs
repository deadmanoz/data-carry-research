//! Fee analysis functionality
//!
//! This module provides comprehensive fee analysis for P2MS transactions.

use crate::database::{Database, QueryHelper};
use crate::errors::AppResult;
use crate::types::analysis_results::{FeeAnalysisReport, FeeStatistics, StorageCostAnalysis};

/// Analyse transaction fees comprehensively
pub fn analyse_transaction_fees(db: &Database) -> AppResult<FeeAnalysisReport> {
    let conn = db.connection();

    // Get transaction counts using QueryHelper
    let total_transactions = conn.count_rows("enriched_transactions", None)?;
    let coinbase_transactions =
        conn.count_rows("enriched_transactions", Some("is_coinbase = 1"))?;
    let regular_transactions = conn.count_rows("enriched_transactions", Some("is_coinbase = 0"))?;

    // Get fee statistics
    let fee_statistics = get_fee_statistics(db)?;

    // Get storage cost analysis
    let storage_cost_analysis = get_storage_costs(db)?;

    Ok(FeeAnalysisReport {
        total_transactions: total_transactions as usize,
        coinbase_transactions: coinbase_transactions as usize,
        regular_transactions: regular_transactions as usize,
        fee_statistics,
        storage_cost_analysis,
    })
}

/// Get detailed fee statistics
pub fn get_fee_statistics(db: &Database) -> AppResult<FeeStatistics> {
    let conn = db.connection();

    // Use safe_aggregate for automatic NULL handling with defaults
    let total_fees_paid = conn.safe_aggregate::<i64>(
        "SELECT SUM(transaction_fee) FROM enriched_transactions",
        0i64,
    )?;

    let average_fee = conn.safe_aggregate::<f64>(
        "SELECT AVG(transaction_fee) FROM enriched_transactions WHERE transaction_fee > 0",
        0.0,
    )?;

    let median_fee_per_byte = conn.safe_aggregate::<f64>(
            "SELECT AVG(fee_per_byte) FROM
                (SELECT fee_per_byte FROM enriched_transactions WHERE fee_per_byte > 0
                 ORDER BY fee_per_byte LIMIT 2 - (SELECT COUNT(*) FROM enriched_transactions WHERE fee_per_byte > 0) % 2
                 OFFSET (SELECT (COUNT(*) - 1) / 2 FROM enriched_transactions WHERE fee_per_byte > 0))",
            0.0,
        )?;

    let average_storage_cost = conn.safe_aggregate::<f64>(
            "SELECT AVG(data_storage_fee_rate) FROM enriched_transactions WHERE data_storage_fee_rate > 0",
            0.0,
        )?;

    Ok(FeeStatistics {
        total_fees_paid: total_fees_paid as u64,
        average_fee,
        median_fee_per_byte,
        average_storage_cost,
    })
}

/// Analyse storage costs for P2MS data
pub fn get_storage_costs(db: &Database) -> AppResult<StorageCostAnalysis> {
    let conn = db.connection();

    // Use safe_aggregate for automatic NULL handling
    let total_p2ms_data_bytes = conn.safe_aggregate::<i64>(
            "SELECT SUM(transaction_size_bytes) FROM enriched_transactions WHERE p2ms_outputs_count > 0",
            0i64,
        )?;

    let average_cost_per_byte = conn.safe_aggregate::<f64>(
            "SELECT AVG(data_storage_fee_rate) FROM enriched_transactions WHERE data_storage_fee_rate > 0",
            0.0,
        )?;

    Ok(StorageCostAnalysis {
        total_p2ms_data_bytes: total_p2ms_data_bytes as usize,
        average_cost_per_byte,
    })
}
