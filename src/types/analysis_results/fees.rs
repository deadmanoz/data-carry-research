//! Fee analysis types

use serde::{Deserialize, Serialize};

/// Comprehensive fee analysis report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FeeAnalysisReport {
    pub total_transactions: usize,
    pub coinbase_transactions: usize,
    pub regular_transactions: usize,
    pub fee_statistics: FeeStatistics,
    pub storage_cost_analysis: StorageCostAnalysis,
}

/// Detailed fee statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FeeStatistics {
    pub total_fees_paid: u64,
    pub average_fee: f64,
    pub median_fee_per_byte: f64,
    pub average_storage_cost: f64,
}

/// Storage cost analysis for P2MS data
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StorageCostAnalysis {
    pub total_p2ms_data_bytes: usize,
    pub average_cost_per_byte: f64,
}

/// Fee statistics for a specific protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolFeeStats {
    pub total_fees_paid_sats: u64,
    pub average_fee_sats: f64,
    pub average_fee_per_byte: f64,
    pub average_storage_cost_per_byte: f64,
}
