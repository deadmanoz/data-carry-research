//! Spendability analysis types

use crate::types::ProtocolType;
use serde::{Deserialize, Serialize};

/// Spendability analysis comprehensive report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SpendabilityStatsReport {
    pub overall: OverallSpendability,
    pub protocol_breakdown: Vec<ProtocolSpendabilityStats>,
    pub reason_distribution: Vec<ReasonStats>,
    pub key_count_distribution: KeyCountDistribution,
    pub transaction_level: TransactionSpendabilityStats,
}

/// Overall spendability breakdown
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OverallSpendability {
    pub total_outputs: usize,
    pub spendable_count: usize,
    pub spendable_percentage: f64,
    pub unspendable_count: usize,
    pub unspendable_percentage: f64,
}

/// Per-protocol spendability statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolSpendabilityStats {
    pub protocol: ProtocolType,
    pub total_outputs: usize,
    pub spendable_count: usize,
    pub spendable_percentage: f64,
    pub unspendable_count: usize,
    pub unspendable_percentage: f64,
}

/// Spendability reason distribution
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReasonStats {
    pub reason: String,
    pub count: usize,
    pub percentage: f64,
}

/// Key count distribution statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyCountDistribution {
    pub real_pubkey_stats: KeyCountStats,
    pub burn_key_stats: KeyCountStats,
    pub data_key_stats: KeyCountStats,
}

/// Statistics for a specific key count type
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeyCountStats {
    pub total: u64,
    pub average: f64,
    pub min: u8,
    pub max: u8,
}

/// Transaction-level spendability statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TransactionSpendabilityStats {
    pub total_transactions: usize,
    pub transactions_with_spendable_outputs: usize,
    pub transactions_all_unspendable: usize,
    pub spendable_transaction_percentage: f64,
}

// ============================================================================
// Spendability Temporal Analysis Types
// ============================================================================

/// Temporal distribution of P2MS output spendability
///
/// Shows the percentage of spendable vs unspendable outputs over time.
///
/// Week boundaries are Thursday-to-Wednesday (Unix epoch started Thursday).
/// Uses fixed 7-day buckets: `timestamp / 604800`
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SpendabilityTemporalReport {
    /// Total number of unspent P2MS outputs analysed
    pub total_outputs: usize,

    /// Number of spendable outputs
    pub spendable_count: usize,

    /// Number of unspendable outputs
    pub unspendable_count: usize,

    /// Overall spendable percentage
    pub overall_spendable_pct: f64,

    /// Number of unique weeks with data
    pub week_count: usize,

    /// Weekly breakdown
    pub weekly_data: Vec<WeeklySpendabilityStats>,
}

/// Weekly statistics for spendability
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WeeklySpendabilityStats {
    /// Week bucket number (timestamp / 604800)
    pub week_bucket: i64,

    /// Week start date (ISO format: YYYY-MM-DD)
    pub week_start_iso: String,

    /// Week end date (ISO format: YYYY-MM-DD)
    pub week_end_iso: String,

    /// Number of spendable outputs in this week
    pub spendable_count: usize,

    /// Number of unspendable outputs in this week
    pub unspendable_count: usize,

    /// Total outputs in this week
    pub total_count: usize,

    /// Percentage of spendable outputs
    pub spendable_pct: f64,

    /// Percentage of unspendable outputs
    pub unspendable_pct: f64,
}
