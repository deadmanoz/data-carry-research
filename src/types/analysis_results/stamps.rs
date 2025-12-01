//! Bitcoin Stamps-specific analysis types
//!
//! Contains types for Stamps transport, signature, fee, and temporal analysis.

use serde::{Deserialize, Serialize};

// ============================================================================
// Stamps Transport Analysis
// ============================================================================

/// Bitcoin Stamps transport mechanism analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampsTransportAnalysis {
    /// Total number of Bitcoin Stamps transactions
    pub total_transactions: usize,

    /// Total number of Bitcoin Stamps outputs
    pub total_outputs: usize,

    /// Pure Bitcoin Stamps statistics
    #[serde(default)]
    pub pure_stamps: TransportStats,

    /// Counterparty-transported Bitcoin Stamps statistics
    #[serde(default)]
    pub counterparty_transport: TransportStats,
}

/// Statistics for a specific transport mechanism
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportStats {
    /// Number of transactions using this transport
    pub transaction_count: usize,

    /// Percentage of total Bitcoin Stamps transactions
    pub transaction_percentage: f64,

    /// Breakdown by variant (StampsSRC20, StampsClassic, etc.)
    #[serde(default)]
    pub variant_breakdown: Vec<TransportVariantStats>,

    /// Number of spendable outputs
    pub spendable_outputs: usize,

    /// Number of unspendable outputs
    pub unspendable_outputs: usize,

    /// Total outputs for this transport type
    pub total_outputs: usize,
}

/// Variant statistics within a transport mechanism (Stamps-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportVariantStats {
    /// Variant name (e.g., "StampsSRC20")
    pub variant: String,

    /// Number of transactions with this variant
    pub count: usize,

    /// Percentage within this transport type
    pub percentage: f64,
}

// ============================================================================
// Stamps Signature Analysis
// ============================================================================

/// Statistics for a specific signature variant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVariantStats {
    pub variant: String,
    pub count: usize,
    pub percentage: f64,
}

/// Bitcoin Stamps signature variant distribution analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampsSignatureAnalysis {
    pub total_stamps: usize,
    pub signature_distribution: Vec<SignatureVariantStats>,
    pub pure_stamps_signatures: Vec<SignatureVariantStats>,
    pub counterparty_stamps_signatures: Vec<SignatureVariantStats>,
}

// ============================================================================
// Stamps Weekly Fee Analysis
// ============================================================================

/// Weekly fee statistics for Bitcoin Stamps transactions
///
/// Aggregates transaction fees at the TRANSACTION level (not output level)
/// to avoid double-counting fees for multi-output transactions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StampsWeeklyFeeReport {
    /// Number of weeks with data
    pub total_weeks: usize,
    /// Total number of distinct Bitcoin Stamps transactions
    pub total_transactions: usize,
    /// Sum of all transaction fees in satoshis
    pub total_fees_sats: u64,
    /// Per-week breakdown ordered by week_bucket
    pub weekly_data: Vec<WeeklyStampsFeeStats>,
    /// Summary statistics across all weeks
    pub summary: StampsFeeSummary,
}

/// Statistics for a single week of Bitcoin Stamps transactions
///
/// Week boundaries are Thursday-to-Wednesday (Unix epoch started Thursday 1970-01-01).
/// Each bucket is exactly 604800 seconds (7 days) with no drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyStampsFeeStats {
    /// Integer bucket number for ordering (timestamp / 604800)
    pub week_bucket: i64,
    /// Unix timestamp of week start (for Plotly/programmatic use)
    pub week_start_ts: i64,
    /// ISO 8601 date for display (YYYY-MM-DD)
    pub week_start_iso: String,
    /// Week end date for display (YYYY-MM-DD)
    pub week_end_iso: String,
    /// Number of distinct transactions in this week
    pub transaction_count: usize,
    /// Sum of fees in satoshis
    pub total_fees_sats: u64,
    /// Average fee per transaction in satoshis
    pub avg_fee_sats: f64,
    /// Sum of P2MS script_size bytes
    pub total_script_bytes: u64,
    /// Fee efficiency: total_fees / total_script_bytes (0.0 if no script bytes)
    pub avg_fee_per_byte_sats: f64,
}

/// Summary statistics for Bitcoin Stamps fee analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StampsFeeSummary {
    /// First week start date (ISO 8601) or empty string if no data
    pub date_range_start: String,
    /// Last week end date (ISO 8601) or empty string if no data
    pub date_range_end: String,
    /// Total fees in BTC (presentation convenience)
    pub total_fees_btc: f64,
    /// Average fee per transaction across all weeks in satoshis
    pub avg_fee_per_tx_sats: f64,
    /// Average fee per byte across all weeks in satoshis
    pub avg_fee_per_byte_sats: f64,
}

impl Default for StampsFeeSummary {
    fn default() -> Self {
        Self {
            date_range_start: String::new(),
            date_range_end: String::new(),
            total_fees_btc: 0.0,
            avg_fee_per_tx_sats: 0.0,
            avg_fee_per_byte_sats: 0.0,
        }
    }
}

// ============================================================================
// Stamps Variant Temporal Distribution
// ============================================================================

/// Temporal distribution of Bitcoin Stamps variants
///
/// Week boundaries are Thursday-to-Wednesday (Unix epoch started Thursday).
/// Uses fixed 7-day buckets: `timestamp / 604800`
///
/// Follows the same pattern as `StampsWeeklyFeeReport` for consistency.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StampsVariantTemporalReport {
    /// Total outputs with valid (non-NULL) variants
    pub total_outputs: usize,

    /// Total value of all outputs in satoshis
    pub total_value_sats: u64,

    /// First week in the data range (ISO date: YYYY-MM-DD)
    pub date_range_start: String,

    /// Last week in the data range (ISO date: YYYY-MM-DD)
    pub date_range_end: String,

    /// Aggregate statistics per variant
    pub variant_totals: Vec<VariantTotal>,

    /// Weekly time series data - one entry per (week, variant) pair
    pub weekly_data: Vec<WeeklyVariantStats>,

    /// First appearance of each variant (ordered by height)
    pub first_appearances: Vec<VariantFirstSeen>,

    /// Count of outputs with NULL variant (indicates bug - should be 0)
    pub null_variant_count: usize,
}

/// Aggregate statistics for a single variant
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VariantTotal {
    /// Variant name (e.g., "Classic", "SRC-20")
    pub variant: String,

    /// Total output count for this variant
    pub count: usize,

    /// Percentage of total Stamps outputs (denominator = unspent P2MS Stamps with non-NULL variant)
    pub percentage: f64,

    /// Total value of outputs in satoshis
    pub total_value_sats: u64,
}

/// Weekly statistics for a single variant
///
/// Empty weeks are omitted (following stamps_weekly_fee_analysis pattern).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WeeklyVariantStats {
    /// Week bucket number (timestamp / 604800)
    pub week_bucket: i64,

    /// Week start date (ISO format: YYYY-MM-DD)
    pub week_start_iso: String,

    /// Week end date (ISO format: YYYY-MM-DD)
    pub week_end_iso: String,

    /// Variant name
    pub variant: String,

    /// Output count for this variant in this week
    pub count: usize,

    /// Total value in satoshis for this variant in this week
    pub value_sats: u64,
}

/// First appearance information for a variant
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VariantFirstSeen {
    /// Variant name
    pub variant: String,

    /// Block height of first appearance
    pub first_height: u64,

    /// Date of first appearance (ISO format: YYYY-MM-DD)
    pub first_date: String,

    /// TXID of first appearance (deterministic tie-break: MIN(txid) at MIN(height))
    pub first_txid: String,
}
