//! Protocol temporal analysis types

use serde::{Deserialize, Serialize};

/// Temporal distribution of P2MS protocols
///
/// Shows how different protocols (Bitcoin Stamps, Counterparty, etc.) are
/// distributed across weekly time buckets.
///
/// Week boundaries are Thursday-to-Wednesday (Unix epoch started Thursday).
/// Uses fixed 7-day buckets: `timestamp / 604800`
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolTemporalReport {
    /// Total number of unspent P2MS outputs analysed
    pub total_outputs: usize,

    /// Total value in satoshis across all outputs
    pub total_value_sats: u64,

    /// Number of unique weeks with data
    pub week_count: usize,

    /// Per-protocol totals
    pub protocol_totals: Vec<ProtocolTotal>,

    /// Weekly breakdown by protocol - one entry per (week, protocol) pair
    pub weekly_data: Vec<WeeklyProtocolStats>,
}

/// Total counts for a single protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolTotal {
    /// Protocol identifier (e.g., "BitcoinStamps", "Counterparty")
    pub protocol: String,

    /// Human-readable display name
    pub display_name: String,

    /// Total output count for this protocol
    pub count: usize,

    /// Total value in satoshis
    pub value_sats: u64,
}

/// Weekly statistics for a protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WeeklyProtocolStats {
    /// Week bucket number (timestamp / 604800)
    pub week_bucket: i64,

    /// Week start date (ISO format: YYYY-MM-DD)
    pub week_start_iso: String,

    /// Week end date (ISO format: YYYY-MM-DD)
    pub week_end_iso: String,

    /// Protocol identifier
    pub protocol: String,

    /// Output count for this protocol in this week
    pub count: usize,

    /// Total value in satoshis for this protocol in this week
    pub value_sats: u64,
}
