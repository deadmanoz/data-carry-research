//! Bitcoin Stamps weekly fee analysis functionality
//!
//! This module provides temporal fee analysis for Bitcoin Stamps transactions,
//! aggregating data into weekly buckets for trend analysis and visualisation.
//!
//! ## Key Design Decisions
//!
//! - **Transaction-level aggregation**: Fees are counted per transaction (not per output)
//!   to avoid double-counting for multi-output transactions
//! - **Two-CTE approach**: Ensures correct de-duplication when joining transaction and script data
//! - **Fixed 7-day buckets**: Uses `(timestamp / 604800)` for drift-free weekly aggregation
//! - **Week boundaries**: Thursday-to-Wednesday (Unix epoch started Thursday 1970-01-01)
//!
//! ## Output Formats
//!
//! - **Console**: Human-readable table with BTC values
//! - **JSON**: Raw structured data with satoshi values
//! - **Plotly**: Plotly-native trace format with `{data: [...], layout: {...}}`

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    StampsFeeSummary, StampsWeeklyFeeReport, WeeklyStampsFeeStats,
};
use crate::types::visualisation::{PlotlyChart, PlotlyLayout, PlotlyTrace};
use crate::utils::time::{extract_date_from_datetime, timestamp_to_iso, SECONDS_PER_WEEK};

/// Analyse weekly fee statistics for Bitcoin Stamps transactions
///
/// Uses a two-CTE approach to ensure correct de-duplication:
/// - CTE 1 (`stamps_txs`): Gets distinct Bitcoin Stamps transactions with fee + timestamp
/// - CTE 2 (`script_bytes_per_tx`): Sums script_size for Stamps txs only
/// - Main SELECT: Aggregates over distinct transactions, LEFT JOINs script bytes
///
/// # Arguments
/// * `db` - Database connection
///
/// # Returns
/// * `AppResult<StampsWeeklyFeeReport>` - Weekly fee analysis report
pub fn analyse_weekly_fees(db: &Database) -> AppResult<StampsWeeklyFeeReport> {
    let conn = db.connection();

    // Two-CTE query for correct de-duplication
    let query = r#"
            WITH stamps_txs AS (
                -- CTE 1: Get distinct Bitcoin Stamps transactions with fee + timestamp
                SELECT DISTINCT
                    tc.txid,
                    et.transaction_fee,
                    b.timestamp
                FROM transaction_classifications tc
                JOIN enriched_transactions et ON tc.txid = et.txid
                JOIN blocks b ON et.height = b.height
                WHERE tc.protocol = 'BitcoinStamps'
                  AND et.is_coinbase = 0
                  AND b.timestamp IS NOT NULL
            ),
            script_bytes_per_tx AS (
                -- CTE 2: Sum script_size for P2MS outputs of Stamps txs only
                -- Uses IN subquery to avoid re-joining transaction_classifications
                -- GROUP BY ensures exactly one row per txid
                SELECT
                    poc.txid,
                    SUM(tout.script_size) as total_script_bytes
                FROM p2ms_output_classifications poc
                JOIN transaction_outputs tout ON poc.txid = tout.txid AND poc.vout = tout.vout
                WHERE poc.txid IN (SELECT txid FROM stamps_txs)
                  AND tout.script_type = 'multisig'
                GROUP BY poc.txid
            )
            SELECT
                (st.timestamp / 604800) AS week_bucket,
                (st.timestamp - (st.timestamp % 604800)) AS week_start_ts,
                datetime(st.timestamp - (st.timestamp % 604800), 'unixepoch') AS week_start_iso,
                COUNT(*) AS transaction_count,
                CAST(SUM(st.transaction_fee) AS INTEGER) AS total_fees_sats,
                CAST(AVG(CAST(st.transaction_fee AS REAL)) AS REAL) AS avg_fee_sats,
                COALESCE(SUM(sbt.total_script_bytes), 0) AS total_script_bytes
            FROM stamps_txs st
            LEFT JOIN script_bytes_per_tx sbt ON st.txid = sbt.txid
            GROUP BY week_bucket
            ORDER BY week_bucket
        "#;

    let mut stmt = conn.prepare(query)?;
    let rows = stmt.query_map([], |row| {
        let week_bucket: i64 = row.get(0)?;
        let week_start_ts: i64 = row.get(1)?;
        let week_start_iso: String = row.get(2)?;
        let transaction_count: i64 = row.get(3)?;
        let total_fees_sats: i64 = row.get(4)?;
        let avg_fee_sats: f64 = row.get(5)?;
        let total_script_bytes: i64 = row.get(6)?;

        Ok((
            week_bucket,
            week_start_ts,
            week_start_iso,
            transaction_count as usize,
            total_fees_sats as u64,
            avg_fee_sats,
            total_script_bytes as u64,
        ))
    })?;

    let mut weekly_data: Vec<WeeklyStampsFeeStats> = Vec::new();
    let mut total_transactions: usize = 0;
    let mut total_fees_sats: u64 = 0;
    let mut total_script_bytes: u64 = 0;

    for row_result in rows {
        let (
            week_bucket,
            week_start_ts,
            week_start_iso_db,
            tx_count,
            fees_sats,
            avg_fee,
            script_bytes,
        ) = row_result?;

        // Calculate week_end_iso: week_start_ts + 604799 (6 days, 23:59:59)
        let week_end_ts = week_start_ts + SECONDS_PER_WEEK - 1;
        let week_end_iso = timestamp_to_iso(week_end_ts);

        // Clean up week_start_iso (remove time portion if present)
        let week_start_iso = extract_date_from_datetime(&week_start_iso_db);

        // Calculate avg_fee_per_byte_sats (handle div-by-zero)
        let avg_fee_per_byte_sats = if script_bytes > 0 {
            fees_sats as f64 / script_bytes as f64
        } else {
            0.0
        };

        total_transactions += tx_count;
        total_fees_sats += fees_sats;
        total_script_bytes += script_bytes;

        weekly_data.push(WeeklyStampsFeeStats {
            week_bucket,
            week_start_ts,
            week_start_iso,
            week_end_iso,
            transaction_count: tx_count,
            total_fees_sats: fees_sats,
            avg_fee_sats: avg_fee,
            total_script_bytes: script_bytes,
            avg_fee_per_byte_sats,
        });
    }

    // Handle empty report case
    if weekly_data.is_empty() {
        return Ok(StampsWeeklyFeeReport::default());
    }

    // Calculate summary statistics
    let date_range_start = weekly_data
        .first()
        .map(|w| w.week_start_iso.clone())
        .unwrap_or_default();
    let date_range_end = weekly_data
        .last()
        .map(|w| w.week_end_iso.clone())
        .unwrap_or_default();

    let total_fees_btc = total_fees_sats as f64 / 100_000_000.0;
    let avg_fee_per_tx_sats = if total_transactions > 0 {
        total_fees_sats as f64 / total_transactions as f64
    } else {
        0.0
    };
    let avg_fee_per_byte_sats = if total_script_bytes > 0 {
        total_fees_sats as f64 / total_script_bytes as f64
    } else {
        0.0
    };

    Ok(StampsWeeklyFeeReport {
        total_weeks: weekly_data.len(),
        total_transactions,
        total_fees_sats,
        weekly_data,
        summary: StampsFeeSummary {
            date_range_start,
            date_range_end,
            total_fees_btc,
            avg_fee_per_tx_sats,
            avg_fee_per_byte_sats,
        },
    })
}

impl StampsWeeklyFeeReport {
    /// Convert report to Plotly-native JSON format
    ///
    /// Produces three traces:
    /// 1. Total Fees (BTC) - bar chart on primary y-axis
    /// 2. Avg Fee/Tx (sats) - line chart on secondary y-axis
    /// 3. Avg sats/byte - line chart on secondary y-axis (hidden by default)
    pub fn to_plotly_chart(&self) -> PlotlyChart {
        let x_values: Vec<String> = self
            .weekly_data
            .iter()
            .map(|w| w.week_start_iso.clone())
            .collect();

        // Trace 1: Total Fees (BTC) - bar chart
        // Convert from satoshis to BTC for readable values (avoids "2.234B" display)
        let total_fees_trace = PlotlyTrace::bar(
            x_values.clone(),
            self.weekly_data
                .iter()
                .map(|w| w.total_fees_sats as f64 / 100_000_000.0)
                .collect(),
            "Total Fees (BTC)",
            "#E74C3C",
        );

        // Trace 2: Avg Fee/Tx (sats) - line chart on secondary y-axis
        let avg_fee_trace = PlotlyTrace::line(
            x_values.clone(),
            self.weekly_data.iter().map(|w| w.avg_fee_sats).collect(),
            "Avg Fee/Tx (sats)",
            "#3498DB",
        )
        .on_secondary_axis();

        // Trace 3: Avg sats/byte - line chart (hidden by default)
        let sats_per_byte_trace = PlotlyTrace::line(
            x_values,
            self.weekly_data
                .iter()
                .map(|w| w.avg_fee_per_byte_sats)
                .collect(),
            "Avg sats/byte",
            "#2ECC71",
        )
        .on_secondary_axis()
        .hidden_by_default();

        let mut layout = PlotlyLayout::dual_axis(
            "Bitcoin Stamps Weekly Fees",
            "Week",
            "Total Fees (BTC)",
            "Avg Fee/Tx (sats)",
        )
        .with_legend("v", 1.02, 1.0, "left");
        // Set x-axis to date type for proper time series display
        layout.xaxis.axis_type = Some("date".to_string());

        PlotlyChart {
            data: vec![total_fees_trace, avg_fee_trace, sats_per_byte_trace],
            layout,
        }
    }
}

// Tests for time utilities moved to src/utils/time.rs
// Tests for chart generation in tests/unit/analysis/stamps_weekly_fee_analysis.rs
