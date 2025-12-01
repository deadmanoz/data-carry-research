//! Bitcoin Stamps variant temporal distribution analysis
//!
//! This module provides temporal analysis of Bitcoin Stamps variants,
//! showing the distribution ("age") of unspent P2MS outputs by variant type.
//!
//! ## Key Design Decisions
//!
//! - **Output-level aggregation**: Counts P2MS outputs (not transactions)
//! - **Fixed 7-day buckets**: Uses `(timestamp / 604800)` for drift-free weekly aggregation
//! - **Week boundaries**: Thursday-to-Wednesday (Unix epoch started Thursday 1970-01-01)
//! - **NULL variant detection**: Reports NULL variants separately (indicates bug per CLAUDE.md)
//!
//! ## Output Formats
//!
//! - **Console**: Human-readable summary with variant totals and first appearances
//! - **JSON**: Raw structured data with all weekly breakdowns
//! - **Plotly**: Stacked area chart data with `stackgroup: "one"`

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{
    StampsVariantTemporalReport, VariantFirstSeen, VariantTotal, WeeklyVariantStats,
};
use crate::types::visualisation::{
    get_stamps_variant_colour, PlotlyChart, PlotlyLayout, PlotlyTrace,
};
use chrono::{TimeZone, Utc};
use std::collections::HashMap;

/// Seconds in a week (7 × 24 × 60 × 60 = 604800)
const SECONDS_PER_WEEK: i64 = 604_800;

/// Bitcoin Stamps variant temporal distribution analyser
pub struct StampsVariantTemporalAnalyser;

impl StampsVariantTemporalAnalyser {
    /// Analyse temporal distribution of Bitcoin Stamps variants
    ///
    /// Uses weekly aggregation with fixed 7-day buckets (Thursday-Wednesday).
    /// Reports NULL variants separately as they indicate a classification bug.
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<StampsVariantTemporalReport>` - Temporal distribution report
    pub fn analyse_temporal_distribution(db: &Database) -> AppResult<StampsVariantTemporalReport> {
        let conn = db.connection();

        // Query 1: Weekly variant aggregation
        let weekly_query = r#"
            SELECT
                (b.timestamp / 604800) AS week_bucket,
                (b.timestamp - (b.timestamp % 604800)) AS week_start_ts,
                poc.variant,
                COUNT(*) AS output_count,
                SUM(tout.amount) AS total_sats
            FROM p2ms_output_classifications poc
            JOIN transaction_outputs tout
                ON poc.txid = tout.txid
               AND poc.vout = tout.vout
               AND tout.is_spent = 0
               AND tout.script_type = 'multisig'
            JOIN blocks b ON tout.height = b.height
            WHERE poc.protocol = 'BitcoinStamps'
              AND poc.variant IS NOT NULL
              AND b.timestamp IS NOT NULL
            GROUP BY week_bucket, poc.variant
            ORDER BY week_bucket, poc.variant
        "#;

        let mut stmt = conn.prepare(weekly_query)?;
        let rows = stmt.query_map([], |row| {
            let week_bucket: i64 = row.get(0)?;
            let week_start_ts: i64 = row.get(1)?;
            let variant: String = row.get(2)?;
            let output_count: i64 = row.get(3)?;
            let total_sats: i64 = row.get(4)?;

            Ok((
                week_bucket,
                week_start_ts,
                variant,
                output_count,
                total_sats,
            ))
        })?;

        let mut weekly_data: Vec<WeeklyVariantStats> = Vec::new();
        let mut variant_totals_map: HashMap<String, (usize, u64)> = HashMap::new();
        let mut total_outputs: usize = 0;
        let mut total_value_sats: u64 = 0;

        for row_result in rows {
            let (week_bucket, week_start_ts, variant, output_count, total_sats) = row_result?;

            let week_start_iso = Self::timestamp_to_iso(week_start_ts);
            let week_end_ts = week_start_ts + SECONDS_PER_WEEK - 1;
            let week_end_iso = Self::timestamp_to_iso(week_end_ts);

            let count = output_count as usize;
            let value = total_sats as u64;

            // Accumulate variant totals
            let entry = variant_totals_map.entry(variant.clone()).or_insert((0, 0));
            entry.0 += count;
            entry.1 += value;

            total_outputs += count;
            total_value_sats += value;

            weekly_data.push(WeeklyVariantStats {
                week_bucket,
                week_start_iso,
                week_end_iso,
                variant,
                count,
                value_sats: value,
            });
        }

        // Query 2: NULL variant count (bug indicator)
        // Run BEFORE early return so null-only datasets are surfaced
        let null_count_query = r#"
            SELECT COUNT(*) as null_count
            FROM p2ms_output_classifications poc
            JOIN transaction_outputs tout
                ON poc.txid = tout.txid
               AND poc.vout = tout.vout
               AND tout.is_spent = 0
               AND tout.script_type = 'multisig'
            WHERE poc.protocol = 'BitcoinStamps'
              AND poc.variant IS NULL
        "#;

        let null_variant_count: i64 = conn.query_row(null_count_query, [], |row| row.get(0))?;

        // Handle empty report case (but still include null_variant_count)
        if weekly_data.is_empty() {
            return Ok(StampsVariantTemporalReport {
                null_variant_count: null_variant_count as usize,
                ..Default::default()
            });
        }

        // Query 3: First appearances (CTE with ROW_NUMBER for deterministic tie-breaking)
        let first_appearance_query = r#"
            WITH ranked AS (
                SELECT
                    poc.variant,
                    tout.height,
                    poc.txid,
                    datetime(b.timestamp, 'unixepoch') as first_date,
                    ROW_NUMBER() OVER (
                        PARTITION BY poc.variant
                        ORDER BY tout.height ASC, poc.txid ASC
                    ) as rn
                FROM p2ms_output_classifications poc
                JOIN transaction_outputs tout
                    ON poc.txid = tout.txid
                   AND poc.vout = tout.vout
                   AND tout.is_spent = 0
                   AND tout.script_type = 'multisig'
                JOIN blocks b ON tout.height = b.height
                WHERE poc.protocol = 'BitcoinStamps'
                  AND poc.variant IS NOT NULL
                  AND b.timestamp IS NOT NULL
            )
            SELECT variant, height as first_height, first_date, txid as first_txid
            FROM ranked
            WHERE rn = 1
            ORDER BY first_height ASC
        "#;

        let mut first_stmt = conn.prepare(first_appearance_query)?;
        let first_rows = first_stmt.query_map([], |row| {
            let variant: String = row.get(0)?;
            let first_height: i64 = row.get(1)?;
            let first_date_raw: String = row.get(2)?;
            let first_txid: String = row.get(3)?;

            Ok((variant, first_height, first_date_raw, first_txid))
        })?;

        let mut first_appearances: Vec<VariantFirstSeen> = Vec::new();
        for row_result in first_rows {
            let (variant, first_height, first_date_raw, first_txid) = row_result?;
            let first_date = Self::extract_date_from_datetime(&first_date_raw);

            first_appearances.push(VariantFirstSeen {
                variant,
                first_height: first_height as u64,
                first_date,
                first_txid,
            });
        }

        // Build variant totals with percentages
        let mut variant_totals: Vec<VariantTotal> = variant_totals_map
            .into_iter()
            .map(|(variant, (count, value))| {
                let percentage = if total_outputs > 0 {
                    (count as f64 / total_outputs as f64) * 100.0
                } else {
                    0.0
                };
                VariantTotal {
                    variant,
                    count,
                    percentage,
                    total_value_sats: value,
                }
            })
            .collect();

        // Sort by count descending for consistent display
        variant_totals.sort_by(|a, b| b.count.cmp(&a.count));

        // Extract date range from weekly data
        let date_range_start = weekly_data
            .first()
            .map(|w| w.week_start_iso.clone())
            .unwrap_or_default();
        let date_range_end = weekly_data
            .last()
            .map(|w| w.week_end_iso.clone())
            .unwrap_or_default();

        Ok(StampsVariantTemporalReport {
            total_outputs,
            total_value_sats,
            date_range_start,
            date_range_end,
            variant_totals,
            weekly_data,
            first_appearances,
            null_variant_count: null_variant_count as usize,
        })
    }

    /// Convert Unix timestamp to ISO 8601 date string (YYYY-MM-DD)
    fn timestamp_to_iso(timestamp: i64) -> String {
        match Utc.timestamp_opt(timestamp, 0) {
            chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d").to_string(),
            _ => String::new(),
        }
    }

    /// Extract date portion from datetime string (handles "YYYY-MM-DD HH:MM:SS" format)
    fn extract_date_from_datetime(datetime_str: &str) -> String {
        // SQLite datetime() returns "YYYY-MM-DD HH:MM:SS" format
        // We only want the date part
        datetime_str
            .split(' ')
            .next()
            .unwrap_or(datetime_str)
            .to_string()
    }
}

impl StampsVariantTemporalReport {
    /// Convert report to Plotly stacked area chart
    ///
    /// Creates one trace per variant with stackgroup for proper stacking.
    /// Uses variant-specific colours for visual distinction.
    pub fn to_plotly_chart(&self) -> PlotlyChart {
        // Get unique weeks in order
        let mut weeks: Vec<&str> = self
            .weekly_data
            .iter()
            .map(|w| w.week_start_iso.as_str())
            .collect();
        weeks.dedup();

        // Get unique variants (ordered by total count for legend)
        let variants: Vec<&str> = self
            .variant_totals
            .iter()
            .map(|v| v.variant.as_str())
            .collect();

        // Build a map of (week, variant) -> count for easy lookup
        let mut data_map: HashMap<(&str, &str), usize> = HashMap::new();
        for stats in &self.weekly_data {
            data_map.insert(
                (stats.week_start_iso.as_str(), stats.variant.as_str()),
                stats.count,
            );
        }

        // Create one trace per variant
        let mut traces: Vec<PlotlyTrace> = Vec::new();
        for variant in &variants {
            let x_values: Vec<String> = weeks.iter().map(|w| w.to_string()).collect();
            let y_values: Vec<f64> = weeks
                .iter()
                .map(|week| *data_map.get(&(*week, *variant)).unwrap_or(&0) as f64)
                .collect();

            let colour = get_stamps_variant_colour(variant);
            let trace = PlotlyTrace::line(x_values, y_values, variant, colour).stacked_area();

            traces.push(trace);
        }

        let mut layout = PlotlyLayout::basic(
            "Bitcoin Stamps Variant Distribution Over Time",
            "Week",
            "Output Count",
        );
        layout.xaxis.axis_type = Some("date".to_string());

        PlotlyChart {
            data: traces,
            layout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_to_iso() {
        // Unix epoch (1970-01-01 00:00:00 UTC)
        assert_eq!(
            StampsVariantTemporalAnalyser::timestamp_to_iso(0),
            "1970-01-01"
        );

        // 2023-01-01 00:00:00 UTC (1672531200)
        assert_eq!(
            StampsVariantTemporalAnalyser::timestamp_to_iso(1672531200),
            "2023-01-01"
        );
    }

    #[test]
    fn test_extract_date_from_datetime() {
        assert_eq!(
            StampsVariantTemporalAnalyser::extract_date_from_datetime("2023-01-01 00:00:00"),
            "2023-01-01"
        );
        assert_eq!(
            StampsVariantTemporalAnalyser::extract_date_from_datetime("2023-12-31"),
            "2023-12-31"
        );
    }
}
