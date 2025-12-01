//! Protocol temporal distribution analysis
//!
//! This module provides temporal analysis of P2MS protocol classifications,
//! showing the distribution of unspent P2MS outputs by protocol type over time.
//!
//! ## Key Design Decisions
//!
//! - **Output-level aggregation**: Counts P2MS outputs (not transactions)
//! - **Fixed 7-day buckets**: Uses `(timestamp / 604800)` for drift-free weekly aggregation
//! - **Week boundaries**: Thursday-to-Wednesday (Unix epoch started Thursday 1970-01-01)
//!
//! ## Output Formats
//!
//! - **Console**: Human-readable summary with protocol totals
//! - **JSON**: Raw structured data with all weekly breakdowns
//! - **Plotly**: Stacked bar chart data with `barmode: "stack"`

use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{ProtocolTemporalReport, ProtocolTotal, WeeklyProtocolStats};
use crate::types::visualisation::{get_protocol_colour, PlotlyChart, PlotlyLayout, PlotlyTrace};
use crate::types::ProtocolType;
use crate::utils::time::week_bucket_dates;
use std::collections::HashMap;

/// Protocol temporal distribution analyser
pub struct ProtocolTemporalAnalyser;

impl ProtocolTemporalAnalyser {
    /// Analyse temporal distribution of P2MS protocols
    ///
    /// Uses weekly aggregation with fixed 7-day buckets (Thursday-Wednesday).
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<ProtocolTemporalReport>` - Temporal distribution report
    pub fn analyse_temporal_distribution(db: &Database) -> AppResult<ProtocolTemporalReport> {
        let conn = db.connection();

        // Weekly protocol aggregation
        let weekly_query = r#"
            SELECT
                (b.timestamp / 604800) AS week_bucket,
                (b.timestamp - (b.timestamp % 604800)) AS week_start_ts,
                poc.protocol,
                COUNT(*) AS output_count,
                SUM(tout.amount) AS total_sats
            FROM p2ms_output_classifications poc
            JOIN transaction_outputs tout
                ON poc.txid = tout.txid
               AND poc.vout = tout.vout
               AND tout.is_spent = 0
               AND tout.script_type = 'multisig'
            JOIN blocks b ON tout.height = b.height
            WHERE b.timestamp IS NOT NULL
            GROUP BY week_bucket, poc.protocol
            ORDER BY week_bucket, poc.protocol
        "#;

        let mut stmt = conn.prepare(weekly_query)?;
        let rows = stmt.query_map([], |row| {
            let week_bucket: i64 = row.get(0)?;
            let week_start_ts: i64 = row.get(1)?;
            let protocol: String = row.get(2)?;
            let output_count: i64 = row.get(3)?;
            let total_sats: i64 = row.get(4)?;

            Ok((
                week_bucket,
                week_start_ts,
                protocol,
                output_count,
                total_sats,
            ))
        })?;

        let mut weekly_data: Vec<WeeklyProtocolStats> = Vec::new();
        let mut protocol_totals_map: HashMap<String, (usize, u64)> = HashMap::new();
        let mut total_outputs: usize = 0;
        let mut total_value_sats: u64 = 0;
        let mut unique_weeks: std::collections::HashSet<i64> = std::collections::HashSet::new();

        for row_result in rows {
            let (week_bucket, week_start_ts, protocol, output_count, total_sats) = row_result?;

            let (week_start_iso, week_end_iso) = week_bucket_dates(week_start_ts);

            let count = output_count as usize;
            let value = total_sats as u64;

            // Accumulate protocol totals
            let entry = protocol_totals_map
                .entry(protocol.clone())
                .or_insert((0, 0));
            entry.0 += count;
            entry.1 += value;

            total_outputs += count;
            total_value_sats += value;
            unique_weeks.insert(week_bucket);

            weekly_data.push(WeeklyProtocolStats {
                week_bucket,
                week_start_iso,
                week_end_iso,
                protocol,
                count,
                value_sats: value,
            });
        }

        // Handle empty report case
        if weekly_data.is_empty() {
            return Ok(ProtocolTemporalReport::default());
        }

        // Convert protocol totals map to sorted vec (by protocol enum order)
        let mut protocol_totals: Vec<ProtocolTotal> = protocol_totals_map
            .into_iter()
            .map(|(protocol, (count, value_sats))| {
                let display_name = ProtocolType::str_to_display_name(&protocol);
                ProtocolTotal {
                    protocol,
                    display_name,
                    count,
                    value_sats,
                }
            })
            .collect();

        // Sort by protocol enum order
        protocol_totals.sort_by(|a, b| {
            let a_order = ProtocolType::str_to_sort_order(&a.protocol);
            let b_order = ProtocolType::str_to_sort_order(&b.protocol);
            a_order.cmp(&b_order)
        });

        Ok(ProtocolTemporalReport {
            total_outputs,
            total_value_sats,
            week_count: unique_weeks.len(),
            protocol_totals,
            weekly_data,
        })
    }

}

impl ProtocolTemporalReport {
    /// Generate Plotly chart from this report
    pub fn to_plotly_chart(&self) -> PlotlyChart {
        // Group weekly data by protocol
        let mut protocol_weekly: HashMap<String, Vec<(String, f64)>> = HashMap::new();

        for week in &self.weekly_data {
            protocol_weekly
                .entry(week.protocol.clone())
                .or_default()
                .push((week.week_start_iso.clone(), week.count as f64));
        }

        // Get sorted list of all weeks
        let mut all_weeks: Vec<String> = self
            .weekly_data
            .iter()
            .map(|w| w.week_start_iso.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        all_weeks.sort();

        // Create traces ordered by protocol enum order
        let mut traces: Vec<PlotlyTrace> = Vec::new();

        // Sort protocols by enum order (using the totals which are already sorted)
        for total in &self.protocol_totals {
            let protocol = &total.protocol;
            let display_name = &total.display_name;
            let colour = get_protocol_colour(protocol);

            // Build y-values for each week (0 if no data for that week)
            let week_data = protocol_weekly.get(protocol);
            let week_map: HashMap<String, f64> = week_data
                .map(|data| data.iter().cloned().collect())
                .unwrap_or_default();

            let y_values: Vec<f64> = all_weeks
                .iter()
                .map(|week| *week_map.get(week).unwrap_or(&0.0))
                .collect();

            let trace = PlotlyTrace::bar(all_weeks.clone(), y_values, display_name, colour);
            traces.push(trace);
        }

        // Create layout
        let mut layout = PlotlyLayout::basic(
            "P2MS Protocol Distribution Over Time",
            "Date",
            "P2MS Output Count",
        )
        .with_log_toggle()
        .with_legend("v", 1.02, 1.0, "left");
        layout.xaxis.axis_type = Some("date".to_string());
        layout.barmode = Some("stack".to_string());

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
    fn test_empty_report_to_plotly() {
        let report = ProtocolTemporalReport::default();
        let chart = report.to_plotly_chart();
        assert!(chart.data.is_empty());
        assert_eq!(chart.layout.barmode, Some("stack".to_string()));
    }
}
