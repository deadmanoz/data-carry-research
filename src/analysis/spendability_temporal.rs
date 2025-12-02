//! Spendability temporal distribution analysis
//!
//! This module provides temporal analysis of P2MS output spendability,
//! showing the percentage of spendable vs unspendable outputs over time.
//!
//! ## Key Design Decisions
//!
//! - **Output-level aggregation**: Counts P2MS outputs (not transactions)
//! - **Fixed 7-day buckets**: Uses `(timestamp / 604800)` for drift-free weekly aggregation
//! - **Week boundaries**: Thursday-to-Wednesday (Unix epoch started Thursday 1970-01-01)
//! - **Percentage display**: Shows spendable/unspendable as percentages of total
//!
//! ## Output Formats
//!
//! - **Console**: Human-readable summary with spendability percentages
//! - **JSON**: Raw structured data with all weekly breakdowns
//! - **Plotly**: Stacked area chart with percentage y-axis

use crate::analysis::reports::ReportFormatter;
use crate::database::Database;
use crate::errors::AppResult;
use crate::types::analysis_results::{SpendabilityTemporalReport, WeeklySpendabilityStats};
use crate::types::visualisation::{PlotlyAnnotation, PlotlyChart, PlotlyLayout, PlotlyTrace};
use crate::utils::time::week_bucket_dates;
use std::collections::HashMap;

/// Analyse temporal distribution of P2MS spendability
///
/// Uses weekly aggregation with fixed 7-day buckets (Thursday-Wednesday).
///
/// # Arguments
/// * `db` - Database connection
///
/// # Returns
/// * `AppResult<SpendabilityTemporalReport>` - Temporal distribution report
pub fn analyse_spendability_temporal_distribution(
    db: &Database,
) -> AppResult<SpendabilityTemporalReport> {
    let conn = db.connection();

    // Weekly spendability aggregation
    let weekly_query = r#"
            SELECT
                (b.timestamp / 604800) AS week_bucket,
                (b.timestamp - (b.timestamp % 604800)) AS week_start_ts,
                poc.is_spendable,
                COUNT(*) AS output_count
            FROM p2ms_output_classifications poc
            JOIN transaction_outputs tout
                ON poc.txid = tout.txid
               AND poc.vout = tout.vout
               AND tout.is_spent = 0
               AND tout.script_type = 'multisig'
            JOIN blocks b ON tout.height = b.height
            WHERE b.timestamp IS NOT NULL
            GROUP BY week_bucket, poc.is_spendable
            ORDER BY week_bucket, poc.is_spendable
        "#;

    let mut stmt = conn.prepare(weekly_query)?;
    let rows = stmt.query_map([], |row| {
        let week_bucket: i64 = row.get(0)?;
        let week_start_ts: i64 = row.get(1)?;
        let is_spendable: i64 = row.get(2)?;
        let output_count: i64 = row.get(3)?;

        Ok((week_bucket, week_start_ts, is_spendable, output_count))
    })?;

    // Group by week
    let mut week_data_map: HashMap<i64, (i64, usize, usize)> = HashMap::new();

    for row_result in rows {
        let (week_bucket, week_start_ts, is_spendable, output_count) = row_result?;
        let entry = week_data_map
            .entry(week_bucket)
            .or_insert((week_start_ts, 0, 0));

        if is_spendable == 1 {
            entry.1 += output_count as usize; // spendable
        } else {
            entry.2 += output_count as usize; // unspendable
        }
    }

    // Handle empty report case
    if week_data_map.is_empty() {
        return Ok(SpendabilityTemporalReport::default());
    }

    // Convert to sorted weekly data
    let mut week_buckets: Vec<i64> = week_data_map.keys().cloned().collect();
    week_buckets.sort();

    let mut weekly_data: Vec<WeeklySpendabilityStats> = Vec::new();
    let mut total_spendable: usize = 0;
    let mut total_unspendable: usize = 0;

    for week_bucket in week_buckets {
        let (week_start_ts, spendable_count, unspendable_count) =
            week_data_map.get(&week_bucket).unwrap();

        let total_count = spendable_count + unspendable_count;
        let spendable_pct = if total_count > 0 {
            (*spendable_count as f64 / total_count as f64) * 100.0
        } else {
            0.0
        };
        let unspendable_pct = 100.0 - spendable_pct;

        let (week_start_iso, week_end_iso) = week_bucket_dates(*week_start_ts);

        total_spendable += spendable_count;
        total_unspendable += unspendable_count;

        weekly_data.push(WeeklySpendabilityStats {
            week_bucket,
            week_start_iso,
            week_end_iso,
            spendable_count: *spendable_count,
            unspendable_count: *unspendable_count,
            total_count,
            spendable_pct,
            unspendable_pct,
        });
    }

    let total_outputs = total_spendable + total_unspendable;
    let overall_spendable_pct = if total_outputs > 0 {
        (total_spendable as f64 / total_outputs as f64) * 100.0
    } else {
        0.0
    };

    Ok(SpendabilityTemporalReport {
        total_outputs,
        spendable_count: total_spendable,
        unspendable_count: total_unspendable,
        overall_spendable_pct,
        week_count: weekly_data.len(),
        weekly_data,
    })
}

impl SpendabilityTemporalReport {
    /// Generate Plotly chart from this report
    ///
    /// Creates a stacked area chart showing spendable vs unspendable percentages.
    pub fn to_plotly_chart(&self) -> PlotlyChart {
        let x_values: Vec<String> = self
            .weekly_data
            .iter()
            .map(|w| w.week_start_iso.clone())
            .collect();

        let spendable_pct: Vec<f64> = self.weekly_data.iter().map(|w| w.spendable_pct).collect();

        let unspendable_pct: Vec<f64> =
            self.weekly_data.iter().map(|w| w.unspendable_pct).collect();

        // Create stacked area traces
        // Spendable goes first (from zero)
        let spendable_trace = PlotlyTrace::stacked_area_with_fill(
            x_values.clone(),
            spendable_pct,
            "Spendable",
            "#2ECC71", // Green
            "rgba(46, 204, 113, 0.7)",
        )
        .fill_to_zero();

        // Unspendable stacks on top
        let unspendable_trace = PlotlyTrace::stacked_area_with_fill(
            x_values,
            unspendable_pct,
            "Unspendable",
            "#E74C3C", // Red
            "rgba(231, 76, 60, 0.7)",
        );

        // Create layout with percentage y-axis
        let mut layout = PlotlyLayout::basic(
            "P2MS Output Spendability Over Time",
            "Date",
            "Percentage of P2MS Outputs",
        )
        .with_legend("v", 1.02, 1.0, "left");

        layout.xaxis.axis_type = Some("date".to_string());
        layout.yaxis.range = Some(vec![0.0, 100.0]);
        layout.yaxis.ticksuffix = Some("%".to_string());

        // Add stats annotation
        let total_formatted = ReportFormatter::format_number(self.total_outputs);
        let stats_text = format!(
            "Total P2MS Outputs: {}<br>Avg Spendable: {:.1}%<br>Avg Unspendable: {:.1}%",
            total_formatted,
            self.overall_spendable_pct,
            100.0 - self.overall_spendable_pct
        );
        layout =
            layout.with_annotations(vec![PlotlyAnnotation::stats_box(&stats_text, 0.02, 0.02)]);

        PlotlyChart {
            data: vec![spendable_trace, unspendable_trace],
            layout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_report_to_plotly() {
        let report = SpendabilityTemporalReport::default();
        let chart = report.to_plotly_chart();
        assert_eq!(chart.data.len(), 2); // Still creates empty traces
        assert_eq!(chart.layout.yaxis.ticksuffix, Some("%".to_string()));
    }
}
