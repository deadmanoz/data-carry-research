//! Bitcoin Stamps transport mechanism statistics analyser
//!
//! This module analyses the transport mechanism used by Bitcoin Stamps transactions
//! (Pure vs Counterparty transport) and provides spendability breakdowns for each.

use crate::database::Database;
use crate::errors::AppResult;
use std::collections::HashMap;

// Import types from canonical location (avoids types↔analysis cycle)
pub use crate::types::analysis_results::{
    StampsTransportAnalysis, TransportStats, TransportVariantStats,
};

// Re-export with original name for backward compatibility
pub use TransportVariantStats as VariantStats;

/// Analyse Bitcoin Stamps transport mechanism breakdown
///
/// Provides comprehensive statistics on:
/// - Transaction counts by transport type (Pure vs Counterparty)
/// - Variant distribution within each transport type
/// - Output-level spendability for each transport mechanism
///
/// # Arguments
///
/// * `db` - Database connection
///
/// # Returns
///
/// * `AppResult<StampsTransportAnalysis>` - Complete transport breakdown
///
/// # Performance
///
/// Uses indexed `transport_protocol` column for efficient querying.
/// Requires migration 0001 to be applied.
pub fn analyse_transport_breakdown(db: &Database) -> AppResult<StampsTransportAnalysis> {
    let conn = db.connection();

    // Transaction-level counts by transport and variant
    let tx_query = "
            SELECT
                COALESCE(transport_protocol, 'Pure Bitcoin Stamps') as transport,
                variant,
                COUNT(*) as tx_count
            FROM transaction_classifications
            WHERE protocol = 'BitcoinStamps'
            GROUP BY transport, variant
        ";

    let mut tx_stmt = conn.prepare(tx_query)?;
    let tx_rows = tx_stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, i64>(2)? as usize,
        ))
    })?;

    // Aggregate transaction data
    let mut pure_tx_count = 0usize;
    let mut pure_variants: HashMap<String, usize> = HashMap::new();
    let mut cp_tx_count = 0usize;
    let mut cp_variants: HashMap<String, usize> = HashMap::new();

    for row_result in tx_rows {
        let (transport, variant, count) = row_result?;

        if transport == "Counterparty" {
            cp_tx_count += count;
            if let Some(v) = variant {
                *cp_variants.entry(v).or_insert(0) += count;
            }
        } else {
            // "Pure Bitcoin Stamps" or NULL
            pure_tx_count += count;
            if let Some(v) = variant {
                *pure_variants.entry(v).or_insert(0) += count;
            }
        }
    }

    let total_transactions = pure_tx_count + cp_tx_count;

    // Output-level spendability by transport
    let output_query = "
            SELECT
                COALESCE(tc.transport_protocol, 'Pure Bitcoin Stamps') as transport,
                oc.is_spendable,
                COUNT(*) as output_count
            FROM p2ms_output_classifications oc
            JOIN transaction_classifications tc ON oc.txid = tc.txid
            WHERE tc.protocol = 'BitcoinStamps'
            GROUP BY transport, oc.is_spendable
        ";

    let mut output_stmt = conn.prepare(output_query)?;
    let output_rows = output_stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, bool>(1)?,
            row.get::<_, i64>(2)? as usize,
        ))
    })?;

    // Aggregate output spendability data
    let mut pure_spendable = 0usize;
    let mut pure_unspendable = 0usize;
    let mut cp_spendable = 0usize;
    let mut cp_unspendable = 0usize;

    for row_result in output_rows {
        let (transport, is_spendable, count) = row_result?;

        if transport == "Counterparty" {
            if is_spendable {
                cp_spendable += count;
            } else {
                cp_unspendable += count;
            }
        } else if is_spendable {
            pure_spendable += count;
        } else {
            pure_unspendable += count;
        }
    }

    let total_outputs = pure_spendable + pure_unspendable + cp_spendable + cp_unspendable;

    // Build variant breakdown lists
    let pure_variant_list = build_variant_list(&pure_variants, pure_tx_count);
    let cp_variant_list = build_variant_list(&cp_variants, cp_tx_count);

    Ok(StampsTransportAnalysis {
        total_transactions,
        total_outputs,
        pure_stamps: TransportStats {
            transaction_count: pure_tx_count,
            transaction_percentage: if total_transactions > 0 {
                (pure_tx_count as f64 / total_transactions as f64) * 100.0
            } else {
                0.0
            },
            variant_breakdown: pure_variant_list,
            spendable_outputs: pure_spendable,
            unspendable_outputs: pure_unspendable,
            total_outputs: pure_spendable + pure_unspendable,
        },
        counterparty_transport: TransportStats {
            transaction_count: cp_tx_count,
            transaction_percentage: if total_transactions > 0 {
                (cp_tx_count as f64 / total_transactions as f64) * 100.0
            } else {
                0.0
            },
            variant_breakdown: cp_variant_list,
            spendable_outputs: cp_spendable,
            unspendable_outputs: cp_unspendable,
            total_outputs: cp_spendable + cp_unspendable,
        },
    })
}

/// Build variant statistics list sorted by count (descending)
fn build_variant_list(variants: &HashMap<String, usize>, total_count: usize) -> Vec<VariantStats> {
    let mut variant_list: Vec<VariantStats> = variants
        .iter()
        .map(|(variant, count)| VariantStats {
            variant: variant.clone(),
            count: *count,
            percentage: if total_count > 0 {
                (*count as f64 / total_count as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect();

    // Sort by count descending
    variant_list.sort_by(|a, b| b.count.cmp(&a.count));
    variant_list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyser_with_empty_database() {
        let db = Database::new(":memory:").unwrap();
        let result = analyse_transport_breakdown(&db);

        // Should succeed with empty results
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.total_transactions, 0);
        assert_eq!(analysis.total_outputs, 0);
    }

    #[test]
    fn test_variant_list_sorting() {
        let mut variants = HashMap::new();
        variants.insert("StampsSRC20".to_string(), 100);
        variants.insert("StampsClassic".to_string(), 50);
        variants.insert("StampsSRC721".to_string(), 150);

        let list = build_variant_list(&variants, 300);

        // Should be sorted by count descending
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].variant, "StampsSRC721");
        assert_eq!(list[0].count, 150);
        assert_eq!(list[1].variant, "StampsSRC20");
        assert_eq!(list[1].count, 100);
        assert_eq!(list[2].variant, "StampsClassic");
        assert_eq!(list[2].count, 50);

        // Check percentages
        assert!((list[0].percentage - 50.0).abs() < 0.01);
        assert!((list[1].percentage - 33.33).abs() < 0.01);
    }
}
