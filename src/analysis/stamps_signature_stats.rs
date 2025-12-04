//! Bitcoin Stamps signature variant distribution analysis
//!
//! Analyses the distribution of signature variants across Bitcoin Stamps transactions.
//! Tracks usage of different signature formats (stamp:, STAMP:, stamps:, STAMPS:) and
//! correlates with transport mechanisms (Pure vs Counterparty).

use crate::database::Database;
use crate::errors::AppResult;
use std::collections::HashMap;

// Import types from canonical location (avoids types↔analysis cycle)
pub use crate::types::analysis_results::{SignatureVariantStats, StampsSignatureAnalysis};

/// Transport protocol constant for Pure Bitcoin Stamps
const PURE_STAMPS_TRANSPORT: &str = "Pure Bitcoin Stamps";

/// Analyse signature variant distribution across all Bitcoin Stamps transactions
pub fn analyse_signature_distribution(db: &Database) -> AppResult<StampsSignatureAnalysis> {
    // Query uses indexed transport_protocol column + nested JSON extract
    // The stamp_signature_variant is inside additional_metadata (a JSON string inside additional_metadata_json)
    // CRITICAL: Cannot use alias in WHERE clause - must use full json_extract expression
    let query = r#"
            SELECT
              COALESCE(transport_protocol, 'Pure Bitcoin Stamps') as transport,
              json_extract(json_extract(additional_metadata_json, '$.additional_metadata'), '$.stamp_signature_variant') as sig_variant,
              COUNT(*) as count
            FROM transaction_classifications
            WHERE protocol = 'BitcoinStamps'
              AND json_extract(json_extract(additional_metadata_json, '$.additional_metadata'), '$.stamp_signature_variant') IS NOT NULL
            GROUP BY transport, sig_variant
            ORDER BY transport, count DESC
        "#;

    let mut stmt = db.connection().prepare(query)?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,       // transport
            row.get::<_, String>(1)?,       // sig_variant
            row.get::<_, i64>(2)? as usize, // count
        ))
    })?;

    // Collect results into maps
    let mut total_stamps = 0;
    let mut overall_map: HashMap<String, usize> = HashMap::new();
    let mut pure_map: HashMap<String, usize> = HashMap::new();
    let mut cp_map: HashMap<String, usize> = HashMap::new();

    for row_result in rows {
        let (transport, variant, count) = row_result?;
        total_stamps += count;
        *overall_map.entry(variant.clone()).or_insert(0) += count;

        // Use explicit equality check with constant to avoid substring matching issues
        if transport == PURE_STAMPS_TRANSPORT {
            *pure_map.entry(variant).or_insert(0) += count;
        } else {
            *cp_map.entry(variant).or_insert(0) += count;
        }
    }

    // Convert maps to sorted vectors with percentages
    let signature_distribution = map_to_stats(&overall_map, total_stamps);
    let pure_stamps_signatures = map_to_stats(&pure_map, pure_map.values().sum::<usize>());
    let counterparty_stamps_signatures = map_to_stats(&cp_map, cp_map.values().sum::<usize>());

    Ok(StampsSignatureAnalysis {
        total_stamps,
        signature_distribution,
        pure_stamps_signatures,
        counterparty_stamps_signatures,
    })
}

/// Convert a count map into sorted stats with percentages
fn map_to_stats(map: &HashMap<String, usize>, total: usize) -> Vec<SignatureVariantStats> {
    let mut stats: Vec<SignatureVariantStats> = map
        .iter()
        .map(|(variant, &count)| SignatureVariantStats {
            variant: variant.clone(),
            count,
            percentage: if total > 0 {
                (count as f64 / total as f64) * 100.0
            } else {
                0.0
            },
        })
        .collect();

    // Sort by count descending
    stats.sort_by(|a, b| b.count.cmp(&a.count));
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_to_stats_empty() {
        let map = HashMap::new();
        let stats = map_to_stats(&map, 0);
        assert!(stats.is_empty());
    }

    #[test]
    fn test_map_to_stats_percentages() {
        let mut map = HashMap::new();
        map.insert("stamp:".to_string(), 75);
        map.insert("STAMP:".to_string(), 25);

        let stats = map_to_stats(&map, 100);
        assert_eq!(stats.len(), 2);

        // Should be sorted by count descending
        assert_eq!(stats[0].variant, "stamp:");
        assert_eq!(stats[0].count, 75);
        assert_eq!(stats[0].percentage, 75.0);

        assert_eq!(stats[1].variant, "STAMP:");
        assert_eq!(stats[1].count, 25);
        assert_eq!(stats[1].percentage, 25.0);
    }

    #[test]
    fn test_map_to_stats_sorting() {
        let mut map = HashMap::new();
        map.insert("stamps:".to_string(), 5);
        map.insert("stamp:".to_string(), 100);
        map.insert("STAMP:".to_string(), 50);
        map.insert("STAMPS:".to_string(), 1);

        let stats = map_to_stats(&map, 156);

        // Verify sorting by count descending
        assert_eq!(stats.len(), 4);
        assert_eq!(stats[0].variant, "stamp:");
        assert_eq!(stats[0].count, 100);
        assert_eq!(stats[1].variant, "STAMP:");
        assert_eq!(stats[1].count, 50);
        assert_eq!(stats[2].variant, "stamps:");
        assert_eq!(stats[2].count, 5);
        assert_eq!(stats[3].variant, "STAMPS:");
        assert_eq!(stats[3].count, 1);
    }

    #[test]
    fn test_map_to_stats_percentage_precision() {
        let mut map = HashMap::new();
        map.insert("stamp:".to_string(), 1);
        map.insert("STAMP:".to_string(), 2);

        let stats = map_to_stats(&map, 3);

        // 1/3 = 33.333...%, 2/3 = 66.666...%
        assert_eq!(stats.len(), 2);
        assert!((stats[0].percentage - 66.666).abs() < 0.01);
        assert!((stats[1].percentage - 33.333).abs() < 0.01);
    }

    #[test]
    fn test_pure_stamps_transport_constant() {
        // Verify the constant matches what's used in the SQL query
        assert_eq!(PURE_STAMPS_TRANSPORT, "Pure Bitcoin Stamps");
    }
}
