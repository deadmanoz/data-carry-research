//! Data size analysis functionality
//!
//! This module provides comprehensive data size (bytes) reporting for P2MS outputs,
//! analysing blockchain storage footprint across protocols, spendability, and content types.

use crate::types::analysis_results::{
    CategoryDataMetrics, CategorySpendabilityData, ComprehensiveDataSizeReport, ContentTypeData,
    ContentTypeSpendabilityReport, OverallDataSummary, ProtocolDataSize, ProtocolDataSizeReport,
    ProtocolSpendabilityData, ReasonSpendabilityData, SpendabilityDataMetrics,
    SpendabilityDataSizeReport,
};
use crate::database::stage3::operations::NO_MIME_TYPE_SENTINEL;
use crate::database::Database;
use crate::errors::AppResult;
use crate::types::content_detection::ContentType;
use std::collections::{HashMap, HashSet};

/// Data size analysis engine for byte-level analysis
pub struct DataSizeAnalyser;

impl DataSizeAnalyser {
    /// Analyse data sizes across protocols with spendability breakdown
    ///
    /// Provides protocol-level byte statistics including:
    /// - Total bytes per protocol (from script_size)
    /// - Transaction and output counts
    /// - Average/min/max bytes per output
    /// - Spendable vs unspendable byte distribution
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<ProtocolDataSizeReport>` - Protocol-level data size analysis
    pub fn analyse_protocol_data_sizes(db: &Database) -> AppResult<ProtocolDataSizeReport> {
        let conn = db.connection();

        // Query 1: Overall totals
        let (total_outputs, total_transactions, total_bytes) = conn.query_row(
            "SELECT COUNT(*) as total_outputs,
                    COUNT(DISTINCT c.txid) as total_transactions,
                    SUM(o.script_size) as total_bytes
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                ))
            },
        )?;

        // Query 2: Per-protocol statistics
        let mut stmt = conn.prepare(
            "SELECT tc.protocol, tc.variant,
                    COUNT(DISTINCT c.txid) as tx_count,
                    COUNT(*) as output_count,
                    SUM(o.script_size) as total_bytes,
                    AVG(o.script_size) as avg_bytes,
                    MIN(o.script_size) as min_bytes,
                    MAX(o.script_size) as max_bytes,
                    SUM(CASE WHEN c.is_spendable = 1 THEN o.script_size ELSE 0 END) as spendable_bytes,
                    SUM(CASE WHEN c.is_spendable = 0 THEN o.script_size ELSE 0 END) as unspendable_bytes
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             INNER JOIN transaction_classifications tc ON c.txid = tc.txid
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'
             GROUP BY tc.protocol, tc.variant
             ORDER BY total_bytes DESC",
        )?;

        let protocols = stmt
            .query_map([], |row| {
                let total_bytes = row.get::<_, Option<i64>>(4)?.unwrap_or(0) as u64;
                let spendable_bytes = row.get::<_, Option<i64>>(8)?.unwrap_or(0) as u64;
                let unspendable_bytes = row.get::<_, Option<i64>>(9)?.unwrap_or(0) as u64;

                Ok(ProtocolDataSize {
                    protocol: row.get(0)?,
                    variant: row.get(1)?,
                    output_count: row.get::<_, i64>(3)? as usize,
                    transaction_count: row.get::<_, i64>(2)? as usize,
                    total_bytes,
                    average_bytes: row.get::<_, Option<f64>>(5)?.unwrap_or(0.0),
                    min_bytes: row.get::<_, Option<i64>>(6)?.unwrap_or(0) as u64,
                    max_bytes: row.get::<_, Option<i64>>(7)?.unwrap_or(0) as u64,
                    percentage_of_total: 0.0, // Calculated later based on overall total
                    spendable_bytes,
                    unspendable_bytes,
                    spendable_percentage: if total_bytes > 0 {
                        (spendable_bytes as f64 / total_bytes as f64) * 100.0
                    } else {
                        0.0
                    },
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Calculate percentages based on overall total
        let protocols = protocols
            .into_iter()
            .map(|mut p| {
                p.percentage_of_total = if total_bytes > 0 {
                    (p.total_bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };
                p
            })
            .collect();

        Ok(ProtocolDataSizeReport {
            total_bytes,
            total_outputs,
            total_transactions,
            protocols,
        })
    }

    /// Analyse data sizes by spendability
    ///
    /// Provides spendability-focused byte statistics including:
    /// - Overall spendable vs unspendable bytes
    /// - Per-protocol spendability breakdown
    /// - Per-reason distribution (for unspendable outputs)
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<SpendabilityDataSizeReport>` - Spendability-level data size analysis
    pub fn analyse_spendability_data_sizes(db: &Database) -> AppResult<SpendabilityDataSizeReport> {
        let conn = db.connection();

        // Query 0: Get total unique transaction count (BEFORE grouped query to avoid double-counting)
        let total_transactions = conn.query_row(
            "SELECT COUNT(DISTINCT c.txid)
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'",
            [],
            |row| row.get::<_, i64>(0).map(|v| v as usize),
        )?;

        // Query 1: Overall spendability metrics (grouped by is_spendable)
        let mut overall_stmt = conn.prepare(
            "SELECT c.is_spendable,
                    COUNT(*) as output_count,
                    SUM(o.script_size) as total_bytes
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'
             GROUP BY c.is_spendable",
        )?;

        let mut spendable_bytes = 0u64;
        let mut unspendable_bytes = 0u64;
        let mut spendable_output_count = 0usize;
        let mut unspendable_output_count = 0usize;

        let overall_rows = overall_stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, bool>(0)?,
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        for (is_spendable, out_count, bytes) in overall_rows {
            if is_spendable {
                spendable_bytes = bytes;
                spendable_output_count = out_count;
            } else {
                unspendable_bytes = bytes;
                unspendable_output_count = out_count;
            }
        }

        let total_bytes = spendable_bytes + unspendable_bytes;

        let overall = SpendabilityDataMetrics {
            total_bytes,
            total_transactions,
            spendable_bytes,
            unspendable_bytes,
            spendable_percentage: if total_bytes > 0 {
                (spendable_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            },
            spendable_output_count,
            unspendable_output_count,
        };

        // Query 2: By protocol
        let mut protocol_stmt = conn.prepare(
            "SELECT tc.protocol,
                    c.is_spendable,
                    COUNT(*) as output_count,
                    SUM(o.script_size) as total_bytes
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             INNER JOIN transaction_classifications tc ON c.txid = tc.txid
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'
             GROUP BY tc.protocol, c.is_spendable",
        )?;

        let mut protocol_map: HashMap<String, (u64, u64, usize, usize)> = HashMap::new();

        for row_result in protocol_stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, i64>(2)? as usize,
                row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
            ))
        })? {
            let (protocol, is_spendable, out_count, bytes) = row_result?;
            let entry = protocol_map.entry(protocol).or_insert((0, 0, 0, 0));
            if is_spendable {
                entry.0 = bytes;
                entry.2 = out_count;
            } else {
                entry.1 = bytes;
                entry.3 = out_count;
            }
        }

        let by_protocol = protocol_map
            .into_iter()
            .map(
                |(protocol, (spendable, unspendable, spend_count, unspend_count))| {
                    ProtocolSpendabilityData {
                        protocol,
                        spendable_bytes: spendable,
                        unspendable_bytes: unspendable,
                        spendable_output_count: spend_count,
                        unspendable_output_count: unspend_count,
                    }
                },
            )
            .collect();

        // Query 3: By spendability reason
        let mut reason_stmt = conn.prepare(
            "SELECT c.spendability_reason,
                    COUNT(*) as output_count,
                    SUM(o.script_size) as total_bytes
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'
               AND c.is_spendable = 0
               AND c.spendability_reason IS NOT NULL
             GROUP BY c.spendability_reason
             ORDER BY total_bytes DESC",
        )?;

        let by_reason = reason_stmt
            .query_map([], |row| {
                let total_bytes = row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64;
                Ok(ReasonSpendabilityData {
                    reason: row.get(0)?,
                    output_count: row.get::<_, i64>(1)? as usize,
                    total_bytes,
                    percentage_of_total: if unspendable_bytes > 0 {
                        (total_bytes as f64 / unspendable_bytes as f64) * 100.0
                    } else {
                        0.0
                    },
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(SpendabilityDataSizeReport {
            overall,
            by_protocol,
            by_reason,
        })
    }

    /// Analyse data sizes by content type with spendability cross-analysis
    ///
    /// Provides content-type-focused byte statistics including:
    /// - Per-content-type byte totals
    /// - Spendable vs unspendable breakdown per content type
    /// - Category-level aggregation (Images, JSON, etc.)
    /// - Category-level transaction deduplication via HashSet
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<ContentTypeSpendabilityReport>` - Content type data size analysis
    pub fn analyse_content_type_spendability(
        db: &Database,
    ) -> AppResult<ContentTypeSpendabilityReport> {
        let conn = db.connection();

        // Query 1: Overall totals
        let (total_transactions, total_bytes) = conn.query_row(
            "SELECT COUNT(DISTINCT c.txid) as total_transactions,
                    SUM(o.script_size) as total_bytes
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             INNER JOIN transaction_classifications tc ON c.txid = tc.txid
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
                ))
            },
        )?;

        // Query 2: Per-content-type transaction counts (NO spendability split)
        let mut tx_count_stmt = conn.prepare(&format!(
            "SELECT COALESCE(tc.content_type, '{}') as content_type,
                    COUNT(DISTINCT c.txid) as transaction_count
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             INNER JOIN transaction_classifications tc ON c.txid = tc.txid
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'
             GROUP BY COALESCE(tc.content_type, '{}')",
            NO_MIME_TYPE_SENTINEL, NO_MIME_TYPE_SENTINEL
        ))?;

        let mut tx_counts_map: HashMap<String, usize> = HashMap::new();
        for row_result in tx_count_stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
        })? {
            let (content_type, count) = row_result?;
            tx_counts_map.insert(content_type, count);
        }

        // Query 3: Per-content-type spendability metrics (WITH spendability split)
        let mut spendability_stmt = conn.prepare(&format!(
            "SELECT COALESCE(tc.content_type, '{}') as content_type,
                    c.is_spendable,
                    COUNT(*) as output_count,
                    SUM(o.script_size) as total_bytes
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             INNER JOIN transaction_classifications tc ON c.txid = tc.txid
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'
             GROUP BY COALESCE(tc.content_type, '{}'), c.is_spendable
             ORDER BY total_bytes DESC",
            NO_MIME_TYPE_SENTINEL, NO_MIME_TYPE_SENTINEL
        ))?;

        // Query 4: Distinct (content_type, txid) pairs for category deduplication (STREAMING)
        let mut txid_pair_stmt = conn.prepare(&format!(
            "SELECT DISTINCT COALESCE(tc.content_type, '{}') as content_type,
                             c.txid
             FROM p2ms_output_classifications c
             INNER JOIN transaction_outputs o ON (c.txid = o.txid AND c.vout = o.vout)
             INNER JOIN transaction_classifications tc ON c.txid = tc.txid
             WHERE o.is_spent = 0 AND o.script_type = 'multisig'",
            NO_MIME_TYPE_SENTINEL
        ))?;

        // Step 1: Build category map with streaming txid pairs
        struct CategoryBuilder {
            category_name: String,
            content_types_data: HashMap<String, ContentTypeBuilder>,
            txid_set: HashSet<String>,
        }

        struct ContentTypeBuilder {
            mime_type: String,
            extension: String,
            transaction_count: usize,
            output_count: usize,
            total_bytes: u64,
            spendable_bytes: u64,
            unspendable_bytes: u64,
        }

        let mut category_map: HashMap<String, CategoryBuilder> = HashMap::new();

        // CRITICAL: Process rows streaming, don't collect into Vec
        let txid_pair_iter = txid_pair_stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        for pair_result in txid_pair_iter {
            let (content_type, txid) = pair_result?;

            let (category, extension) = if content_type.as_str() == NO_MIME_TYPE_SENTINEL {
                (
                    "Unclassified".to_string(),
                    NO_MIME_TYPE_SENTINEL.to_string(),
                )
            } else {
                let parsed = ContentType::from_mime_type(&content_type);
                let cat = parsed
                    .as_ref()
                    .map(|ct| ct.category())
                    .unwrap_or("Other")
                    .to_string();
                let ext = parsed
                    .and_then(|ct| ct.file_extension())
                    .unwrap_or("Unknown")
                    .to_string();
                (cat, ext)
            };

            let cat_builder =
                category_map
                    .entry(category.clone())
                    .or_insert_with(|| CategoryBuilder {
                        category_name: category.clone(),
                        content_types_data: HashMap::new(),
                        txid_set: HashSet::new(),
                    });

            // Add txid to category HashSet (streaming insertion)
            cat_builder.txid_set.insert(txid);

            // Initialise content type builder if needed
            cat_builder
                .content_types_data
                .entry(content_type.clone())
                .or_insert_with(|| ContentTypeBuilder {
                    mime_type: content_type.clone(),
                    extension: extension.clone(),
                    transaction_count: *tx_counts_map.get(&content_type).unwrap_or(&0),
                    output_count: 0,
                    total_bytes: 0,
                    spendable_bytes: 0,
                    unspendable_bytes: 0,
                });
        }

        // Step 2: Populate spendability metrics
        let spendability_rows = spendability_stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, i64>(2)? as usize,
                    row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        for (content_type, is_spendable, output_count, bytes) in spendability_rows {
            let (category, _) = if content_type.as_str() == NO_MIME_TYPE_SENTINEL {
                (
                    "Unclassified".to_string(),
                    NO_MIME_TYPE_SENTINEL.to_string(),
                )
            } else {
                let parsed = ContentType::from_mime_type(&content_type);
                let cat = parsed
                    .as_ref()
                    .map(|ct| ct.category())
                    .unwrap_or("Other")
                    .to_string();
                (cat, String::new())
            };

            if let Some(cat_builder) = category_map.get_mut(&category) {
                if let Some(ct_builder) = cat_builder.content_types_data.get_mut(&content_type) {
                    ct_builder.output_count += output_count;
                    ct_builder.total_bytes += bytes;
                    if is_spendable {
                        ct_builder.spendable_bytes += bytes;
                    } else {
                        ct_builder.unspendable_bytes += bytes;
                    }
                }
            }
        }

        // Step 3: Build final report structures
        let mut categories = Vec::new();
        for (_, cat_builder) in category_map {
            let mut content_types: Vec<ContentTypeData> = cat_builder
                .content_types_data
                .into_values()
                .map(|ct| ContentTypeData {
                    mime_type: ct.mime_type,
                    extension: ct.extension,
                    transaction_count: ct.transaction_count,
                    output_count: ct.output_count,
                    total_bytes: ct.total_bytes,
                    spendable_bytes: ct.spendable_bytes,
                    unspendable_bytes: ct.unspendable_bytes,
                    spendable_percentage: if ct.total_bytes > 0 {
                        (ct.spendable_bytes as f64 / ct.total_bytes as f64) * 100.0
                    } else {
                        0.0
                    },
                })
                .collect();
            content_types.sort_by_key(|ct| std::cmp::Reverse(ct.total_bytes));

            let category_totals = CategoryDataMetrics {
                transaction_count: cat_builder.txid_set.len(),
                output_count: content_types.iter().map(|ct| ct.output_count).sum(),
                total_bytes: content_types.iter().map(|ct| ct.total_bytes).sum(),
                spendable_bytes: content_types.iter().map(|ct| ct.spendable_bytes).sum(),
                unspendable_bytes: content_types.iter().map(|ct| ct.unspendable_bytes).sum(),
            };

            categories.push(CategorySpendabilityData {
                category: cat_builder.category_name,
                content_types,
                category_totals,
            });
        }

        categories.sort_by_key(|cat| std::cmp::Reverse(cat.category_totals.total_bytes));

        Ok(ContentTypeSpendabilityReport {
            total_bytes,
            total_transactions,
            categories,
        })
    }

    /// Analyse comprehensive data sizes across all dimensions
    ///
    /// Combines protocol, spendability, and content type analyses into
    /// a unified report with consistency checks.
    ///
    /// # Arguments
    /// * `db` - Database connection
    ///
    /// # Returns
    /// * `AppResult<ComprehensiveDataSizeReport>` - Complete data size analysis
    pub fn analyse_comprehensive_data_sizes(
        db: &Database,
    ) -> AppResult<ComprehensiveDataSizeReport> {
        let protocol_breakdown = Self::analyse_protocol_data_sizes(db)?;
        let spendability_breakdown = Self::analyse_spendability_data_sizes(db)?;
        let content_type_breakdown = Self::analyse_content_type_spendability(db)?;

        let overall_summary = OverallDataSummary {
            total_p2ms_bytes: protocol_breakdown.total_bytes,
            total_outputs: protocol_breakdown.total_outputs,
            total_transactions: protocol_breakdown.total_transactions,
            average_bytes_per_output: if protocol_breakdown.total_outputs > 0 {
                protocol_breakdown.total_bytes as f64 / protocol_breakdown.total_outputs as f64
            } else {
                0.0
            },
            spendable_percentage: spendability_breakdown.overall.spendable_percentage,
        };

        // Consistency checks
        assert_eq!(
            overall_summary.total_p2ms_bytes, spendability_breakdown.overall.total_bytes,
            "Protocol and spendability totals must match"
        );
        assert_eq!(
            overall_summary.total_p2ms_bytes, content_type_breakdown.total_bytes,
            "Protocol and content type totals must match (NULL included as Unclassified)"
        );

        Ok(ComprehensiveDataSizeReport {
            overall_summary,
            protocol_breakdown,
            spendability_breakdown,
            content_type_breakdown,
        })
    }
}
