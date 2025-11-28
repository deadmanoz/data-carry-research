//! File extension and data size statistics for classified transactions.
//!
//! This analyser derives a human-readable breakdown of embedded file formats
//! from the MIME types stored during Stage 3 classification. It aggregates both
//! count- and size-based metrics so reports can highlight which payload formats
//! dominate the dataset.

use crate::database::Database;
use crate::errors::{AppError, AppResult};
use crate::types::analysis_results::{
    CategoryBreakdown, CategoryTotals, ExtensionStats, FileExtensionReport,
};
use crate::types::content_detection::ContentType;
use crate::utils::math::{safe_percentage, safe_percentage_u64};
use std::collections::BTreeMap;

/// Analyser responsible for computing file extension statistics.
pub struct FileExtensionAnalyser;

impl FileExtensionAnalyser {
    /// Aggregate file extension statistics from the database.
    pub fn analyse_file_types(db: &Database) -> AppResult<FileExtensionReport> {
        let conn = db.connection();

        let mut stmt = conn.prepare(
            "SELECT tc.content_type,
                    COUNT(DISTINCT tc.txid) AS transaction_count,
                    COUNT(*) AS output_count,
                    COALESCE(SUM(outputs.script_size), 0) AS total_bytes
             FROM transaction_classifications tc
             JOIN transaction_outputs AS outputs ON tc.txid = outputs.txid
             WHERE tc.content_type IS NOT NULL
             AND outputs.is_spent = 0
             GROUP BY tc.content_type",
        )?;

        let mut aggregates = Vec::new();
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let mime_type: String = row.get(0)?;
            let transaction_count: i64 = row.get(1)?;
            let output_count: i64 = row.get(2)?;
            let total_bytes: i64 = row.get(3)?;

            let transaction_count = usize::try_from(transaction_count).map_err(|_| {
                AppError::InvalidData("Negative transaction count encountered".to_string())
            })?;

            let output_count = usize::try_from(output_count).map_err(|_| {
                AppError::InvalidData("Negative output count encountered".to_string())
            })?;

            let total_bytes = if total_bytes < 0 {
                return Err(AppError::InvalidData(
                    "Negative byte count encountered".to_string(),
                ));
            } else {
                total_bytes as u64
            };

            let parsed = ContentType::from_mime_type(&mime_type);
            let category = parsed
                .as_ref()
                .map(|ct| ct.category().to_string())
                .unwrap_or_else(|| "Other".to_string());

            let extension = parsed
                .and_then(|ct| ct.file_extension().map(str::to_string))
                .unwrap_or_else(|| "Unknown".to_string());

            aggregates.push(ExtensionAggregate {
                category,
                extension,
                transaction_count,
                output_count,
                total_bytes,
            });
        }

        build_report(aggregates)
    }
}

fn build_report(raw: Vec<ExtensionAggregate>) -> AppResult<FileExtensionReport> {
    let total_transactions: usize = raw.iter().map(|entry| entry.transaction_count).sum();
    let total_outputs: usize = raw.iter().map(|entry| entry.output_count).sum();
    let total_bytes: u64 = raw.iter().map(|entry| entry.total_bytes).sum();

    if raw.is_empty() {
        return Ok(FileExtensionReport {
            total_transactions,
            total_outputs,
            total_bytes,
            categories: Vec::new(),
        });
    }

    let mut buckets: BTreeMap<String, Vec<ExtensionAggregate>> = BTreeMap::new();
    for entry in raw {
        let category_key = entry.category.clone();
        buckets.entry(category_key).or_default().push(entry);
    }

    let mut categories: Vec<CategoryBreakdown> = buckets
        .into_iter()
        .map(|(category, mut entries)| {
            entries.sort_by(|a, b| {
                b.total_bytes
                    .cmp(&a.total_bytes)
                    .then_with(|| a.extension.cmp(&b.extension))
            });

            let mut category_transaction_count: usize = 0;
            let mut category_output_count: usize = 0;
            let mut category_total_bytes: u64 = 0;

            let extensions: Vec<ExtensionStats> = entries
                .into_iter()
                .map(|entry| {
                    category_transaction_count += entry.transaction_count;
                    category_output_count += entry.output_count;
                    category_total_bytes += entry.total_bytes;

                    ExtensionStats {
                        extension: entry.extension,
                        transaction_count: entry.transaction_count,
                        output_count: entry.output_count,
                        total_bytes: entry.total_bytes,
                        transaction_percentage: safe_percentage(
                            entry.transaction_count,
                            total_transactions,
                        ),
                        output_percentage: safe_percentage(entry.output_count, total_outputs),
                        byte_percentage: safe_percentage_u64(entry.total_bytes, total_bytes),
                    }
                })
                .collect();

            CategoryBreakdown {
                category,
                extensions,
                category_totals: CategoryTotals {
                    transaction_count: category_transaction_count,
                    output_count: category_output_count,
                    total_bytes: category_total_bytes,
                    transaction_percentage: safe_percentage(
                        category_transaction_count,
                        total_transactions,
                    ),
                    output_percentage: safe_percentage(category_output_count, total_outputs),
                    byte_percentage: safe_percentage_u64(category_total_bytes, total_bytes),
                },
            }
        })
        .collect();

    categories.sort_by(|a, b| {
        b.category_totals
            .total_bytes
            .cmp(&a.category_totals.total_bytes)
            .then_with(|| a.category.cmp(&b.category))
    });

    Ok(FileExtensionReport {
        total_transactions,
        total_outputs,
        total_bytes,
        categories,
    })
}

#[derive(Debug, Clone)]
struct ExtensionAggregate {
    category: String,
    extension: String,
    transaction_count: usize,
    output_count: usize,
    total_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_db() -> Database {
        Database::new_v2(":memory:").expect("failed to create in-memory database")
    }

    #[test]
    fn report_is_empty_when_no_classifications() {
        let db = setup_db();
        let report = FileExtensionAnalyser::analyse_file_types(&db).unwrap();
        assert_eq!(report.total_transactions, 0);
        assert_eq!(report.total_outputs, 0);
        assert_eq!(report.total_bytes, 0);
        assert!(report.categories.is_empty());
    }

    #[test]
    fn aggregates_counts_and_bytes_by_extension() {
        let db = setup_db();
        let conn = db.connection();

        // Minimal enriched transaction rows to satisfy foreign key constraints
        for (txid, outputs_count) in [("tx1", 2), ("tx2", 1), ("tx3", 1)] {
            conn.execute(
                "INSERT INTO enriched_transactions (
                    txid, height, total_input_value, total_output_value, transaction_fee,
                    fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
                    data_storage_fee_rate, p2ms_outputs_count, input_count, output_count,
                    is_coinbase
                 ) VALUES (?1, 1, 0, 0, 0, 0.0, 1, 0.0, 0, 0.0, ?2, 1, ?2, 0)",
                rusqlite::params![txid, outputs_count],
            )
            .unwrap();
        }

        conn.execute(
            "INSERT INTO transaction_classifications (txid, protocol, variant, additional_metadata_json, protocol_signature_found, classification_method, content_type)
             VALUES ('tx1', 'BitcoinStamps', 'Classic', '{}', 1, 'Detector', 'image/png')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transaction_classifications (txid, protocol, variant, additional_metadata_json, protocol_signature_found, classification_method, content_type)
             VALUES ('tx2', 'BitcoinStamps', 'Classic', '{}', 1, 'Detector', 'application/pdf')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transaction_classifications (txid, protocol, variant, additional_metadata_json, protocol_signature_found, classification_method, content_type)
             VALUES ('tx3', 'DataStorage', NULL, '{}', 0, 'Detector', 'application/octet-stream')",
            [],
        )
        .unwrap();

        // Insert stub blocks to satisfy FK constraint (Schema V2 requirement)
        conn.execute("INSERT INTO blocks (height) VALUES (1)", [])
            .unwrap();
        conn.execute("INSERT INTO blocks (height) VALUES (2)", [])
            .unwrap();
        conn.execute("INSERT INTO blocks (height) VALUES (3)", [])
            .unwrap();

        // transaction_outputs rows (two outputs for tx1, one for tx2, one for tx3)
        // CRITICAL: Set is_spent = 0 for test data to simulate UTXO set
        conn.execute(
            "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, is_coinbase, script_size, is_spent)
             VALUES ('tx1', 0, 1, 1000, '00', 'multisig', 0, 120, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, is_coinbase, script_size, is_spent)
             VALUES ('tx1', 1, 1, 1000, '01', 'multisig', 0, 130, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, is_coinbase, script_size, is_spent)
             VALUES ('tx2', 0, 2, 1000, '00', 'multisig', 0, 256, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, is_coinbase, script_size, is_spent)
             VALUES ('tx3', 0, 3, 1000, '00', 'multisig', 0, 64, 0)",
            [],
        )
        .unwrap();

        let report = FileExtensionAnalyser::analyse_file_types(&db).unwrap();
        assert_eq!(report.total_transactions, 3);
        assert_eq!(report.total_outputs, 4);
        assert_eq!(report.total_bytes, 570);
        assert_eq!(report.categories.len(), 3);

        let images = report
            .categories
            .iter()
            .find(|category| category.category == "Images")
            .expect("images category missing");
        assert_eq!(images.category_totals.transaction_count, 1);
        assert_eq!(images.category_totals.output_count, 2);
        assert_eq!(images.category_totals.total_bytes, 250);
        assert_eq!(images.extensions[0].extension, ".png");
        assert!(images.extensions[0].byte_percentage > 40.0);

        let other = report
            .categories
            .iter()
            .find(|category| category.category == "Other")
            .expect("other category missing");
        assert_eq!(other.extensions[0].extension, "Unknown");
        assert_eq!(other.extensions[0].transaction_count, 1);
    }
}
