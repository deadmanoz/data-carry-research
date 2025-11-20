//! Stage 3 database operations - Protocol classification.

use crate::database::connection::DatabaseConnection;
use crate::database::traits::Stage3Operations;
use crate::errors::{AppError, AppResult};
use crate::types::{ClassificationResult, EnrichedTransaction, TransactionOutput};
use rusqlite::params;
use tracing::debug;

/// Sentinel value used when content types are missing in the database.
pub const NO_MIME_TYPE_SENTINEL: &str = "__NO_MIME_TYPE__";

impl Stage3Operations for DatabaseConnection {
    fn get_unclassified_transactions_for_stage3(
        &self,
        limit: usize,
    ) -> AppResult<Vec<EnrichedTransaction>> {
        let mut stmt = self
            .connection()
            .prepare(
                r#"
            SELECT et.txid, et.height, et.total_input_value, et.total_output_value,
                   et.transaction_fee, et.fee_per_byte, et.transaction_size_bytes, et.fee_per_kb,
                   et.total_p2ms_amount, et.data_storage_fee_rate, et.p2ms_outputs_count,
                   et.input_count, et.output_count, et.is_coinbase
            FROM enriched_transactions et
            LEFT JOIN transaction_classifications pc ON et.txid = pc.txid
            WHERE pc.txid IS NULL
            ORDER BY et.height, et.txid
            LIMIT ?1
            "#,
            )
            .map_err(AppError::Database)?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(EnrichedTransaction {
                    txid: row.get(0)?,
                    height: row.get(1)?,
                    total_input_value: row.get::<_, i64>(2)? as u64,
                    total_output_value: row.get::<_, i64>(3)? as u64,
                    transaction_fee: row.get::<_, i64>(4)? as u64,
                    fee_per_byte: row.get(5)?,
                    transaction_size_bytes: row.get(6)?,
                    fee_per_kb: row.get(7)?,
                    total_p2ms_amount: row.get::<_, i64>(8)? as u64,
                    data_storage_fee_rate: row.get(9)?,
                    p2ms_outputs_count: row.get(10)?,
                    input_count: row.get(11)?,
                    output_count: row.get(12)?,
                    is_coinbase: row.get(13)?,

                    // These will be populated separately
                    burn_patterns_detected: Vec::new(),
                    outputs: Vec::new(),
                })
            })
            .map_err(AppError::Database)?;

        let mut transactions = Vec::new();
        for tx_result in rows {
            let mut tx = tx_result.map_err(AppError::Database)?;

            // Load burn patterns for this transaction
            tx.burn_patterns_detected = self.get_burn_patterns_for_transaction(&tx.txid)?;

            // Load ALL transaction outputs for protocol detection
            // (Exodus address, OP_RETURN markers, etc.)
            tx.outputs = self.get_all_outputs_for_transaction(&tx.txid)?;

            transactions.push(tx);
        }

        Ok(transactions)
    }

    fn count_unclassified_transactions_for_stage3(&self) -> AppResult<u64> {
        let count: u64 = self
            .connection()
            .query_row(
                r#"
            SELECT COUNT(*)
            FROM enriched_transactions et
            LEFT JOIN transaction_classifications pc ON et.txid = pc.txid
            WHERE pc.txid IS NULL
            "#,
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        Ok(count)
    }

    fn count_classified_transactions_for_stage3(&self) -> AppResult<u64> {
        let count: u64 = self
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications",
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;

        Ok(count)
    }

    fn get_classification_breakdown(
        &self,
    ) -> AppResult<std::collections::HashMap<crate::types::ProtocolType, u64>> {
        use std::collections::HashMap;

        let mut breakdown = HashMap::new();
        let mut stmt = self
            .connection()
            .prepare("SELECT protocol, COUNT(*) FROM transaction_classifications GROUP BY protocol")
            .map_err(AppError::Database)?;

        let rows = stmt
            .query_map([], |row| {
                let protocol_str: String = row.get(0)?;
                let count: u64 = row.get(1)?;
                Ok((protocol_str, count))
            })
            .map_err(AppError::Database)?;

        for row in rows {
            let (protocol_str, count) = row.map_err(AppError::Database)?;
            if let Ok(protocol) = protocol_str.parse::<crate::types::ProtocolType>() {
                breakdown.insert(protocol, count);
            }
        }

        Ok(breakdown)
    }

    fn insert_classification_results_batch(
        &mut self,
        results: &[ClassificationResult],
    ) -> AppResult<()> {
        if results.is_empty() {
            return Ok(());
        }

        self.execute_transaction(|tx| {
            let mut stmt = tx
                .prepare(
                    r#"
                INSERT INTO transaction_classifications (
                    txid, protocol, variant, additional_metadata_json,
                    protocol_signature_found,
                    classification_method, content_type, transport_protocol, classification_timestamp
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                )
                .map_err(AppError::Database)?;

            for result in results {
                let variant_str = result.variant.as_ref().map(|v| format!("{}", v));
                let metadata_json = serde_json::to_string(&result.classification_details)
                    .unwrap_or_else(|_| "{}".to_string());

                // Extract transport_protocol from additional_metadata JSON if present
                let transport_protocol = result
                    .classification_details
                    .additional_metadata
                    .as_ref()
                    .and_then(|meta_json| {
                        // Parse the JSON string
                        serde_json::from_str::<serde_json::Value>(meta_json)
                            .ok()
                            .and_then(|json| {
                                // Extract the transport_protocol field
                                json.get("transport_protocol")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                            })
                    });

                stmt.execute(params![
                    result.txid,
                    format!("{}", result.protocol),
                    variant_str,
                    metadata_json,
                    if result.classification_details.protocol_signature_found {
                        1
                    } else {
                        0
                    },
                    result.classification_details.classification_method,
                    result.classification_details.content_type,
                    transport_protocol,
                    result.classification_timestamp as i64
                ])
                .map_err(AppError::Database)?;
            }

            debug!("Inserted batch of {} classification results", results.len());
            Ok(())
        })
    }

    fn insert_output_classifications_batch(
        &mut self,
        txid: &str,
        outputs: &[crate::types::OutputClassificationData],
    ) -> AppResult<()> {
        if outputs.is_empty() {
            return Ok(());
        }

        self.execute_transaction(|tx| {
            let mut stmt = tx
                .prepare(
                    r#"
                    INSERT OR REPLACE INTO p2ms_output_classifications (
                        txid, vout, protocol, variant, additional_metadata_json,
                        protocol_signature_found, classification_method, content_type,
                        is_spendable, spendability_reason,
                        real_pubkey_count, burn_key_count, data_key_count,
                        classification_timestamp
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, strftime('%s', 'now'))
                    "#,
                )
                .map_err(AppError::Database)?;

            for output_data in outputs {
                let metadata_json =
                    serde_json::to_string(&output_data.details).unwrap_or_else(|_| "{}".to_string());
                let is_spendable = if output_data.details.is_spendable {
                    1
                } else {
                    0
                };

                stmt.execute(params![
                    txid,
                    output_data.vout as i64,
                    format!("{}", output_data.protocol),
                    output_data.variant.as_ref().map(|v| format!("{}", v)),
                    metadata_json,
                    if output_data.details.protocol_signature_found {
                        1
                    } else {
                        0
                    },
                    output_data.details.classification_method,
                    output_data.details.content_type,
                    is_spendable,
                    &output_data.details.spendability_reason,
                    output_data.details.real_pubkey_count as i64,
                    output_data.details.burn_key_count as i64,
                    output_data.details.data_key_count as i64,
                ])
                .map_err(AppError::Database)?;
            }

            debug!(
                "Inserted batch of {} output classifications for tx {}",
                outputs.len(),
                txid
            );
            Ok(())
        })
    }

    fn get_enriched_transaction(&self, txid: &str) -> AppResult<Option<EnrichedTransaction>> {
        let mut stmt = self
            .connection()
            .prepare(
                r#"
            SELECT et.txid, et.height, et.total_input_value, et.total_output_value,
                   et.transaction_fee, et.fee_per_byte, et.transaction_size_bytes, et.fee_per_kb,
                   et.total_p2ms_amount, et.data_storage_fee_rate, et.p2ms_outputs_count,
                   et.input_count, et.output_count, et.is_coinbase
            FROM enriched_transactions et
            WHERE et.txid = ?1
            "#,
            )
            .map_err(AppError::Database)?;

        let mut rows = stmt
            .query_map(params![txid], |row| {
                Ok(EnrichedTransaction {
                    txid: row.get(0)?,
                    height: row.get(1)?,
                    total_input_value: row.get::<_, i64>(2)? as u64,
                    total_output_value: row.get::<_, i64>(3)? as u64,
                    transaction_fee: row.get::<_, i64>(4)? as u64,
                    fee_per_byte: row.get(5)?,
                    transaction_size_bytes: row.get(6)?,
                    fee_per_kb: row.get(7)?,
                    total_p2ms_amount: row.get::<_, i64>(8)? as u64,
                    data_storage_fee_rate: row.get(9)?,
                    p2ms_outputs_count: row.get(10)?,
                    input_count: row.get(11)?,
                    output_count: row.get(12)?,
                    is_coinbase: row.get(13)?,

                    outputs: Vec::new(), // Will be filled with ALL outputs
                    burn_patterns_detected: Vec::new(), // Will be filled if needed
                })
            })
            .map_err(AppError::Database)?;

        match rows.next() {
            Some(Ok(mut tx)) => {
                // Fill in ALL transaction outputs for protocol detection
                tx.outputs = self.get_all_outputs_for_transaction(txid)?;
                // Fill in burn patterns (always load - single source of truth)
                tx.burn_patterns_detected = self.get_burn_patterns_for_transaction(txid)?;
                Ok(Some(tx))
            }
            Some(Err(e)) => Err(AppError::Database(e)),
            None => Ok(None),
        }
    }

    fn get_content_type_distribution(&self) -> AppResult<std::collections::HashMap<String, u64>> {
        let mut stmt = self.connection().prepare(
            r#"
            SELECT COALESCE(content_type, ?1) AS content_type, COUNT(*) as count
            FROM transaction_classifications
            GROUP BY COALESCE(content_type, ?1)
            ORDER BY count DESC
            "#,
        )?;

        let rows = stmt.query_map(params![NO_MIME_TYPE_SENTINEL], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;

        let mut distribution = std::collections::HashMap::new();
        for row_result in rows {
            let (mime_type, count) = row_result?;
            distribution.insert(mime_type, count);
        }

        Ok(distribution)
    }

    fn get_content_type_distribution_by_protocol(
        &self,
        protocol: crate::types::ProtocolType,
    ) -> AppResult<std::collections::HashMap<String, u64>> {
        let protocol_str = format!("{:?}", protocol);

        let mut stmt = self.connection().prepare(
            r#"
            SELECT COALESCE(content_type, ?2) AS content_type, COUNT(*) as count
            FROM transaction_classifications
            WHERE protocol = ?1
            GROUP BY COALESCE(content_type, ?2)
            ORDER BY count DESC
            "#,
        )?;

        let rows = stmt.query_map(params![protocol_str, NO_MIME_TYPE_SENTINEL], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;

        let mut distribution = std::collections::HashMap::new();
        for row_result in rows {
            let (mime_type, count) = row_result?;
            distribution.insert(mime_type, count);
        }

        Ok(distribution)
    }

    fn get_transactions_by_content_type(&self, mime_type: &str) -> AppResult<Vec<String>> {
        let mut stmt = self.connection().prepare(
            r#"
            SELECT txid
            FROM transaction_classifications
            WHERE content_type = ?1
            ORDER BY id
            "#,
        )?;

        let rows = stmt.query_map([mime_type], |row| row.get::<_, String>(0))?;

        let mut txids = Vec::new();
        for row_result in rows {
            txids.push(row_result?);
        }

        Ok(txids)
    }

    fn get_all_outputs_for_transaction(&self, txid: &str) -> AppResult<Vec<TransactionOutput>> {
        let mut stmt = self.connection().prepare(
            r#"
            SELECT txid, vout, height, amount, script_hex, script_type,
                   is_coinbase, script_size, metadata_json, address
            FROM transaction_outputs
            WHERE txid = ?1
            ORDER BY vout
            "#,
        )?;

        let rows = stmt.query_map([txid], |row| {
            Ok(TransactionOutput {
                txid: row.get(0)?,
                vout: row.get(1)?,
                height: row.get::<_, i64>(2)? as u32,
                amount: row.get::<_, i64>(3)? as u64,
                script_hex: row.get(4)?,
                script_type: row.get(5)?,
                is_coinbase: row.get(6)?,
                script_size: row.get::<_, i64>(7)? as usize,
                metadata: row
                    .get::<_, Option<String>>(8)?
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                address: row.get(9)?,
            })
        })?;

        let mut outputs = Vec::new();
        for row in rows {
            outputs.push(row.map_err(AppError::Database)?);
        }

        Ok(outputs)
    }

    fn get_outputs_by_type(
        &self,
        txid: &str,
        script_type: &str,
    ) -> AppResult<Vec<TransactionOutput>> {
        let mut stmt = self.connection().prepare(
            r#"
            SELECT txid, vout, height, amount, script_hex, script_type,
                   is_coinbase, script_size, metadata_json, address
            FROM transaction_outputs
            WHERE txid = ?1 AND script_type = ?2
            ORDER BY vout
            "#,
        )?;

        let rows = stmt.query_map(params![txid, script_type], |row| {
            Ok(TransactionOutput {
                txid: row.get(0)?,
                vout: row.get(1)?,
                height: row.get::<_, i64>(2)? as u32,
                amount: row.get::<_, i64>(3)? as u64,
                script_hex: row.get(4)?,
                script_type: row.get(5)?,
                is_coinbase: row.get(6)?,
                script_size: row.get::<_, i64>(7)? as usize,
                metadata: row
                    .get::<_, Option<String>>(8)?
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                address: row.get(9)?,
            })
        })?;

        let mut outputs = Vec::new();
        for row in rows {
            outputs.push(row.map_err(AppError::Database)?);
        }

        Ok(outputs)
    }
}

impl DatabaseConnection {
    /// Get burn patterns for a specific transaction (helper method)
    fn get_burn_patterns_for_transaction(
        &self,
        txid: &str,
    ) -> AppResult<Vec<crate::types::burn_patterns::BurnPattern>> {
        let mut stmt = self
            .connection()
            .prepare(
                r#"
            SELECT bp.pattern_type, bp.vout, bp.pubkey_index, bp.pattern_data, bp.confidence
            FROM burn_patterns bp
            WHERE bp.txid = ?1
            "#,
            )
            .map_err(AppError::Database)?;

        let rows = stmt
            .query_map(params![txid], |row| {
                let pattern_type_str: String = row.get(0)?;
                let confidence_str: String = row.get(4)?;

                Ok(crate::types::burn_patterns::BurnPattern {
                    pattern_type: match pattern_type_str.as_str() {
                        "Stamps22Pattern" => {
                            crate::types::burn_patterns::BurnPatternType::Stamps22Pattern
                        }
                        "Stamps33Pattern" => {
                            crate::types::burn_patterns::BurnPatternType::Stamps33Pattern
                        }
                        "Stamps0202Pattern" => {
                            crate::types::burn_patterns::BurnPatternType::Stamps0202Pattern
                        }
                        "Stamps0303Pattern" => {
                            crate::types::burn_patterns::BurnPatternType::Stamps0303Pattern
                        }
                        "ProofOfBurn" => crate::types::burn_patterns::BurnPatternType::ProofOfBurn,
                        _ => crate::types::burn_patterns::BurnPatternType::UnknownBurn,
                    },
                    vout: row.get(1)?,
                    pubkey_index: row.get(2)?,
                    pattern_data: row.get(3)?,
                    confidence: match confidence_str.as_str() {
                        "High" => crate::types::burn_patterns::BurnConfidence::High,
                        "Medium" => crate::types::burn_patterns::BurnConfidence::Medium,
                        _ => crate::types::burn_patterns::BurnConfidence::Low,
                    },
                })
            })
            .map_err(AppError::Database)?;

        let mut patterns = Vec::new();
        for pattern in rows {
            patterns.push(pattern.map_err(AppError::Database)?);
        }

        Ok(patterns)
    }
}
