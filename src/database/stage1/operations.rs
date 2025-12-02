//! Stage 1 database operations - P2MS detection and storage.
//!
//! Stage 1 performs a two-table atomic insert:
//! 1. **Stub blocks**: Inserts height-only rows into `blocks` (NULL hash/timestamp)
//! 2. **transaction_outputs**: All P2MS outputs with `is_spent = 0`
//! 3. **p2ms_outputs**: Extracted P2MS metadata (required_sigs, total_pubkeys, pubkeys_json)

use crate::database::helpers::ensure_blocks_exist;
use crate::database::traits::{Stage1Checkpoint, Stage1Operations};
use crate::database::Database;
use crate::errors::AppResult;
use crate::types::TransactionOutput;
use rusqlite::params;
use std::collections::HashSet;
use tracing::debug;

impl Stage1Operations for Database {
    fn insert_p2ms_batch(&mut self, batch: &[TransactionOutput]) -> AppResult<()> {
        // Redirect to the new generic method - table names will be migrated separately
        self.insert_transaction_output_batch(batch)
    }

    /// Insert a batch of TransactionOutput records (two-table atomic insert).
    ///
    /// ## Behaviour
    ///
    /// 1. **Stub blocks**: Ensures blocks table has height-only rows (satisfies FK)
    /// 2. **transaction_outputs**: Inserts ALL outputs with `is_spent = 0` (0 = unspent/UTXO)
    /// 3. **p2ms_outputs**: For P2MS only, extracts metadata to dedicated columns
    ///
    /// All operations are atomic within a single transaction.
    fn insert_transaction_output_batch(&mut self, batch: &[TransactionOutput]) -> AppResult<()> {
        self.execute_transaction(|tx| {
            // 1. Extract unique heights and ensure stub blocks exist
            let unique_heights: HashSet<u32> = batch.iter().map(|o| o.height).collect();
            let heights_vec: Vec<u32> = unique_heights.into_iter().collect();
            ensure_blocks_exist(tx, &heights_vec)?;

            // 2. Insert into transaction_outputs
            // Uses is_spent = 0 (0 = unspent/UTXO)
            let mut outputs_stmt = tx.prepare_cached(
                r#"INSERT OR IGNORE INTO transaction_outputs
                   (txid, vout, height, amount, script_hex, script_type, script_size,
                    is_coinbase, is_spent, address)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, NULL)"#,
            )?;

            for output in batch {
                outputs_stmt.execute(params![
                    output.txid,
                    output.vout,
                    output.height,
                    output.amount,
                    output.script_hex,
                    output.script_type,
                    output.script_size,
                    output.is_coinbase
                ])?;
            }

            // 3. Insert P2MS metadata into p2ms_outputs (for multisig only)
            let mut p2ms_stmt = tx.prepare_cached(
                r#"INSERT OR IGNORE INTO p2ms_outputs
                   (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
                   VALUES (?1, ?2, ?3, ?4, ?5)"#,
            )?;

            let mut p2ms_count = 0;
            for output in batch.iter().filter(|o| o.script_type == "multisig") {
                // Extract P2MS metadata from JSON using TransactionOutput::multisig_info()
                if let Some(multisig_info) = output.multisig_info() {
                    // serde_json::Error automatically converts to AppError::InvalidData via From trait
                    let pubkeys_json = serde_json::to_string(&multisig_info.pubkeys)?;

                    p2ms_stmt.execute(params![
                        output.txid,
                        output.vout,
                        multisig_info.required_sigs,
                        multisig_info.total_pubkeys,
                        pubkeys_json
                    ])?;

                    p2ms_count += 1;
                } else {
                    // This should not happen for properly parsed P2MS outputs
                    tracing::warn!(
                        "P2MS output {txid}:{vout} has no multisig metadata",
                        txid = output.txid,
                        vout = output.vout
                    );
                }
            }

            debug!(
                "Inserted batch of {} outputs ({} P2MS with metadata)",
                batch.len(),
                p2ms_count
            );
            Ok(())
        })
    }

    /// Get P2MS outputs for a transaction (with JOIN to p2ms_outputs).
    ///
    /// Joins `transaction_outputs` and `p2ms_outputs` to reconstruct TransactionOutput
    /// with metadata containing MultisigInfo (required_sigs, total_pubkeys, pubkeys).
    fn get_p2ms_outputs_for_transaction(&self, txid: &str) -> AppResult<Vec<TransactionOutput>> {
        let mut stmt = self.connection().prepare(
            r#"
            SELECT
                o.txid, o.vout, o.amount, o.height, o.script_hex, o.script_type,
                o.is_coinbase, o.script_size, o.address,
                p.required_sigs, p.total_pubkeys, p.pubkeys_json
            FROM transaction_outputs o
            INNER JOIN p2ms_outputs p ON o.txid = p.txid AND o.vout = p.vout
            WHERE o.txid = ?1 AND o.script_type = 'multisig' AND o.is_spent = 0
            ORDER BY o.vout
            "#,
        )?;

        let rows = stmt.query_map(params![txid], |row| {
            // Reconstruct MultisigInfo from p2ms_outputs columns
            let pubkeys_json: String = row.get(11)?;
            let pubkeys: Vec<String> = serde_json::from_str(&pubkeys_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;

            let multisig_info = crate::types::script_metadata::MultisigInfo {
                pubkeys,
                required_sigs: row.get::<_, u32>(9)?,
                total_pubkeys: row.get::<_, u32>(10)?,
            };

            // Serialize MultisigInfo back to JSON for TransactionOutput.metadata
            let metadata = serde_json::to_value(multisig_info).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;

            Ok(TransactionOutput {
                txid: row.get(0)?,
                vout: row.get(1)?,
                amount: row.get::<_, i64>(2)? as u64,
                height: row.get(3)?,
                script_hex: row.get(4)?,
                script_type: row.get(5)?,
                is_coinbase: row.get(6)?,
                script_size: row.get::<_, i64>(7)? as usize,
                metadata,
                address: row.get(8)?, // May be NULL in Stage 1, populated in Stage 2
            })
        })?;

        let mut outputs = Vec::new();
        for output in rows {
            outputs.push(output?);
        }

        Ok(outputs)
    }

    fn save_checkpoint_enhanced(
        &mut self,
        last_count: u64,
        total_processed: usize,
        csv_line_number: u64,
        batch_number: usize,
    ) -> AppResult<()> {
        self.connection().execute(
            r#"INSERT OR REPLACE INTO processing_checkpoints
               (id, stage, last_processed_count, total_processed, csv_line_number, batch_number, updated_at)
               VALUES (1, 'stage1', ?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)"#,
            params![last_count, total_processed, csv_line_number, batch_number],
        )?;

        debug!(
            "Enhanced checkpoint saved: count={}, total={}, line={}, batch={}",
            last_count, total_processed, csv_line_number, batch_number
        );
        Ok(())
    }

    fn get_checkpoint_enhanced(&self) -> AppResult<Option<Stage1Checkpoint>> {
        let mut stmt = self.connection().prepare(
            r#"SELECT last_processed_count, total_processed, csv_line_number, batch_number, created_at
               FROM processing_checkpoints
               WHERE stage = 'stage1'"#,
        )?;

        let mut rows = stmt.query_map([], |row| {
            // created_at is INTEGER (unix timestamp), convert to String
            let created_at: String = match row.get::<_, i64>(4) {
                Ok(timestamp) => timestamp.to_string(),
                Err(_) => row.get::<_, String>(4)?, // Fallback for legacy format
            };

            Ok(Stage1Checkpoint {
                last_processed_count: row.get::<_, u64>(0)?,
                total_processed: row.get::<_, usize>(1)?,
                csv_line_number: row.get::<_, u64>(2)?,
                batch_number: row.get::<_, usize>(3)?,
                created_at,
            })
        })?;

        match rows.next() {
            Some(result) => Ok(Some(result?)),
            None => Ok(None),
        }
    }

    fn clear_checkpoint(&mut self) -> AppResult<()> {
        self.connection().execute(
            "DELETE FROM processing_checkpoints WHERE stage = 'stage1'",
            [],
        )?;

        debug!("Stage 1 checkpoint cleared");
        Ok(())
    }
}
