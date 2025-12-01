//! Stage 2 database operations - Transaction enrichment.

use crate::database::helpers::ensure_blocks_exist;
use crate::database::traits::Stage2Operations;
use crate::database::Database;
use crate::errors::{AppError, AppResult};
use crate::types::{EnrichedTransaction, TransactionInput, TransactionOutput};
use rusqlite::params;
use std::collections::HashSet;
use tracing::debug;

impl Stage2Operations for Database {
    fn get_unprocessed_transactions(&self, limit: usize) -> AppResult<Vec<String>> {
        let mut stmt = self
            .connection()
            .prepare(
                r#"
            SELECT DISTINCT txid
            FROM transaction_outputs
            WHERE script_type = 'multisig'
              AND NOT EXISTS (
                  SELECT 1 FROM enriched_transactions e
                  WHERE e.txid = transaction_outputs.txid
              )
            ORDER BY height, txid
            LIMIT ?1
            "#,
            )
            .map_err(AppError::Database)?;

        let rows = stmt
            .query_map(params![limit], |row| row.get::<_, String>(0))
            .map_err(AppError::Database)?;

        let mut txids = Vec::new();
        for txid in rows {
            txids.push(txid.map_err(AppError::Database)?);
        }

        Ok(txids)
    }

    fn count_unprocessed_transactions(&self) -> AppResult<u64> {
        let count: u64 = self
            .connection()
            .query_row(
                r#"
            SELECT COUNT(DISTINCT txid)
            FROM transaction_outputs
            WHERE script_type = 'multisig'
              AND NOT EXISTS (
                  SELECT 1 FROM enriched_transactions e
                  WHERE e.txid = transaction_outputs.txid
              )
            "#,
                [],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;
        Ok(count)
    }

    fn insert_enriched_transactions_batch(
        &mut self,
        items: &[(
            EnrichedTransaction,
            Vec<TransactionInput>,
            Vec<TransactionOutput>,
        )],
    ) -> AppResult<()> {
        if items.is_empty() {
            return Ok(());
        }

        self.execute_transaction(|tx| {
            // PHASE 0: Ensure stub blocks exist for all heights (FK constraint satisfaction)
            // Collect unique heights from both transactions and outputs
            let mut unique_heights: HashSet<u32> = items.iter()
                .map(|(tx_data, _, _)| tx_data.height)
                .collect();

            // Also collect heights from outputs (may differ if outputs are from different blocks)
            for (_, _, outputs) in items {
                for output in outputs {
                    unique_heights.insert(output.height);
                }
            }

            let heights_vec: Vec<u32> = unique_heights.into_iter().collect();
            ensure_blocks_exist(tx, &heights_vec)?;

            // PHASE 1: Prepare statements
            let mut insert_tx_stmt = tx
                .prepare(
                    r#"
                INSERT INTO enriched_transactions
                (txid, height, total_input_value, total_output_value,
                 transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb,
                 total_p2ms_amount, data_storage_fee_rate, p2ms_outputs_count,
                 input_count, output_count, is_coinbase)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                "#,
                )
                .map_err(AppError::Database)?;

            let mut select_unspent_multisig_stmt = tx.prepare_cached(
                r#"
                SELECT vout
                FROM transaction_outputs
                WHERE txid = ?1
                  AND script_type = 'multisig'
                  AND is_spent = 0
                "#,
            ).map_err(AppError::Database)?;

            let mut upsert_output_stmt = tx.prepare(
                r#"
                INSERT INTO transaction_outputs
                (txid, vout, height, amount, script_hex, script_type, script_size, address, metadata_json, is_coinbase, is_spent)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                ON CONFLICT(txid, vout) DO UPDATE SET
                    height = excluded.height,
                    amount = excluded.amount,
                    script_hex = excluded.script_hex,
                    script_type = excluded.script_type,
                    script_size = excluded.script_size,
                    address = excluded.address,
                    metadata_json = excluded.metadata_json,
                    is_coinbase = excluded.is_coinbase
                    -- CRITICAL: DO NOT UPDATE is_spent - preserve Stage 1 value (0 = unspent/UTXO)
                "#
            ).map_err(AppError::Database)?;

            let mut insert_input_stmt = tx.prepare(
                r#"
                INSERT INTO transaction_inputs (txid, input_index, prev_txid, prev_vout, value, script_sig, sequence, source_address)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#
            ).map_err(AppError::Database)?;

            let mut insert_pattern_stmt = tx.prepare(
                r#"
                INSERT INTO burn_patterns (txid, pattern_type, vout, pubkey_index, pattern_data, confidence)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#
            ).map_err(AppError::Database)?;

            let mut upsert_p2ms_stmt = tx.prepare(
                r#"
                INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(txid, vout) DO UPDATE SET
                    required_sigs = excluded.required_sigs,
                    total_pubkeys = excluded.total_pubkeys,
                    pubkeys_json = excluded.pubkeys_json
                "#
            ).map_err(AppError::Database)?;

            // PHASE 2: Insert data in FK-safe order
            for (tx_data, inputs, outputs) in items {
                // Determine which multisig outputs were seeded by Stage 1 (UTXO set)
                let mut utxo_multisig_vouts: HashSet<u32> = HashSet::new();
                let utxo_rows = select_unspent_multisig_stmt
                    .query_map(params![&tx_data.txid], |row| row.get::<_, u32>(0))
                    .map_err(AppError::Database)?;
                for row in utxo_rows {
                    utxo_multisig_vouts.insert(row.map_err(AppError::Database)?);
                }

                // 2.1: Insert enriched_transactions (parent row)
                insert_tx_stmt
                    .execute(params![
                        tx_data.txid,
                        tx_data.height,
                        tx_data.total_input_value as i64,
                        tx_data.total_output_value as i64,
                        tx_data.transaction_fee as i64,
                        tx_data.fee_per_byte,
                        tx_data.transaction_size_bytes,
                        tx_data.fee_per_kb,
                        tx_data.total_p2ms_amount as i64,
                        tx_data.data_storage_fee_rate,
                        tx_data.p2ms_outputs_count,
                        tx_data.input_count,
                        tx_data.output_count,
                        tx_data.is_coinbase,
                    ])
                    .map_err(AppError::Database)?;

                // 2.2: UPSERT transaction_outputs (MUST come before inputs!)
                // FK: transaction_inputs.prev_txid/prev_vout → transaction_outputs.txid/vout
                for output in outputs {
                    let is_spent_flag = if output.script_type == "multisig" {
                        if utxo_multisig_vouts.contains(&output.vout) {
                            0
                        } else {
                            1
                        }
                    } else {
                        0
                    };

                    upsert_output_stmt
                        .execute(params![
                            output.txid,
                            output.vout,
                            output.height as i64,
                            output.amount as i64,
                            output.script_hex,
                            output.script_type,
                            output.script_size as i64,
                            output.address,
                            serde_json::to_string(&output.metadata).unwrap_or_else(|_| "{}".to_string()),
                            output.is_coinbase,
                            is_spent_flag,
                        ])
                        .map_err(AppError::Database)?;

                    // 2.2b: UPSERT p2ms_outputs for multisig outputs (Trigger Compliance)
                    //
                    // CRITICAL: Stage 3's enforce_p2ms_only_classification trigger requires ALL
                    // P2MS outputs to exist in p2ms_outputs table before classification.
                    //
                    // Stage 2 encounters BOTH unspent (from Stage 1) AND spent P2MS outputs (from
                    // fetching full transactions). Spent outputs aren't in UTXO dump, so Stage 1
                    // never seeded them into p2ms_outputs. We must insert them here to satisfy
                    // the trigger.
                    //
                    // PROJECT SCOPE CLARIFICATION:
                    // - This project analyses UNSPENT P2MS outputs only (is_spent = 0)
                    // - ALL statistics/analysis queries MUST filter by WHERE is_spent = 0
                    // - Spent outputs (is_spent = 1) are stored for data completeness but NOT
                    //   included in project analysis or statistics
                    //
                    // Why store spent outputs at all?
                    // - Stage 2 fetches full transactions (which include spent outputs)
                    // - Storing them prevents re-fetching and aids transaction context analysis
                    // - They are excluded from statistics via is_spent flag
                    if output.script_type == "multisig" {
                        if let Some(multisig_info) = output.multisig_info() {
                            let pubkeys_json = serde_json::to_string(&multisig_info.pubkeys)
                                .unwrap_or_else(|_| "[]".to_string());

                            upsert_p2ms_stmt
                                .execute(params![
                                    output.txid,
                                    output.vout,
                                    multisig_info.required_sigs,
                                    multisig_info.total_pubkeys,
                                    pubkeys_json
                                ])
                                .map_err(AppError::Database)?;
                        }
                    }
                }

                // 2.3: Insert transaction_inputs (FK to transaction_outputs satisfied)
                for (index, input) in inputs.iter().enumerate() {
                    insert_input_stmt
                        .execute(params![
                            &tx_data.txid,
                            index as i64,
                            input.txid,
                            input.vout,
                            input.value as i64,
                            input.script_sig,
                            input.sequence,
                            input.source_address
                        ])
                        .map_err(AppError::Database)?;
                }

                // 2.4: Insert burn_patterns (FK to enriched_transactions and p2ms_outputs)
                // NOTE: p2ms_outputs created by Stage 1, FK is satisfied
                for pattern in &tx_data.burn_patterns_detected {
                    insert_pattern_stmt
                        .execute(params![
                            &tx_data.txid,
                            format!("{:?}", pattern.pattern_type),
                            pattern.vout,
                            pattern.pubkey_index,
                            pattern.pattern_data,
                            format!("{:?}", pattern.confidence),
                        ])
                        .map_err(AppError::Database)?;
                }
            }

            Ok(())
        })
    }

    fn get_transaction_inputs(&self, txid: &str) -> AppResult<Vec<TransactionInput>> {
        let result = self
            .connection()
            .prepare(
                r#"
            SELECT ti.prev_txid, ti.prev_vout, ti.value, ti.script_sig, ti.sequence, ti.source_address
            FROM transaction_inputs ti
            WHERE ti.txid = ?1
            ORDER BY ti.input_index
            "#,
            )
            .and_then(|mut stmt| {
                let rows = stmt.query_map([txid], |row| {
                    Ok(TransactionInput {
                        txid: row.get(0)?,
                        vout: row.get(1)?,
                        value: row.get::<_, i64>(2)? as u64,
                        script_sig: row.get(3)?,
                        sequence: row.get(4)?,
                        source_address: row.get(5)?,
                    })
                })?;

                let mut inputs = Vec::new();
                for input in rows {
                    inputs.push(input?);
                }
                Ok(inputs)
            })
            .map_err(AppError::Database)?;

        Ok(result)
    }

    fn get_first_input_txid(&self, txid: &str) -> AppResult<Option<String>> {
        let result = self.connection().query_row(
            r#"
            SELECT ti.prev_txid
            FROM transaction_inputs ti
            WHERE ti.txid = ?1 AND ti.input_index = 0
            ORDER BY ti.input_index
            LIMIT 1
            "#,
            params![txid],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(prev_txid) => Ok(Some(prev_txid)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Database(e)),
        }
    }

    fn get_sender_address_from_largest_input(&self, txid: &str) -> AppResult<Option<String>> {
        // Implement actual "largest input by sum" logic per Omnicore spec.
        // For Class B transactions, the sender is the address that contributed the most input value.
        //
        // NOTE: This logic is duplicated in src/rpc/client.rs::get_sender_address_from_largest_input()
        // for Stage 4 RPC-based decoding. Both implementations follow the same algorithm.
        // Extraction into shared module was evaluated but skipped (different contexts).

        let inputs = self.get_transaction_inputs(txid)?;
        if inputs.is_empty() {
            debug!("No inputs found for tx {} while determining sender", txid);
            return Ok(None);
        }

        // Group inputs by address and sum their values (following Omnicore logic)
        use std::collections::HashMap;
        let mut address_sums: HashMap<String, u64> = HashMap::new();

        for input in inputs {
            // Use the source_address field that Stage 2 extracted from previous output
            let address = if let Some(addr) = input.source_address {
                addr
            } else {
                // If no source address available, we can't determine the sender
                debug!(
                    "Input missing source address for tx {}, input: {}:{}",
                    txid, input.txid, input.vout
                );
                continue;
            };

            *address_sums.entry(address).or_insert(0) += input.value;
        }

        // Find the address with the largest sum (per Omnicore specification)
        if let Some((largest_address, largest_value)) =
            address_sums.iter().max_by_key(|(_, &value)| value)
        {
            debug!(
                "Determined sender address {} (contributed {} satoshis) for tx {} via largest input analysis",
                largest_address, largest_value, txid
            );
            return Ok(Some(largest_address.clone()));
        }

        debug!(
            "Failed to determine sender address from inputs for tx {} - no valid address information found",
            txid
        );
        Ok(None)
    }

    fn has_output_to_address(&self, txid: &str, address: &str) -> AppResult<bool> {
        let exists: i32 = self
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM transaction_outputs WHERE txid = ?1 AND address = ?2)",
                params![txid, address],
                |row| row.get(0),
            )
            .map_err(AppError::Database)?;
        Ok(exists == 1)
    }

    fn update_blocks_batch(&mut self, blocks: &[(u32, String, u64)]) -> AppResult<usize> {
        if blocks.is_empty() {
            return Ok(0);
        }

        self.execute_transaction(|tx| {
            let mut stmt = tx
                .prepare_cached(
                    "UPDATE blocks SET block_hash = ?2, timestamp = ?3 WHERE height = ?1",
                )
                .map_err(AppError::Database)?;

            for (height, hash, timestamp) in blocks {
                stmt.execute(params![height, hash, timestamp])
                    .map_err(AppError::Database)?;
            }
            Ok(blocks.len())
        })
    }

    fn get_heights_needing_block_info(&self, heights: &[u32]) -> AppResult<Vec<u32>> {
        if heights.is_empty() {
            return Ok(Vec::new());
        }

        let placeholders: String = heights.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!(
            "SELECT height FROM blocks WHERE height IN ({}) AND (timestamp IS NULL OR block_hash IS NULL)",
            placeholders
        );

        let conn = self.connection();
        let mut stmt = conn.prepare(&query).map_err(AppError::Database)?;

        // Use params_from_iter for proper rusqlite parameter binding
        let rows = stmt
            .query_map(rusqlite::params_from_iter(heights.iter()), |row| {
                row.get::<_, u32>(0)
            })
            .map_err(AppError::Database)?;

        rows.map(|r| r.map_err(AppError::Database)).collect()
    }
}
