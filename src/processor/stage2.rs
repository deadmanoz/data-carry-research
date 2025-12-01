use crate::analysis::BurnPatternDetector;
use crate::analysis::FeeAnalyser;
use crate::config::BitcoinRpcConfig;
use crate::database::traits::{Stage1Operations, Stage2Operations, StatisticsOperations};
use crate::database::{Database, EnrichedTransactionStats};
use crate::errors::{AppError, AppResult, RpcError};
use crate::processor::{
    ConfigValidator, ProgressReporter, StandardBatchProcessor, StandardProgressTracker,
};
use crate::rpc::BitcoinRpcClient;
use crate::types::statistics::StatisticsCollector;
use crate::types::{EnrichedTransaction, Stage2Stats, TransactionInput, TransactionOutput};
use crate::utils::currency::{format_sats_as_btc, format_sats_as_btc_f64};
use std::collections::HashSet;
use tracing::{debug, error, info, warn};

/// Result type for transaction enrichment operations
type EnrichmentResult = AppResult<(
    EnrichedTransaction,
    Vec<TransactionInput>,
    Vec<TransactionOutput>,
)>;

/// Stage 2 processor for transaction enrichment and fee analysis
pub struct Stage2Processor {
    database: Database,
    rpc_client: BitcoinRpcClient,
    batch_size: usize,
    progress_interval: usize,
    progress_tracker: StandardProgressTracker,
    _batch_processor: StandardBatchProcessor,
    /// Session cache: tracks heights already updated with block hash/timestamp
    /// Prevents redundant RPC calls across batches within the same run
    updated_block_heights: HashSet<u32>,
}

impl Stage2Processor {
    /// Create a new Stage 2 processor
    pub async fn new(
        database_path: &str,
        rpc_config: BitcoinRpcConfig,
        batch_size: usize,
        progress_interval: usize,
    ) -> AppResult<Self> {
        // Validate configuration using shared validator
        ConfigValidator::validate_batch_config(batch_size, progress_interval)?;

        // Initialise database for Stage 2 operations
        let database = Database::new(database_path)?;

        // Initialise RPC client with connection test
        let rpc_client = BitcoinRpcClient::new(rpc_config)
            .await
            .map_err(|e| match e {
                RpcError::ConnectionFailed(msg) => {
                    AppError::Config(format!("Failed to initialise Bitcoin RPC client: {}", msg))
                }
                _ => AppError::Config(format!("RPC client initialisation error: {}", e)),
            })?;

        // Test RPC connection
        rpc_client.test_connection().await.map_err(|e| match e {
            RpcError::ConnectionFailed(msg) => {
                AppError::Config(format!("Bitcoin RPC connection test failed: {}", msg))
            }
            _ => AppError::Config(format!("RPC connection test error: {}", e)),
        })?;

        // Initialise shared components
        let progress_tracker = StandardProgressTracker::new();
        let batch_processor = StandardBatchProcessor::new(batch_size);

        // Use shared configuration logging
        ConfigValidator::log_config_summary(
            "Stage 2 Processor",
            batch_size,
            progress_interval,
            Some(&format!(
                "Database: {}, RPC connection verified",
                database_path
            )),
        );

        Ok(Self {
            database,
            rpc_client,
            batch_size,
            progress_interval,
            progress_tracker,
            _batch_processor: batch_processor,
            updated_block_heights: HashSet::new(),
        })
    }

    /// Run the complete Stage 2 processing pipeline
    pub async fn run(&mut self) -> AppResult<Stage2Stats> {
        let mut stats = Stage2Stats::new();
        let mut processed_count = 0usize;
        // Determine total work for progress estimation
        let total_to_process = self.database.count_unprocessed_transactions().unwrap_or(0);

        // Initialise progress tracker
        self.progress_tracker.start();

        info!("=== Starting Stage 2: Transaction Enrichment ===");
        info!(
            "Batch size: {}, Progress interval: {}",
            self.batch_size, self.progress_interval
        );

        loop {
            // Get batch of unprocessed transactions
            let txids = self
                .database
                .get_unprocessed_transactions(self.batch_size)?;

            if txids.is_empty() {
                info!("No more transactions to process");
                break;
            }

            debug!("Processing batch of {} transactions", txids.len());

            match self.process_transaction_batch(&txids, &mut stats).await {
                Ok(()) => {
                    processed_count += txids.len();
                    stats.transactions_processed += txids.len() as u64;

                    // Timer-driven progress updates (~500ms) to keep output clean
                    if self.progress_tracker.should_report() {
                        let elapsed = self.progress_tracker.elapsed_seconds();

                        // Update dynamic stats from RPC client
                        stats.rpc_errors_encountered = self.rpc_client.get_error_count();
                        stats.cache_hit_rate = self.rpc_client.get_cache_stats().hit_rate();

                        ProgressReporter::report_progress_with_metrics(
                            &stats,
                            processed_count,
                            Some(total_to_process as usize),
                            elapsed,
                        )?;
                    }
                }
                Err(e) => {
                    error!("Failed to process transaction batch: {}", e);
                    stats.rpc_errors_encountered += 1;

                    // For Stage 2, RPC failures are critical - abort processing
                    return Err(AppError::Config(format!(
                        "Critical RPC failure in Stage 2 (100% success required): {}",
                        e
                    )));
                }
            }
        }

        stats.finish();
        // Print a newline to end in-place progress (stdout progress line)
        ProgressReporter::finish_progress_line();

        // End-of-session warning for block timestamp failures
        if stats.block_update_failures > 0 {
            warn!(
                "{} block timestamp updates failed - re-run Stage 2 to retry",
                stats.block_update_failures
            );
        }

        self.print_final_summary(&mut stats).await?;

        Ok(stats)
    }

    /// Process a batch of transactions with enrichment
    async fn process_transaction_batch(
        &mut self,
        txids: &[String],
        stats: &mut Stage2Stats,
    ) -> AppResult<()> {
        // OPTIMISATION: Pre-fetch all required transactions in parallel
        debug!(
            "Pre-fetching transactions and inputs for batch of {} transactions",
            txids.len()
        );
        let main_tx_map = self.prefetch_batch_transactions(txids, stats).await?;

        // OPTIMISATION: Process transactions in parallel after prefetch
        debug!("Processing {} transactions in parallel", txids.len());
        let enriched_results = self
            .enrich_transactions_parallel(txids, &main_tx_map, stats)
            .await?;

        // Insert all enriched transactions into database in a single batch for performance
        self.database
            .insert_enriched_transactions_batch(&enriched_results)?;

        // --- Block timestamp update (Stage 2A) ---
        self.update_block_timestamps(&enriched_results, stats)
            .await?;

        // Update statistics (safe to do serially after parallel enrichment)
        for (enriched_tx, _, _) in &enriched_results {
            stats.total_fees_analysed += enriched_tx.transaction_fee;
            stats.total_p2ms_value += enriched_tx.total_p2ms_amount;
            stats.burn_patterns_found += enriched_tx.burn_patterns_detected.len() as u64;
        }

        Ok(())
    }

    /// Update block timestamps for heights in this batch (Stage 2A)
    ///
    /// Populates `blocks.block_hash` and `blocks.timestamp` for blocks referenced by
    /// transactions in this batch. Uses session-level cache to prevent redundant RPC calls.
    async fn update_block_timestamps(
        &mut self,
        enriched_results: &[(
            EnrichedTransaction,
            Vec<TransactionInput>,
            Vec<TransactionOutput>,
        )],
        stats: &mut Stage2Stats,
    ) -> AppResult<()> {
        // Step 1: Collect unique heights from this batch (filter by session cache)
        let batch_heights: Vec<u32> = enriched_results
            .iter()
            .map(|(tx, _, _)| tx.height)
            .filter(|h| !self.updated_block_heights.contains(h))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if batch_heights.is_empty() {
            return Ok(());
        }

        // Step 2: Query DB for heights needing block info (hash OR timestamp NULL)
        let heights_needing_update = self
            .database
            .get_heights_needing_block_info(&batch_heights)?;

        // Step 3: Fetch block info via RPC for heights that need updating
        let mut blocks_to_update: Vec<(u32, String, u64)> = Vec::new();
        for height in &heights_needing_update {
            // Track RPC calls for block timestamp fetching
            stats.rpc_calls_made += 1;
            match self.rpc_client.get_block_hash(*height as u64).await {
                Ok(block_hash) => {
                    stats.rpc_calls_made += 1;
                    match self.rpc_client.get_block(&block_hash).await {
                        Ok(block_info) => {
                            if let Some(time) = block_info["time"].as_u64() {
                                blocks_to_update.push((*height, block_hash, time));
                            } else {
                                // Block JSON missing time field - unexpected but handle gracefully
                                warn!(
                                    "Block {} (height {}) missing time field in response",
                                    block_hash, height
                                );
                                stats.block_update_failures += 1;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to fetch block {}: {}", block_hash, e);
                            stats.block_update_failures += 1;
                            stats.rpc_errors_encountered += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get block hash for height {}: {}", height, e);
                    stats.block_update_failures += 1;
                    stats.rpc_errors_encountered += 1;
                }
            }
        }

        // Step 4: Update DB (single transaction)
        if !blocks_to_update.is_empty() {
            let count = self.database.update_blocks_batch(&blocks_to_update)?;
            debug!("Updated {} blocks with hash/timestamp", count);

            // CRITICAL: Only cache heights that were SUCCESSFULLY updated
            // (not all batch_heights - failed RPC calls should be retried)
            for (height, _, _) in &blocks_to_update {
                self.updated_block_heights.insert(*height);
            }
        }

        // Also cache heights that already had timestamps (from DB query)
        // These don't need retry - they were already populated
        for height in &batch_heights {
            if !heights_needing_update.contains(height) {
                self.updated_block_heights.insert(*height);
            }
        }

        Ok(())
    }

    /// Process multiple transactions in parallel with controlled concurrency
    async fn enrich_transactions_parallel(
        &self,
        txids: &[String],
        main_tx_map: &std::collections::HashMap<String, corepc_client::bitcoin::Transaction>,
        stats: &mut Stage2Stats,
    ) -> AppResult<
        Vec<(
            EnrichedTransaction,
            Vec<TransactionInput>,
            Vec<TransactionOutput>,
        )>,
    > {
        use futures::stream::StreamExt;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        // Thread-safe statistics counters for parallel processing
        let rpc_calls_counter = Arc::new(AtomicU64::new(0));

        // Limit concurrent enrichment to the RPC client's configured limit
        let concurrent_limit = self.rpc_client.get_concurrent_limit();

        debug!(
            "Enriching {} transactions with concurrent limit: {}",
            txids.len(),
            concurrent_limit
        );

        let results: Vec<EnrichmentResult> = futures::stream::iter(txids.iter())
            .map(|txid| {
                let rpc_calls_counter = Arc::clone(&rpc_calls_counter);
                let txid_str = txid.clone();
                let tx_opt = main_tx_map.get(&txid_str).cloned();
                async move {
                    debug!("Enriching transaction: {}", txid);

                    // Create a temporary stats structure for this task
                    let mut task_stats = crate::types::Stage2Stats::new();

                    match self
                        .enrich_transaction_with_prefetched(&txid_str, tx_opt, &mut task_stats)
                        .await
                    {
                        Ok(result) => {
                            // Add this task's RPC calls to the shared counter
                            rpc_calls_counter
                                .fetch_add(task_stats.rpc_calls_made, Ordering::Relaxed);
                            debug!("Successfully enriched transaction: {}", txid);
                            Ok(result)
                        }
                        Err(e) => {
                            error!("Failed to enrich transaction {}: {}", txid, e);
                            Err(e)
                        }
                    }
                }
            })
            .buffer_unordered(concurrent_limit)
            .collect()
            .await;

        // Update global stats with accumulated RPC calls
        stats.rpc_calls_made += rpc_calls_counter.load(Ordering::Relaxed);

        // Collect successful results and handle errors
        let mut enriched_results = Vec::new();
        for result in results {
            match result {
                Ok(enriched_data) => enriched_results.push(enriched_data),
                Err(e) => {
                    error!("Critical error in parallel transaction enrichment: {}", e);
                    return Err(e);
                }
            }
        }

        debug!(
            "Successfully enriched {} transactions in parallel",
            enriched_results.len()
        );
        Ok(enriched_results)
    }

    /// Pre-fetch all transactions and their inputs in parallel to optimise RPC calls
    async fn prefetch_batch_transactions(
        &self,
        txids: &[String],
        stats: &mut Stage2Stats,
    ) -> AppResult<std::collections::HashMap<String, corepc_client::bitcoin::Transaction>> {
        use std::collections::{HashMap, HashSet};

        debug!("Collecting all required transaction IDs for batch prefetch");
        let mut all_required_txids = HashSet::new();

        // Step 1: Fetch all main transactions to determine input requirements
        let main_transactions = self.fetch_transactions_parallel(txids, stats).await?;
        let mut main_tx_map: HashMap<String, corepc_client::bitcoin::Transaction> = HashMap::new();
        for t in &main_transactions {
            // Use the actual transaction's txid to avoid ordering issues from buffer_unordered
            let txid_hex = t.compute_txid().to_string();
            main_tx_map.insert(txid_hex, t.clone());
        }

        // Step 2: Collect all input transaction IDs from non-coinbase transactions
        for transaction in &main_transactions {
            if !transaction.is_coinbase() {
                for input in &transaction.input {
                    let input_txid = input.previous_output.txid.to_string();
                    all_required_txids.insert(input_txid);
                }
            }
        }

        // Step 3: Fetch all input transactions in parallel (will use cache for any already fetched)
        if !all_required_txids.is_empty() {
            debug!(
                "Pre-fetching {} unique input transactions",
                all_required_txids.len()
            );
            let input_txids: Vec<String> = all_required_txids.into_iter().collect();
            self.fetch_transactions_parallel(&input_txids, stats)
                .await?;
        }

        debug!("Batch prefetch completed - all required transactions are now cached");
        Ok(main_tx_map)
    }

    /// Fetch multiple transactions in parallel with controlled concurrency
    async fn fetch_transactions_parallel(
        &self,
        txids: &[String],
        stats: &mut Stage2Stats,
    ) -> AppResult<Vec<corepc_client::bitcoin::Transaction>> {
        use futures::stream::StreamExt;

        // Limit parallel requests to the RPC client's configured limit
        let concurrent_limit = self.rpc_client.get_concurrent_limit();

        debug!(
            "Fetching {} transactions with concurrent limit: {}",
            txids.len(),
            concurrent_limit
        );

        // Count RPC calls upfront (we know we'll make one per txid)
        stats.rpc_calls_made += txids.len() as u64;

        let rpc_client = &self.rpc_client;
        let results: Vec<AppResult<corepc_client::bitcoin::Transaction>> =
            futures::stream::iter(txids.iter())
                .map(|txid| async move {
                    rpc_client.get_transaction(txid).await.map_err(|e| {
                        AppError::Config(format!("RPC call failed for transaction {}: {}", txid, e))
                    })
                })
                .buffer_unordered(concurrent_limit)
                .collect()
                .await;

        // Collect successful results and handle errors
        let mut transactions = Vec::new();
        for result in results {
            match result {
                Ok(transaction) => transactions.push(transaction),
                Err(e) => {
                    error!(
                        "Failed to fetch transaction during parallel prefetch: {}",
                        e
                    );
                    return Err(e);
                }
            }
        }

        debug!(
            "Successfully fetched {} transactions in parallel",
            transactions.len()
        );
        Ok(transactions)
    }

    /// Enrich a single transaction with complete fee analysis and burn pattern detection
    async fn enrich_transaction_with_prefetched(
        &self,
        txid: &str,
        prefetched_tx: Option<corepc_client::bitcoin::Transaction>,
        stats: &mut Stage2Stats,
    ) -> AppResult<(
        EnrichedTransaction,
        Vec<TransactionInput>,
        Vec<TransactionOutput>,
    )> {
        // Get P2MS outputs for this transaction from Stage 1 data
        let p2ms_outputs = self.database.get_p2ms_outputs_for_transaction(txid)?;

        if p2ms_outputs.is_empty() {
            return Err(AppError::Config(format!(
                "No P2MS outputs found for transaction {} - this shouldn't happen in Stage 2",
                txid
            )));
        }

        // Use prefetched transaction if available, otherwise fetch
        let transaction = if let Some(t) = prefetched_tx {
            t
        } else {
            stats.rpc_calls_made += 1;
            self.rpc_client.get_transaction(txid).await.map_err(|e| {
                AppError::Config(format!("RPC call failed for transaction {}: {}", txid, e))
            })?
        };

        // Build inputs, preferring cache; fall back to RPC for cache misses
        let inputs = self
            .get_inputs_preferring_cache(&transaction, stats)
            .await
            .map_err(|e| AppError::Config(format!("Failed to get transaction inputs: {}", e)))?;

        // Perform fee analysis
        let fee_analysis = FeeAnalyser::analyse_fees(&transaction, &inputs, &p2ms_outputs);

        // Detect burn patterns across all P2MS outputs
        let burn_patterns = BurnPatternDetector::detect_burn_patterns(&p2ms_outputs);

        // Parse ALL transaction outputs for unified storage
        let mut all_outputs = Vec::new();
        {
            use crate::types::script_metadata::{
                parse_nonstandard_script, parse_opreturn_script, parse_p2ms_script, ScriptType,
            };
            use corepc_client::bitcoin::{Address, Network};

            for (vout, out) in transaction.output.iter().enumerate() {
                let script_hex = hex::encode(out.script_pubkey.as_bytes());
                let script_size = out.script_pubkey.len();

                // Determine address (if applicable)
                let address = Address::from_script(&out.script_pubkey, Network::Bitcoin)
                    .ok()
                    .map(|addr| addr.to_string());

                // Determine script type and metadata
                let (script_type, metadata_json) = if out.script_pubkey.is_op_return() {
                    // Parse OP_RETURN
                    let metadata = if let Some(op_data) = parse_opreturn_script(&script_hex) {
                        serde_json::json!({
                            "op_return_hex": op_data.op_return_hex,
                            "protocol_prefix_hex": op_data.protocol_prefix_hex,
                            "data_hex": op_data.data_hex,
                            "data_length": op_data.data_length
                        })
                    } else {
                        serde_json::json!({})
                    };
                    (ScriptType::OpReturn, metadata)
                } else if out.script_pubkey.is_p2pkh() {
                    (ScriptType::P2PKH, serde_json::json!({}))
                } else if out.script_pubkey.is_p2sh() {
                    (ScriptType::P2SH, serde_json::json!({}))
                } else if out.script_pubkey.is_witness_program() {
                    // Determine witness version
                    if out.script_pubkey.is_p2wpkh() {
                        (ScriptType::P2WPKH, serde_json::json!({}))
                    } else if out.script_pubkey.is_p2wsh() {
                        (ScriptType::P2WSH, serde_json::json!({}))
                    } else if out.script_pubkey.is_p2tr() {
                        (ScriptType::P2TR, serde_json::json!({}))
                    } else {
                        (ScriptType::Unknown, serde_json::json!({}))
                    }
                } else if out.script_pubkey.is_p2pk() {
                    (ScriptType::P2PK, serde_json::json!({}))
                } else {
                    // Try multisig or nonstandard parsing
                    if let Ok((pubkeys, required_sigs, total_pubkeys)) =
                        parse_p2ms_script(&script_hex)
                    {
                        let metadata = serde_json::json!({
                            "required_sigs": required_sigs,
                            "total_pubkeys": total_pubkeys,
                            "pubkeys": pubkeys
                        });
                        (ScriptType::Multisig, metadata)
                    } else {
                        let nonstandard_data = parse_nonstandard_script(&script_hex);
                        (ScriptType::Nonstandard, serde_json::json!(nonstandard_data))
                    }
                };

                all_outputs.push(TransactionOutput {
                    txid: txid.to_string(),
                    vout: vout as u32,
                    height: p2ms_outputs[0].height,
                    amount: out.value.to_sat(),
                    script_hex,
                    script_type: script_type.as_str().to_string(),
                    is_coinbase: transaction.is_coinbase(),
                    script_size,
                    metadata: metadata_json,
                    address,
                });
            }
        }

        // Create enriched transaction
        let enriched_tx = EnrichedTransaction {
            txid: txid.to_string(),
            height: p2ms_outputs[0].height, // All outputs in same transaction have same height

            // Fee analysis data
            total_input_value: fee_analysis.total_input_value,
            total_output_value: fee_analysis.total_output_value,
            transaction_fee: fee_analysis.transaction_fee,
            fee_per_byte: fee_analysis.fee_per_byte,
            transaction_size_bytes: fee_analysis.transaction_size_bytes,
            fee_per_kb: fee_analysis.fee_per_kb,

            // P2MS specific analysis
            total_p2ms_amount: fee_analysis.total_p2ms_amount,
            data_storage_fee_rate: fee_analysis.data_storage_fee_rate,
            p2ms_outputs_count: fee_analysis.p2ms_outputs_count,

            // Burn pattern analysis
            burn_patterns_detected: burn_patterns,

            // Transaction metadata
            input_count: inputs.len(),
            output_count: transaction.output.len(),
            is_coinbase: transaction.is_coinbase(),

            // P2MS outputs from Stage 1 (Stage 2 only needs P2MS for enrichment)
            outputs: p2ms_outputs,
        };

        debug!(
            "Enriched transaction {}: fee={}, burn_patterns={}, p2ms_outputs={}, inputs={}",
            txid,
            format_sats_as_btc(enriched_tx.transaction_fee),
            enriched_tx.burn_patterns_detected.len(),
            enriched_tx.p2ms_outputs_count,
            inputs.len()
        );

        Ok((enriched_tx, inputs, all_outputs))
    }

    /// Build transaction inputs using cache where possible; fall back to RPC on cache miss
    async fn get_inputs_preferring_cache(
        &self,
        tx: &corepc_client::bitcoin::Transaction,
        stats: &mut Stage2Stats,
    ) -> crate::errors::RpcResult<Vec<crate::types::TransactionInput>> {
        let mut inputs = Vec::new();
        if tx.is_coinbase() {
            return Ok(inputs);
        }

        for input in &tx.input {
            let input_txid = input.previous_output.txid.to_string();

            // Fetch transaction (caching handled internally)
            stats.rpc_calls_made += 1;
            let prev_tx = self
                .rpc_client
                .get_transaction(&input_txid)
                .await
                .map_err(|e| crate::errors::RpcError::CallFailed {
                    method: "get_transaction".to_string(),
                    message: format!("Failed to get input transaction {}: {}", input_txid, e),
                })?;

            let output_index = input.previous_output.vout as usize;
            if output_index >= prev_tx.output.len() {
                return Err(crate::errors::RpcError::InvalidResponse(format!(
                    "Invalid output index {} for transaction {} (has {} outputs)",
                    output_index,
                    input_txid,
                    prev_tx.output.len()
                )));
            }

            let output = &prev_tx.output[output_index];

            // Extract source address from previous output
            use corepc_client::bitcoin::{Address, Network};
            let source_address =
                if let Ok(addr) = Address::from_script(&output.script_pubkey, Network::Bitcoin) {
                    Some(addr.to_string())
                } else {
                    None
                };

            inputs.push(crate::types::TransactionInput {
                txid: input_txid,
                vout: input.previous_output.vout,
                value: output.value.to_sat(),
                script_sig: hex::encode(input.script_sig.as_bytes()),
                sequence: input.sequence.0,
                source_address,
            });
        }

        Ok(inputs)
    }

    /// Print final processing summary
    async fn print_final_summary(&self, stats: &mut Stage2Stats) -> AppResult<()> {
        // Update final RPC error count before printing summary
        stats.rpc_errors_encountered = self.rpc_client.get_error_count();

        let db_stats = self.database.get_enriched_transaction_stats()?;

        println!("\n=== STAGE 2 COMPLETE ===");
        println!(
            "Transactions processed this run: {}",
            stats.transactions_processed
        );
        println!(
            "Processing time: {}",
            ProgressReporter::format_elapsed_time(stats.timing.processing_duration.as_secs_f64())
        );
        println!(
            "Processing rate: {:.2} transactions/sec",
            stats.processing_rate()
        );

        println!("\n=== RPC PERFORMANCE (This Run) ===");
        println!("RPC calls made: {}", stats.rpc_calls_made);
        println!("RPC success rate: {:.2}%", stats.rpc_success_rate());

        // Add cache performance statistics
        let final_cache_stats = self.rpc_client.get_cache_stats();
        println!("Cache hit rate: {:.2}%", final_cache_stats.hit_rate());
        println!("Cache hits: {}", final_cache_stats.hits);
        println!("Cache misses: {}", final_cache_stats.misses);
        println!(
            "Total cache requests: {}",
            final_cache_stats.total_requests()
        );

        println!("\n=== BURN PATTERN ANALYSIS (Cumulative Database Totals) ===");
        println!(
            "Transactions with burn patterns: {}",
            db_stats.transactions_with_burn_patterns
        );
        println!(
            "Total burn patterns detected: {}",
            db_stats.total_burn_patterns_detected
        );
        println!(
            "Burn pattern rate: {:.2}%",
            db_stats.burn_pattern_percentage()
        );
        println!(
            "Avg patterns per transaction: {:.2}",
            db_stats.average_patterns_per_transaction()
        );

        println!("\n=== FEE ANALYSIS (Cumulative Database Totals) ===");
        println!(
            "Total fees analysed: {}",
            format_sats_as_btc(db_stats.total_fees_analysed)
        );
        println!(
            "Average fee per transaction: {}",
            format_sats_as_btc_f64(db_stats.average_fee_per_transaction())
        );
        println!("Coinbase transactions: {}", db_stats.coinbase_transactions);
        println!("Regular transactions: {}", db_stats.regular_transactions);

        if stats.transactions_processed > 0 {
            println!("\n=== P2MS VALUE ANALYSIS (This Run) ===");
            println!(
                "Total P2MS value: {}",
                format_sats_as_btc(stats.total_p2ms_value)
            );
            println!(
                "Average P2MS value per tx: {}",
                format_sats_as_btc_f64(
                    stats.total_p2ms_value as f64 / stats.transactions_processed as f64
                )
            );
        }

        Ok(())
    }

    /// Get database statistics
    pub fn get_database_stats(&self) -> AppResult<EnrichedTransactionStats> {
        self.database.get_enriched_transaction_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BitcoinRpcConfig;

    fn create_test_rpc_config() -> BitcoinRpcConfig {
        BitcoinRpcConfig {
            url: "http://localhost:18332".to_string(), // testnet port
            username: "test".to_string(),
            password: "test".to_string(),
            timeout_seconds: 5,
            max_retries: 3,
            initial_backoff_ms: 10,
            backoff_multiplier: 1.5,
            max_backoff_seconds: 1,
            concurrent_requests: 2,
        }
    }

    #[tokio::test]
    async fn test_stage2_processor_creation() {
        let rpc_config = create_test_rpc_config();

        // This test will fail without a Bitcoin node running, but demonstrates correct usage
        match Stage2Processor::new(":memory:", rpc_config, 10, 100).await {
            Ok(_processor) => {
                println!("Stage 2 processor created successfully");
            }
            Err(e) => {
                println!(
                    "Stage 2 processor creation failed (expected without Bitcoin node): {}",
                    e
                );
                // This is expected in most test environments
            }
        }
    }

    #[test]
    fn test_stage2_stats() {
        let mut stats = Stage2Stats::new();

        stats.transactions_processed = 100;
        stats.rpc_calls_made = 200;
        stats.rpc_errors_encountered = 5;
        stats.burn_patterns_found = 25;
        stats.total_fees_analysed = 50000;

        assert_eq!(stats.rpc_success_rate(), 97.5); // (200-5)/200 * 100
        assert_eq!(stats.average_fee_per_transaction(), 500.0); // 50000/100

        // Test with no transactions
        let empty_stats = Stage2Stats::new();
        assert_eq!(empty_stats.rpc_success_rate(), 0.0);
        assert_eq!(empty_stats.processing_rate(), 0.0);
    }
}
