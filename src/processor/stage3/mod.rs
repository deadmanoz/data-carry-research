use crate::database::traits::Stage3Operations;
use crate::database::Database;
use crate::errors::{AppError, AppResult};
use crate::processor::{ConfigValidator, ProgressReporter, StandardProgressTracker};
use crate::types::statistics::StatisticsCollector;
use crate::types::{
    ClassificationResult, EnrichedTransaction, ProtocolType, Stage3Config, Stage3Results,
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info};

// Split protocol-specific classifiers into submodules for clarity
pub mod ascii_identifier_protocols;
pub mod chancecoin;
pub mod counterparty;
pub mod datastorage;
pub mod filters;
pub mod likely_data_storage;
pub mod likely_legitimate;
pub mod omni;
pub mod opreturn_signalled;
pub mod ppk; // PPk protocol classifier
pub mod spendability;
pub mod stamps;
pub mod wikileaks_cablegate;

// Re-export spendability analyser and filter helper for use in classifiers
// Note: MultisigPatternMatcher, PubkeyExtractor, SignatureDetector now in crate::shared
pub use filters::filter_p2ms_for_classification;
pub use spendability::SpendabilityAnalyser;

/// Stage 3 processor for protocol classification
pub struct Stage3Processor {
    database: Database,
    config: Stage3Config,
    classifier: ProtocolClassificationEngine,
    progress_tracker: StandardProgressTracker,
}

impl Stage3Processor {
    /// Create a new Stage 3 processor
    pub fn new(database_path: &str, config: Stage3Config) -> AppResult<Self> {
        // Validate configuration using shared validator
        config.validate().map_err(AppError::Config)?;
        ConfigValidator::validate_batch_config(config.batch_size, config.get_progress_interval())?;

        // Initialise database for Stage 3 operations
        let database = Database::new(database_path)?;

        // Initialise classification engine
        let classifier = ProtocolClassificationEngine::new();

        // Initialise shared components
        let progress_tracker = StandardProgressTracker::new();

        // Use shared configuration logging
        ConfigValidator::log_config_summary(
            "Stage 3 Processor",
            config.batch_size,
            config.get_progress_interval(),
            Some(&format!(
                "Database: {}, Protocol classification engine initialised",
                database_path
            )),
        );

        Ok(Self {
            database,
            config,
            classifier,
            progress_tracker,
        })
    }

    /// Run the complete Stage 3 processing pipeline
    pub async fn run(&mut self) -> AppResult<Stage3Results> {
        let mut results = Stage3Results::new();
        let mut processed_count = 0usize;

        // Determine total work for progress estimation
        let total_to_process = self
            .database
            .count_unclassified_transactions_for_stage3()
            .unwrap_or(0);

        // Get already-classified count for resume progress tracking
        let already_classified = self
            .database
            .count_classified_transactions_for_stage3()
            .unwrap_or(0);

        // Load existing classification breakdown to include in progress
        if already_classified > 0 {
            // Store baseline for accurate rate calculations
            results.baseline_transactions = already_classified;

            let breakdown = self
                .database
                .get_classification_breakdown()
                .unwrap_or_default();
            results.stamps_classified = *breakdown.get(&ProtocolType::BitcoinStamps).unwrap_or(&0);
            results.counterparty_classified =
                *breakdown.get(&ProtocolType::Counterparty).unwrap_or(&0);
            results.ascii_identifier_protocols_classified = *breakdown
                .get(&ProtocolType::AsciiIdentifierProtocols)
                .unwrap_or(&0);
            results.omni_classified = *breakdown.get(&ProtocolType::OmniLayer).unwrap_or(&0);
            results.chancecoin_classified = *breakdown.get(&ProtocolType::Chancecoin).unwrap_or(&0);
            results.ppk_classified = *breakdown.get(&ProtocolType::PPk).unwrap_or(&0);
            results.opreturn_signalled_classified = *breakdown
                .get(&ProtocolType::OpReturnSignalled)
                .unwrap_or(&0);
            results.datastorage_classified =
                *breakdown.get(&ProtocolType::DataStorage).unwrap_or(&0);
            results.likely_data_storage_classified = *breakdown
                .get(&ProtocolType::LikelyDataStorage)
                .unwrap_or(&0);
            results.legitimate_classified = *breakdown
                .get(&ProtocolType::LikelyLegitimateMultisig)
                .unwrap_or(&0);
            results.unknown_classified = *breakdown.get(&ProtocolType::Unknown).unwrap_or(&0);

            // Seed transactions_processed with historical baseline to keep classification_rate coherent
            results.transactions_processed = already_classified;
        }

        let total_transactions = already_classified + total_to_process;

        // Initialise progress tracker (replaces manual Instant tracking)
        self.progress_tracker.start();

        info!("=== Starting Stage 3: Protocol Classification ===");
        info!("Batch size: {}", self.config.batch_size);
        if already_classified > 0 {
            info!(
                "Resuming: {} already classified, {} pending",
                already_classified, total_to_process
            );
        } else if total_to_process > 0 {
            info!("Transactions pending classification: {}", total_to_process);
        } else {
            info!("Transactions pending classification: 0 (database already fully classified)");
        }

        loop {
            // Get batch of unclassified transactions
            let transactions = self
                .database
                .get_unclassified_transactions_for_stage3(self.config.batch_size)?;

            if transactions.is_empty() {
                info!("No more transactions to classify");
                break;
            }

            debug!("Processing batch of {} transactions", transactions.len());

            match self
                .process_classification_batch(&transactions, &mut results)
                .await
            {
                Ok(()) => {
                    processed_count += transactions.len();
                    results.transactions_processed += transactions.len() as u64;

                    // Timer-driven progress updates (~500ms) to keep output clean
                    if self.progress_tracker.should_report() {
                        let elapsed = self.progress_tracker.elapsed_seconds();
                        ProgressReporter::report_progress_with_metrics(
                            &results,
                            (already_classified + processed_count as u64) as usize,
                            Some(total_transactions as usize),
                            elapsed,
                        )?;
                    }
                }
                Err(e) => {
                    error!("Failed to process classification batch: {}", e);
                    results.errors_encountered += 1;

                    // For Stage 3, classification failures are logged but processing continues
                    info!("Continuing with next batch after error");
                }
            }
        }

        results.finish();
        // Print a newline to end in-place progress (stdout progress line)
        ProgressReporter::finish_progress_line();
        self.print_final_summary(&mut results, processed_count as u64, already_classified)
            .await?;

        Ok(results)
    }

    /// Process a batch of transactions for classification
    ///
    /// # Architecture
    ///
    /// This method implements the correct FK ordering:
    /// 1. Call classifier.classify_transaction() to get (tx_classification, output_classifications)
    /// 2. Insert transaction classification (satisfies FK parent requirement)
    /// 3. Insert output classifications in batch (FK child rows)
    ///
    /// This ensures p2ms_output_classifications.txid -> transaction_classifications.txid
    /// FK constraint is satisfied.
    async fn process_classification_batch(
        &mut self,
        transactions: &[EnrichedTransaction],
        results: &mut Stage3Results,
    ) -> AppResult<()> {
        for tx in transactions {
            match self.classifier.classify_transaction(tx, &self.database) {
                Ok((classification, output_classifications)) => {
                    // Update statistics based on classification
                    match classification.protocol {
                        ProtocolType::BitcoinStamps => results.stamps_classified += 1,
                        ProtocolType::Counterparty => results.counterparty_classified += 1,
                        ProtocolType::AsciiIdentifierProtocols => {
                            results.ascii_identifier_protocols_classified += 1
                        }
                        ProtocolType::OmniLayer => results.omni_classified += 1,
                        ProtocolType::Chancecoin => results.chancecoin_classified += 1,
                        ProtocolType::PPk => results.ppk_classified += 1,
                        ProtocolType::OpReturnSignalled => {
                            results.opreturn_signalled_classified += 1
                        }
                        ProtocolType::DataStorage => results.datastorage_classified += 1,
                        ProtocolType::LikelyDataStorage => {
                            results.likely_data_storage_classified += 1
                        }
                        ProtocolType::LikelyLegitimateMultisig => {
                            results.legitimate_classified += 1
                        }
                        ProtocolType::Unknown => results.unknown_classified += 1,
                    }

                    // FK Ordering:
                    // STEP 1: Insert transaction classification (FK parent)
                    self.database
                        .insert_classification_results_batch(std::slice::from_ref(
                            &classification,
                        ))?;

                    // STEP 2: Insert output classifications (FK child)
                    if !output_classifications.is_empty() {
                        self.database.insert_output_classifications_batch(
                            &tx.txid,
                            &output_classifications,
                        )?;
                    }
                }
                Err(e) => {
                    error!("Failed to classify transaction {}: {}", tx.txid, e);
                    results.errors_encountered += 1;

                    // Create a fallback Unknown classification (no output classifications)
                    let fallback_classification = create_fallback_classification(&tx.txid);
                    results.unknown_classified += 1;

                    // Insert transaction classification only (no outputs for error fallback)
                    self.database
                        .insert_classification_results_batch(&[fallback_classification])?;
                }
            }
        }

        Ok(())
    }

    /// Print final processing summary
    async fn print_final_summary(
        &self,
        results: &mut Stage3Results,
        newly_processed: u64,
        baseline: u64,
    ) -> AppResult<()> {
        // Rate is now correctly calculated in processing_rate() using baseline
        let rate = results.processing_rate();
        let (
            stamps_pct,
            cp_pct,
            cpv_pct,
            omni_pct,
            chancecoin_pct,
            ppk_pct,
            opreturn_signalled_pct,
            datastorage_pct,
            likely_data_storage_pct,
            legitimate_pct,
            unknown_pct,
        ) = results.classification_breakdown();

        info!("=== Stage 3 Complete ===");
        if baseline > 0 {
            info!(
                "Transactions classified this run: {} (baseline: {}, total: {})",
                newly_processed, baseline, results.transactions_processed
            );
        } else {
            info!(
                "Total transactions classified: {}",
                results.transactions_processed
            );
        }
        info!("Processing rate: {:.0} tx/sec", rate);
        info!(
            "Processing time: {}",
            ProgressReporter::format_elapsed_time(results.timing.processing_duration.as_secs_f64())
        );
        info!("");
        info!("Classification Breakdown (cumulative totals):");
        info!(
            "  Bitcoin Stamps:      {} ({:.1}%)",
            results.stamps_classified, stamps_pct
        );
        info!(
            "  Counterparty:        {} ({:.1}%)",
            results.counterparty_classified, cp_pct
        );
        info!(
            "  ASCII ID Protocols:  {} ({:.1}%)",
            results.ascii_identifier_protocols_classified, cpv_pct
        );
        info!(
            "  Omni Layer:          {} ({:.1}%)",
            results.omni_classified, omni_pct
        );
        info!(
            "  Chancecoin:          {} ({:.1}%)",
            results.chancecoin_classified, chancecoin_pct
        );
        info!(
            "  PPk:                 {} ({:.1}%)",
            results.ppk_classified, ppk_pct
        );
        info!(
            "  OP_RETURN Signalled: {} ({:.1}%)",
            results.opreturn_signalled_classified, opreturn_signalled_pct
        );
        info!(
            "  DataStorage:         {} ({:.1}%)",
            results.datastorage_classified, datastorage_pct
        );
        info!(
            "  LikelyDataStorage:   {} ({:.1}%)",
            results.likely_data_storage_classified, likely_data_storage_pct
        );
        info!(
            "  Likely Legit:        {} ({:.1}%)",
            results.legitimate_classified, legitimate_pct
        );
        info!(
            "  Unknown:             {} ({:.1}%)",
            results.unknown_classified, unknown_pct
        );

        if results.errors_encountered > 0 {
            info!("Errors encountered: {}", results.errors_encountered);
        }

        // Log additional classification statistics
        let total_classified: i64 = self
            .database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let signatures_found: i64 = self
            .database
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM transaction_classifications WHERE protocol_signature_found = 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let signature_rate = if total_classified > 0 {
            (signatures_found as f64 / total_classified as f64) * 100.0
        } else {
            0.0
        };

        info!("");
        info!("Database Classification Statistics:");
        info!("  Total classified: {}", total_classified);
        info!(
            "  Definitive signatures: {} ({:.1}%)",
            signatures_found, signature_rate
        );

        Ok(())
    }
}

/// Protocol classification engine that orchestrates different classifiers
pub struct ProtocolClassificationEngine {
    cache: HashMap<String, ClassificationResult>,
    classifiers: ProtocolClassifiers,
}

impl Default for ProtocolClassificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolClassificationEngine {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            classifiers: ProtocolClassifiers::new(),
        }
    }

    /// Classify a transaction using the modular classifier approach
    ///
    /// Returns both transaction classification and output classifications.
    /// The output classifications should be inserted AFTER the transaction classification
    /// to satisfy FK constraints.
    pub fn classify_transaction(
        &mut self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> AppResult<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Check cache first (note: cache only stores transaction classification, not outputs)
        // TODO: Consider caching output classifications as well if needed
        if let Some(cached_result) = self.cache.get(&tx.txid) {
            // For cached results, we don't have output classifications
            // This is acceptable since caching is within a single run and output classifications
            // are already in the database from the first classification
            return Ok((cached_result.clone(), Vec::new()));
        }

        // Try each classifier in order of PRIORITY (not efficiency):
        // 1. Omni (exclusive transport - Exodus address)
        // 2. Chancecoin (exclusive transport - signature check)
        // 3. Bitcoin Stamps (MUST be checked BEFORE Counterparty - can be embedded IN Counterparty)
        // 4. Counterparty (checked after Stamps to avoid misclassifying Stamps-over-Counterparty)
        // 5. AsciiIdentifierProtocols (TB0001, TEST01, Metronotes - checked after main Counterparty)
        // 6. PPk (infrastructure protocol with RT, Registration, Message variants)
        // 7. WikiLeaks Cablegate (specific historical artifact, checked before generic DataStorage)
        // 8. OpReturnSignalled (OP_RETURN-based protocols: Protocol47930, CLIPPERZ, GenericASCII)
        // 9. DataStorage (generic data embedding patterns in P2MS outputs)
        // 10. LikelyDataStorage (suspicious patterns - invalid EC points, high output count, dust amounts)
        // 11. LikelyLegitimateMultisig (pubkey validation - all valid EC points)
        // 12. Unknown (fallback)
        //
        // CRITICAL: Stamps BEFORE Counterparty because Stamps can use Counterparty as transport!
        // If we check Counterparty first, we'll miss the "stamp:" signature inside.
        //
        // CRITICAL: OpReturnSignalled BEFORE DataStorage to catch OP_RETURN protocol markers first.
        // OpReturnSignalled checks OP_RETURN outputs for specific protocol signatures (0xbb3a, CLIPPERZ).
        // DataStorage checks P2MS outputs for generic data patterns (burn patterns, text, file signatures).
        // Running OpReturnSignalled first prevents misclassifying OP_RETURN protocols as DataStorage.
        let (tx_result, output_results) = if let Some((tx_res, out_res)) =
            self.classifiers.omni.classify(tx, database)
        {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) = self.classifiers.chancecoin.classify(tx, database) {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) =
            self.classifiers.bitcoin_stamps.classify(tx, database)
        {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) = self.classifiers.counterparty.classify(tx, database)
        {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) = self
            .classifiers
            .ascii_identifier_protocols
            .classify(tx, database)
        {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) = ppk::PPkClassifier::classify(tx, database) {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) =
            self.classifiers.wikileaks_cablegate.classify(tx, database)
        {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) =
            self.classifiers.opreturn_signalled.classify(tx, database)
        {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) = self.classifiers.datastorage.classify(tx, database)
        {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) =
            self.classifiers.likely_data_storage.classify(tx, database)
        {
            (tx_res, out_res)
        } else if let Some((tx_res, out_res)) =
            self.classifiers.likely_legitimate.classify(tx, database)
        {
            (tx_res, out_res)
        } else {
            // Default to unknown classification - this always returns Some
            self.classifiers.unknown.classify(tx, database).unwrap()
        };

        // Cache the transaction result (output classifications not cached - they're in DB)
        self.cache.insert(tx.txid.clone(), tx_result.clone());

        Ok((tx_result, output_results))
    }
}

/// Container for protocol-specific classifiers
pub struct ProtocolClassifiers {
    pub bitcoin_stamps: stamps::BitcoinStampsClassifier,
    pub omni: omni::OmniClassifier,
    pub chancecoin: chancecoin::ChancecoinClassifier,
    pub counterparty: counterparty::CounterpartyClassifier,
    pub ascii_identifier_protocols: ascii_identifier_protocols::AsciiIdentifierProtocolsClassifier,
    pub ppk: ppk::PPkClassifier,
    pub wikileaks_cablegate: wikileaks_cablegate::WikiLeaksCablegateClassifier,
    pub datastorage: datastorage::DataStorageClassifier,
    pub opreturn_signalled: opreturn_signalled::OpReturnSignalledDetector,
    pub likely_data_storage: likely_data_storage::LikelyDataStorageClassifier,
    pub likely_legitimate: likely_legitimate::LikelyLegitimateClassifier,
    pub unknown: UnknownClassifier,
}

impl Default for ProtocolClassifiers {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolClassifiers {
    pub fn new() -> Self {
        Self {
            bitcoin_stamps: stamps::BitcoinStampsClassifier,
            omni: omni::OmniClassifier,
            chancecoin: chancecoin::ChancecoinClassifier,
            counterparty: counterparty::CounterpartyClassifier,
            ascii_identifier_protocols:
                ascii_identifier_protocols::AsciiIdentifierProtocolsClassifier,
            ppk: ppk::PPkClassifier,
            wikileaks_cablegate: wikileaks_cablegate::WikiLeaksCablegateClassifier::new(),
            datastorage: datastorage::DataStorageClassifier,
            opreturn_signalled: opreturn_signalled::OpReturnSignalledDetector,
            likely_data_storage: likely_data_storage::LikelyDataStorageClassifier::new(),
            likely_legitimate: likely_legitimate::LikelyLegitimateClassifier,
            unknown: UnknownClassifier,
        }
    }
}

/// Trait that each protocol classifier implements
///
/// # Architecture
///
/// Classifiers produce pure data structures without performing database operations.
/// The Stage3Processor handles all persistence in the correct order:
/// 1. Call classify() to get transaction + output classification data
/// 2. Insert transaction classification (satisfies FK parent)
/// 3. Batch insert output classifications (FK child rows)
///
/// This ensures FK constraints are satisfied and separates business logic from persistence.
pub trait ProtocolSpecificClassifier {
    /// Attempt to classify transaction for this protocol
    ///
    /// Returns Some((tx_classification, output_classifications)) if definitively matches
    /// this protocol, None otherwise. Output classifications list should include ALL
    /// P2MS outputs in the transaction that belong to this protocol.
    ///
    /// Database access provided for data extraction and analysis (read-only during classification).
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )>;
}

// ===== Protocol-Specific Classifiers (Placeholder Implementations) =====

/// Unknown pattern classifier (fallback)
pub struct UnknownClassifier;

impl ProtocolSpecificClassifier for UnknownClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        _database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        let additional_metadata = format!(
            "P2MS outputs: {}, Burn patterns: {}",
            tx.p2ms_outputs_count,
            tx.burn_patterns_detected.len()
        );

        // Build per-output classifications with PER-OUTPUT spendability analysis
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
        let mut output_classifications = Vec::new();

        for output in p2ms_outputs.iter() {
            // CRITICAL: Analyse spendability for THIS specific output
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let details = crate::types::OutputClassificationDetails::new(
                tx.burn_patterns_detected
                    .iter()
                    .map(|p| p.pattern_type.clone())
                    .collect(),
                true,
                false,
                "Fallback to Unknown protocol".to_string(),
                spendability_result,
            )
            .with_metadata(additional_metadata.clone());

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::Unknown,
                None,
                details,
            ));
        }

        // Return transaction-level classification (no spendability - that's per-output)
        let tx_classification = ClassificationResult {
            txid: tx.txid.clone(),
            protocol: ProtocolType::Unknown,
            variant: None,
            classification_details: crate::types::ClassificationDetails {
                burn_patterns_detected: tx
                    .burn_patterns_detected
                    .iter()
                    .map(|p| p.pattern_type.clone())
                    .collect(),
                height_check_passed: true,
                protocol_signature_found: false,
                classification_method: "Fallback to Unknown protocol".to_string(),
                additional_metadata: Some(additional_metadata),
                content_type: None,
            },
            classification_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        Some((tx_classification, output_classifications))
    }
}

/// Create a fallback classification when classification fails
fn create_fallback_classification(txid: &str) -> ClassificationResult {
    let details = crate::types::ClassificationDetails {
        burn_patterns_detected: Vec::new(),
        height_check_passed: false,
        protocol_signature_found: false,
        classification_method: "Classification failed - fallback to Unknown".to_string(),
        additional_metadata: Some("Error during classification process".to_string()),
        content_type: None,
    };

    ClassificationResult {
        txid: txid.to_string(),
        protocol: ProtocolType::Unknown,
        variant: None,
        classification_details: details,
        classification_timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_database() -> Database {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path().join("test.db");
        Database::new(temp_path.to_str().unwrap()).unwrap()
    }

    fn create_test_transaction(
        txid: &str,
        height: u32,
        with_burn_patterns: bool,
    ) -> EnrichedTransaction {
        let burn_patterns_detected = if with_burn_patterns {
            vec![crate::types::burn_patterns::BurnPattern {
                pattern_type: crate::types::burn_patterns::BurnPatternType::Stamps22Pattern,
                vout: 1,
                pubkey_index: 2,
                pattern_data: "0222222222...".to_string(),
                confidence: crate::types::burn_patterns::BurnConfidence::High,
            }]
        } else {
            Vec::new()
        };

        EnrichedTransaction {
            txid: txid.to_string(),
            height,
            total_input_value: 10000,
            total_output_value: 9000,
            transaction_fee: 1000,
            fee_per_byte: 10.0,
            transaction_size_bytes: 100,
            fee_per_kb: 10000.0,
            total_p2ms_amount: 1000,
            data_storage_fee_rate: 1.0,
            p2ms_outputs_count: 1,
            input_count: 1,
            output_count: 2,
            is_coinbase: false,
            burn_patterns_detected,
            outputs: Vec::new(),
        }
    }

    #[test]
    fn test_bitcoin_stamps_classifier() {
        let classifier = stamps::BitcoinStampsClassifier;
        let database = create_test_database();

        // Test transaction after Stamps launch with burn patterns
        let tx_with_stamps = create_test_transaction("stamps_tx", 800000, true);
        let result = classifier.classify(&tx_with_stamps, &database);

        assert!(result.is_some());
        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::BitcoinStamps);
        // In burn-pattern fallback (no ARC4 validation), signature flag is false
        assert!(
            !classification
                .classification_details
                .protocol_signature_found
        );

        // Test transaction with burn patterns (should classify)
        let tx_with_patterns = create_test_transaction("with_patterns_tx", 0, true);
        let result = classifier.classify(&tx_with_patterns, &database);
        assert!(result.is_some()); // Classifies based on burn patterns

        // Test transaction without burn patterns
        let tx_no_patterns = create_test_transaction("no_patterns_tx", 0, false);
        let result = classifier.classify(&tx_no_patterns, &database);
        assert!(result.is_none());
    }

    #[test]
    fn test_unknown_classifier() {
        let classifier = UnknownClassifier;
        let database = create_test_database();

        let tx = create_test_transaction("unknown_tx", 100000, false);
        let result = classifier.classify(&tx, &database);

        assert!(result.is_some());
        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::Unknown);
        assert!(
            !classification
                .classification_details
                .protocol_signature_found
        );
    }

    #[test]
    fn test_classification_engine() {
        let mut engine = ProtocolClassificationEngine::new();
        let database = create_test_database();

        // Test Stamps classification
        let stamps_tx = create_test_transaction("stamps_tx", 800000, true);
        let result = engine.classify_transaction(&stamps_tx, &database);
        assert!(result.is_ok());
        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::BitcoinStamps);

        // Test caching
        let cached_result = engine.classify_transaction(&stamps_tx, &database);
        assert!(cached_result.is_ok());
        let (cached_classification, _cached_outputs) = cached_result.unwrap();
        assert_eq!(cached_classification.protocol, ProtocolType::BitcoinStamps);
    }
}
