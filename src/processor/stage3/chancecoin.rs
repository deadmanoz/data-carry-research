//! Chancecoin protocol classifier for Stage 3 processing
//!
//! This classifier identifies Chancecoin gambling protocol transactions in P2MS outputs.
//! Unlike Counterparty and Bitcoin Stamps, Chancecoin uses NO obfuscation - data is stored
//! directly in the second pubkey slot of 1-of-2 or 1-of-3 multisig transactions.
//!
//! Detection criteria:
//! - Height >= 300,000 (conservative estimate)
//! - P2MS output with 8-byte "CHANCECO" signature
//! - Data in second pubkey slot (typically 16 bytes total: length + signature + data)

use crate::database::Database;
use crate::decoder::chancecoin::parse_chancecoin_message;
use crate::types::chancecoin::{ChancecoinMessage, ChancecoinMessageType, CHANCECOIN_SIGNATURE};
use crate::types::{
    ClassificationResult, EnrichedTransaction, ProtocolType, ProtocolVariant, TransactionOutput,
};
use tracing::debug;

use super::filter_p2ms_for_classification;
use super::spendability::SpendabilityAnalyser;
use super::ProtocolSpecificClassifier;
use crate::shared::PubkeyExtractor;

/// Chancecoin protocol classifier
pub struct ChancecoinClassifier;

impl ChancecoinClassifier {
    /// Extract Chancecoin data from P2MS outputs
    ///
    /// Chancecoin uses multiple P2MS outputs to store data:
    /// - Each output contains a 32-byte chunk in the second pubkey slot
    /// - Each chunk has: [length:1][data:0-32][padding:0-32] = 33 bytes total
    /// - Chunks are concatenated to form: [CHANCECO:8][MessageID:4][Data:variable]
    fn extract_chancecoin_data(&self, tx: &EnrichedTransaction) -> Option<ChancecoinMessage> {
        debug!("Checking for Chancecoin data in tx: {}", tx.txid);

        // Filter to P2MS outputs ONLY (collect owned values for helper functions)
        let p2ms_outputs: Vec<_> = filter_p2ms_for_classification(&tx.outputs)
            .into_iter()
            .cloned()
            .collect();

        // Extract and concatenate chunks from all P2MS outputs
        let concatenated_data = self.extract_and_concatenate_chunks(&p2ms_outputs)?;

        // Verify Chancecoin signature
        if concatenated_data.len() < 8 || &concatenated_data[..8] != CHANCECOIN_SIGNATURE {
            debug!("No Chancecoin signature found in concatenated data");
            return None;
        }

        debug!("✅ Chancecoin signature detected!");
        debug!("   • Total data length: {} bytes", concatenated_data.len());

        // Create Chancecoin message using parser from decoder module
        parse_chancecoin_message(tx.txid.clone(), concatenated_data)
    }

    /// Extract data chunks from all P2MS outputs and concatenate them
    ///
    /// Each P2MS output contains data in the second pubkey slot (index 1).
    /// The data format is:
    /// - Byte 0: Length of actual data (1-32)
    /// - Bytes 1-N: Actual data
    /// - Bytes N+1-32: Padding zeros (total 33 bytes)
    fn extract_and_concatenate_chunks(
        &self,
        p2ms_outputs: &[TransactionOutput],
    ) -> Option<Vec<u8>> {
        let mut all_chunks = Vec::new();

        debug!("Extracting chunks from {} P2MS outputs", p2ms_outputs.len());

        for (output_idx, output) in p2ms_outputs.iter().enumerate() {
            // Chancecoin uses 1-of-2 or 1-of-3 multisig
            // Data is in the second pubkey slot (index 1)
            let info = match output.multisig_info() {
                Some(i) => i,
                None => {
                    debug!("Output {} has no multisig info, skipping", output_idx);
                    continue;
                }
            };

            if info.pubkeys.len() < 2 {
                debug!("Output {} has < 2 pubkeys, skipping", output_idx);
                continue;
            }

            let data_hex = &info.pubkeys[1];

            // Extract chunk with length prefix (Chancecoin format)
            if let Some(chunk) = PubkeyExtractor::extract_with_length_prefix(data_hex) {
                debug!(
                    "Output {}: extracted {} bytes from Chancecoin chunk",
                    output_idx,
                    chunk.len()
                );
                all_chunks.push(chunk);
            }
        }

        if all_chunks.is_empty() {
            debug!("No valid chunks extracted");
            return None;
        }

        // Concatenate all chunks
        let concatenated: Vec<u8> = all_chunks.into_iter().flatten().collect();
        debug!("Total concatenated data: {} bytes", concatenated.len());

        Some(concatenated)
    }

    /// Map Chancecoin message type to protocol variant
    fn message_type_to_variant(message_type: &ChancecoinMessageType) -> ProtocolVariant {
        match message_type {
            ChancecoinMessageType::Send => ProtocolVariant::ChancecoinSend,
            ChancecoinMessageType::Order => ProtocolVariant::ChancecoinOrder,
            ChancecoinMessageType::BTCPay => ProtocolVariant::ChancecoinBTCPay,
            ChancecoinMessageType::Roll => ProtocolVariant::ChancecoinRoll,
            ChancecoinMessageType::DiceBet => ProtocolVariant::ChancecoinBet,
            ChancecoinMessageType::PokerBet => ProtocolVariant::ChancecoinBet,
            ChancecoinMessageType::Cancel => ProtocolVariant::ChancecoinCancel,
            ChancecoinMessageType::Unknown => ProtocolVariant::ChancecoinUnknown,
        }
    }
}

impl ProtocolSpecificClassifier for ChancecoinClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        _database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        debug!("Chancecoin classifier processing tx: {}", tx.txid);

        // Extract Chancecoin message
        let message = self.extract_chancecoin_data(tx)?;
        let variant = Self::message_type_to_variant(&message.message_type);

        debug!(
            "✅ Chancecoin detected: {} - {:?}",
            tx.txid, message.message_type
        );

        // Build detailed metadata
        // Get P2MS output count before classification loop
        let total_chunks = filter_p2ms_for_classification(&tx.outputs).len();

        let metadata = serde_json::json!({
            "message_id": message.message_id,
            "message_type": message.message_type.description(),
            "summary": message.summary(),
            "data_length": message.data.len(),
            "total_chunks": total_chunks,
        });

        // Insert per-output classifications with PER-OUTPUT spendability analysis
        // Filter to ONLY P2MS outputs before classifying
        let mut output_classifications = Vec::new();
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
        for output in p2ms_outputs {
            // CRITICAL: Analyse spendability for THIS specific output
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let details = crate::types::OutputClassificationDetails::new(
                Vec::new(), // burn_patterns
                true,       // height_check_passed
                true,       // protocol_signature_found
                format!("Chancecoin multi-output P2MS: {}", message.summary()),
                spendability_result, // Spendability analysis
            )
            .with_metadata(metadata.to_string())
            .with_content_type("application/octet-stream");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::Chancecoin,
                Some(variant.clone()),
                details,
            ));
        }

        // Return transaction-level classification (no spendability - that's per-output)
        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::Chancecoin,
            Some(variant),
            crate::types::ClassificationDetails {
                burn_patterns_detected: Vec::new(),
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: format!(
                    "Chancecoin multi-output P2MS: {}",
                    message.summary()
                ),
                additional_metadata: Some(metadata.to_string()),
                content_type: Some("application/octet-stream".to_string()),
            },
        );

        Some((tx_classification, output_classifications))
    }
}

// Note: Comprehensive Chancecoin tests are located in:
// tests/unit/stage3/protocols/chancecoin.rs
//
// The test suite includes:
// - Signature detection tests
// - Height threshold validation
// - Message type classification (Dice, Poker bets)
// - Full transaction classification with real blockchain data
