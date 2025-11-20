use crate::database::traits::Stage2Operations;
use crate::database::Database;
use crate::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, ProtocolType,
    ProtocolVariant, Stage3Config,
};

use super::filter_p2ms_for_classification;
use super::spendability::SpendabilityAnalyser;
use super::ProtocolSpecificClassifier;

/// WikiLeaks Cablegate classifier - detects the historic WikiLeaks Cablegate archive upload
///
/// Historical Context:
/// - April 2013: WikiLeaks Cablegate archive embedded in Bitcoin blockchain
/// - Banking blockade (2010-2013) made Bitcoin a censorship-resistant storage medium
/// - 132 transactions total: 1 downloader + 1 uploader + 130 data transactions
/// - Donation address: 1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v (1 satoshi per transaction)
/// - Message: "Free speech and free enterprise! Thank you Satoshi!"
///
/// Technical Pattern:
/// - Heights: 229,991-230,256
/// - Downloader tool: 6c53cd987119ef797d5adccd76241247988a0a5ef783572a9972e7371c5fb0cc (height 229,991)
/// - Uploader tool: 4b72a223007eab8a951d43edc171befeabc7b5dca4213770c88e09ba5b936e17
/// - Data transactions: 130 txs, each with 100+ P2MS outputs
/// - Each transaction: outputs 0-101 are data, output 102 is footer, output 103 is WikiLeaks donation, output 104 is change
/// - Total archive size: ~2.8 MB (corrupted during upload due to CRC32 bug)
///
/// Detection Criteria:
/// 1. WikiLeaks donation address in outputs (primary detection method)
/// 2. Massive P2MS output pattern (100+ outputs for data transactions)
///
///    Historical range: 229,991-230,256 (documented for reference only - not enforced)
pub struct WikiLeaksCablegateClassifier {
    _config: Stage3Config,
    /// WikiLeaks donation address
    wikileaks_address: String,
}

impl WikiLeaksCablegateClassifier {
    pub fn new(config: &Stage3Config) -> Self {
        Self {
            _config: config.clone(),
            wikileaks_address: "1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v".to_string(),
        }
    }

    /// Check if transaction is part of WikiLeaks Cablegate upload
    ///
    /// Uses the wikileaks_outputs table (populated during Stage 2) to detect
    /// transactions with outputs to the WikiLeaks donation address.
    ///
    /// Fallback: If the table lookup returns Ok(false) (table exists but empty,
    /// e.g., before Stage 2 runs), use pattern matching as a heuristic.
    fn is_cablegate_transaction(&self, tx: &EnrichedTransaction, db: &Database) -> bool {
        // Check for WikiLeaks donation address in transaction outputs (populated during Stage 2)
        match db.has_output_to_address(&tx.txid, &self.wikileaks_address) {
            Ok(true) => {
                // Positive match - definitely Cablegate
                true
            }
            Ok(false) | Err(_) => {
                // No address match OR lookup error
                // Fallback to pattern matching heuristic:
                // Most Cablegate transactions have 100+ P2MS outputs (data transactions)
                // Downloader (6 outputs) and uploader are exceptions (4-10 outputs)
                let is_data_tx = tx.p2ms_outputs_count >= 100;
                let is_tool_tx = tx.p2ms_outputs_count >= 4 && tx.p2ms_outputs_count <= 10;
                is_data_tx || is_tool_tx
            }
        }
    }
}

impl ProtocolSpecificClassifier for WikiLeaksCablegateClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        db: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        if !self.is_cablegate_transaction(tx, db) {
            return None;
        }

        // Determine transaction type
        let tx_type = if tx.height == 229_991 {
            "downloader_tool"
        } else if tx.height <= 229_993 {
            "uploader_tool"
        } else {
            "data_transaction"
        };

        let additional_metadata = format!(
            "WikiLeaks Cablegate {} | Donation address: {} | Height: {} | P2MS outputs: {} | Historical note: April 2013 upload, corrupted during blockchain storage",
            tx_type,
            self.wikileaks_address,
            tx.height,
            tx.p2ms_outputs_count
        );

        // Build per-output classifications with PER-OUTPUT spendability analysis
        // Filter to ONLY P2MS outputs before classifying
        let p2ms_outputs = filter_p2ms_for_classification(&tx.outputs);
        let mut output_classifications = Vec::new();

        for output in p2ms_outputs {
            // CRITICAL: Analyse spendability for THIS specific output
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let details = crate::types::OutputClassificationDetails::new(
                Vec::new(),
                true,
                true,
                "WikiLeaks donation address detection".to_string(),
                spendability_result,
            )
            .with_metadata(additional_metadata.clone())
            .with_content_type("application/octet-stream");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::DataStorage,
                Some(ProtocolVariant::DataStorageWikiLeaksCablegate),
                details,
            ));
        }

        // Return transaction-level classification (no spendability - that's per-output)
        let tx_classification = ClassificationResult {
            txid: tx.txid.clone(),
            protocol: ProtocolType::DataStorage,
            variant: Some(ProtocolVariant::DataStorageWikiLeaksCablegate),
            classification_details: ClassificationDetails {
                burn_patterns_detected: Vec::new(),
                height_check_passed: true,
                protocol_signature_found: true,
                classification_method: "WikiLeaks donation address detection".to_string(),
                additional_metadata: Some(additional_metadata),
                content_type: Some("application/octet-stream".to_string()),
            },
            classification_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        Some((tx_classification, output_classifications))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wikileaks_address() {
        let config = Stage3Config::default();
        let classifier = WikiLeaksCablegateClassifier::new(&config);

        // Verify WikiLeaks donation address
        assert_eq!(
            classifier.wikileaks_address,
            "1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v"
        );
    }
}
