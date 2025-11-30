use crate::database::traits::Stage2Operations;
use crate::database::Database;
use crate::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, ProtocolType,
    ProtocolVariant, Stage3Config,
};

use super::filter_p2ms_for_classification;
use super::spendability::SpendabilityAnalyser;
use super::ProtocolSpecificClassifier;

/// WikiLeaks Cablegate Tool TXIDs (hardcoded - these don't have the donation address)
const CABLEGATE_DOWNLOADER_TXID: &str =
    "6c53cd987119ef797d5adccd76241247988a0a5ef783572a9972e7371c5fb0cc";
const CABLEGATE_UPLOADER_TXID: &str =
    "4b72a223007eab8a951d43edc171befeabc7b5dca4213770c88e09ba5b936e17";

/// WikiLeaks Cablegate height range
const CABLEGATE_MIN_HEIGHT: u32 = 229_991;
const CABLEGATE_MAX_HEIGHT: u32 = 230_256;

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
/// - Data transactions: 130 txs with varying P2MS output counts (final chunk may have fewer)
/// - Each transaction: outputs 0-101 are data, output 102 is footer, output 103 is WikiLeaks donation, output 104 is change
/// - Total archive size: ~2.8 MB (corrupted during upload due to CRC32 bug)
///
/// Detection Criteria (all 132 transactions):
/// 1. Tool transactions: Hardcoded TXIDs (downloader + uploader don't have donation address)
/// 2. Data transactions: WikiLeaks donation address + height range 229,991-230,256
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

    /// Check if transaction is a tool transaction (downloader or uploader)
    fn is_tool_transaction(txid: &str) -> Option<&'static str> {
        if txid == CABLEGATE_DOWNLOADER_TXID {
            Some("downloader_tool")
        } else if txid == CABLEGATE_UPLOADER_TXID {
            Some("uploader_tool")
        } else {
            None
        }
    }

    /// Check if transaction is in the Cablegate height range
    fn is_in_cablegate_height_range(height: u32) -> bool {
        (CABLEGATE_MIN_HEIGHT..=CABLEGATE_MAX_HEIGHT).contains(&height)
    }

    /// Check if transaction is part of WikiLeaks Cablegate upload
    ///
    /// Detection criteria:
    /// 1. Tool transactions: Match hardcoded TXIDs (don't have donation address)
    /// 2. Data transactions: WikiLeaks donation address + height range 229,991-230,256
    fn is_cablegate_transaction(&self, tx: &EnrichedTransaction, db: &Database) -> bool {
        // First check: Tool transactions by TXID (don't have donation address)
        if Self::is_tool_transaction(&tx.txid).is_some() {
            return true;
        }

        // Second check: Data transactions must have WikiLeaks address + be in height range
        // Height range check excludes later donations (e.g., height 339,898)
        if !Self::is_in_cablegate_height_range(tx.height) {
            return false;
        }

        // Check for WikiLeaks donation address in transaction outputs (populated during Stage 2)
        match db.has_output_to_address(&tx.txid, &self.wikileaks_address) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                tracing::warn!("DB error checking WikiLeaks address for {}: {}", tx.txid, e);
                false
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

        // Determine transaction type using TXID-based detection for tools
        let tx_type = Self::is_tool_transaction(&tx.txid).unwrap_or("data_transaction");

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

    #[test]
    fn test_tool_transaction_detection() {
        // Downloader tool
        assert_eq!(
            WikiLeaksCablegateClassifier::is_tool_transaction(CABLEGATE_DOWNLOADER_TXID),
            Some("downloader_tool")
        );

        // Uploader tool
        assert_eq!(
            WikiLeaksCablegateClassifier::is_tool_transaction(CABLEGATE_UPLOADER_TXID),
            Some("uploader_tool")
        );

        // Non-tool transaction
        assert_eq!(
            WikiLeaksCablegateClassifier::is_tool_transaction(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            None
        );
    }

    #[test]
    fn test_height_range_check() {
        // Below range
        assert!(!WikiLeaksCablegateClassifier::is_in_cablegate_height_range(
            229_990
        ));

        // At minimum
        assert!(WikiLeaksCablegateClassifier::is_in_cablegate_height_range(
            229_991
        ));

        // In middle
        assert!(WikiLeaksCablegateClassifier::is_in_cablegate_height_range(
            230_000
        ));

        // At maximum
        assert!(WikiLeaksCablegateClassifier::is_in_cablegate_height_range(
            230_256
        ));

        // Above range
        assert!(!WikiLeaksCablegateClassifier::is_in_cablegate_height_range(
            230_257
        ));

        // Much later (donation at 339,898)
        assert!(!WikiLeaksCablegateClassifier::is_in_cablegate_height_range(
            339_898
        ));
    }

    #[test]
    fn test_constants() {
        // Verify hardcoded TXIDs
        assert_eq!(
            CABLEGATE_DOWNLOADER_TXID,
            "6c53cd987119ef797d5adccd76241247988a0a5ef783572a9972e7371c5fb0cc"
        );
        assert_eq!(
            CABLEGATE_UPLOADER_TXID,
            "4b72a223007eab8a951d43edc171befeabc7b5dca4213770c88e09ba5b936e17"
        );

        // Verify height range
        assert_eq!(CABLEGATE_MIN_HEIGHT, 229_991);
        assert_eq!(CABLEGATE_MAX_HEIGHT, 230_256);
    }
}
