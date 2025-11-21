//! PPk Protocol Classifier
//!
//! PPk is a blockchain infrastructure protocol with multiple applications.
//! Primary detection: marker pubkey 0320a0de...3e12 in position 2 of multisig.
//!
//! This classifier delegates to the shared PPk detection module (src/types/ppk.rs)
//! to ensure consistency with Stage 4 decoder and adhere to DRY principles.

use crate::database::{
    traits::{Stage1Operations, Stage3Operations},
    Database,
};
use crate::processor::stage3::spendability::SpendabilityAnalyser;
use crate::types::{
    ppk::detect_ppk_variant, ClassificationDetails, ClassificationResult, EnrichedTransaction,
    OutputClassificationDetails, ProtocolType, ProtocolVariant, TransactionOutput,
};

pub struct PPkClassifier;

impl PPkClassifier {
    /// Classify transaction using shared PPk detection module
    ///
    /// This method delegates to `detect_ppk_variant()` from `src/types/ppk.rs`
    /// which is the SINGLE SOURCE OF TRUTH for PPk protocol detection.
    pub fn classify(
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Get P2MS and OP_RETURN outputs for detection
        let p2ms_outputs = database.get_p2ms_outputs_for_transaction(&tx.txid).ok()?;
        let op_return_outputs = database
            .get_outputs_by_type(&tx.txid, "op_return")
            .unwrap_or_default();

        // Delegate to shared detection module (SINGLE SOURCE OF TRUTH)
        let detection_result = detect_ppk_variant(&op_return_outputs, &p2ms_outputs)?;

        // Convert detection result to Stage 3 classification format
        Self::build_classification(
            tx,
            &p2ms_outputs,
            detection_result.variant,
            detection_result.content_type,
            detection_result.rt_json.as_ref(),
        )
    }

    /// Build Stage 3 classification from detection result
    fn build_classification(
        tx: &EnrichedTransaction,
        p2ms_outputs: &[TransactionOutput],
        variant: ProtocolVariant,
        content_type: &str,
        rt_json: Option<&serde_json::Value>,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Build metadata string
        let metadata = match (&variant, rt_json) {
            (ProtocolVariant::PPkProfile, Some(json)) => {
                format!("PPk Profile variant (JSON profile data), data: {}", json)
            }
            (ProtocolVariant::PPkRegistration, _) => {
                "PPk Registration variant (quoted number string)".to_string()
            }
            (ProtocolVariant::PPkMessage, _) => {
                "PPk Message variant (promotional text)".to_string()
            }
            (ProtocolVariant::PPkUnknown, _) => {
                "PPk Unknown variant (marker present, no specific pattern)".to_string()
            }
            _ => format!("PPk variant: {:?}", variant),
        };

        let classification_method = format!("PPk marker pubkey detected, variant: {:?}", variant);

        // Build output classifications for ALL P2MS outputs
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(), // No burn patterns for PPk
                true,       // height_check_passed (not used for PPk)
                true,       // protocol_signature_found
                classification_method.clone(),
                spendability_result,
            )
            .with_metadata(metadata.clone())
            .with_content_type(content_type);

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::PPk,
                Some(variant.clone()),
                output_details,
            ));
        }

        // Build transaction classification
        let details = ClassificationDetails::new(
            Vec::new(), // No burn patterns for PPk
            true,       // height_check_passed (not used for PPk)
            true,       // protocol_signature_found
            classification_method,
        )
        .with_content_type(content_type)
        .with_metadata(metadata);

        let tx_classification =
            ClassificationResult::new(tx.txid.clone(), ProtocolType::PPk, Some(variant), details);

        Some((tx_classification, output_classifications))
    }
}
