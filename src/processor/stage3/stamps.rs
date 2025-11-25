use crate::crypto::arc4;
use crate::database::traits::Stage2Operations;
use crate::database::Database;
use crate::types::counterparty::COUNTERPARTY_PREFIX;
use crate::types::stamps::{validation, StampsTransport};
use crate::types::{ClassificationResult, EnrichedTransaction, ProtocolType, Stage3Config};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::trace;

use super::filter_p2ms_for_classification;
use super::{ProtocolSpecificClassifier, SignatureDetector, SpendabilityAnalyser};

/// Bitcoin Stamps classifier - detects keyburn P2MS and validates ARC4 'stamp:' payload
pub struct BitcoinStampsClassifier {
    _config: Stage3Config,
}

impl BitcoinStampsClassifier {
    pub fn new(config: &Stage3Config) -> Self {
        Self {
            _config: config.clone(),
        }
    }
}

impl ProtocolSpecificClassifier for BitcoinStampsClassifier {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Collect Stage 2 burns for potential fallback (maintain prior behaviour)
        let stamps_patterns: Vec<_> = tx
            .burn_patterns_detected
            .iter()
            .filter(|p| {
                matches!(
                    p.pattern_type,
                    crate::types::burn_patterns::BurnPatternType::Stamps22Pattern
                        | crate::types::burn_patterns::BurnPatternType::Stamps33Pattern
                        | crate::types::burn_patterns::BurnPatternType::Stamps0202Pattern
                        | crate::types::burn_patterns::BurnPatternType::Stamps0303Pattern
                )
            })
            .collect();

        // Use burn keys from stamps types module

        // Filter to P2MS outputs ONLY (collect owned values for validation functions)
        let p2ms_outputs: Vec<_> = filter_p2ms_for_classification(&tx.outputs)
            .into_iter()
            .cloned()
            .collect();

        // Fetch first input prev_txid (hex) for ARC4 seed (only if we have P2MS outputs)
        let arc4_key_opt: Option<Vec<u8>> = if p2ms_outputs.is_empty() {
            None
        } else {
            let input_txid_result = database.get_first_input_txid(&tx.txid);

            // Debug: Print what we got from database
            // Debug logging handled by trace! macro if needed

            input_txid_result
                .ok()
                .flatten()
                .and_then(|txid| arc4::prepare_key_from_txid(txid.as_str()))
        };

        // Use the unified multi-output processing function (handles both pure and Counterparty-embedded)
        if let Some(ref key) = arc4_key_opt {
            if let Some(result) = validation::process_multioutput_stamps(&p2ms_outputs, key) {
                // Check if this is Counterparty transport (has both CNTRPRTY and STAMP:)
                let has_cntrprty = SignatureDetector::has_at_any_offset(
                    &result.decrypted_data,
                    COUNTERPARTY_PREFIX,
                );

                // Compose metadata summary including all outputs
                let output_info: Vec<_> = result
                    .valid_outputs
                    .iter()
                    .map(|out| {
                        let info = out.multisig_info();
                        serde_json::json!({
                            "vout": out.vout,
                            "burn_pubkey": info.as_ref().and_then(|i| i.pubkeys.get(2)),
                            "required_sigs": info.as_ref().map(|i| i.required_sigs),
                            "total_pubkeys": info.as_ref().map(|i| i.total_pubkeys),
                        })
                    })
                    .collect();

                // Convert signature variant to string once to avoid move issues
                let signature_str = result.stamp_signature_variant.to_string();

                let meta = if has_cntrprty {
                    serde_json::json!({
                        "transport_protocol": "Counterparty",
                        "stamp_signature_variant": signature_str.clone(),
                        "outputs": output_info,
                        "total_outputs": result.valid_outputs.len(),
                        "concatenated_data_size": result.concatenated_data_size,
                        "stamp_signature_offset": result.stamp_signature_offset,
                        "has_dual_signature": true,
                        "encoding_format": "Counterparty embedded"
                    })
                } else {
                    serde_json::json!({
                        "transport_protocol": "Pure Bitcoin Stamps",
                        "stamp_signature_variant": signature_str,
                        "outputs": output_info,
                        "total_outputs": result.valid_outputs.len(),
                        "concatenated_data_size": result.concatenated_data_size,
                        "stamp_signature_offset": result.stamp_signature_offset,
                        "encoding_format": "Direct P2MS"
                    })
                }
                .to_string();

                let classification_method = if has_cntrprty {
                    "Bitcoin Stamps via Counterparty transport (burn keys + CNTRPRTY + STAMP signatures)"
                } else if result.valid_outputs.len() == 1 {
                    "Pure Bitcoin Stamps (single P2MS output)"
                } else {
                    "Pure Bitcoin Stamps (multi-output concatenated)"
                };

                // Determine transport mechanism for spendability analysis
                let transport = if has_cntrprty {
                    StampsTransport::Counterparty
                } else {
                    StampsTransport::Pure
                };

                // Detect variant and content type together using the new function
                let (variant_opt, content_type_opt, _image_format) =
                    validation::detect_stamps_variant_with_content(&result.decrypted_data);

                let variant = variant_opt.map(|v| v.into());
                let content_type = content_type_opt.map(|s| s.to_string());

                trace!(
                    "Classified Bitcoin Stamps tx {} (variant: {:?}, outputs: {}, method: {})",
                    tx.txid,
                    variant,
                    result.valid_outputs.len(),
                    classification_method
                );

                // Build per-output classifications with PER-OUTPUT spendability analysis
                let mut output_classifications = Vec::new();
                for out in result.valid_outputs.iter() {
                    // CRITICAL: Analyse spendability for THIS specific output to get accurate key counts
                    let spendability_result =
                        SpendabilityAnalyser::analyse_stamps_output(out, transport);

                    let mut details = crate::types::OutputClassificationDetails::new(
                        tx.burn_patterns_detected
                            .iter()
                            .map(|p| p.pattern_type.clone())
                            .collect(),
                        true,
                        true,
                        classification_method.to_string(),
                        spendability_result,
                    )
                    .with_metadata(meta.clone());

                    if let Some(ct) = &content_type {
                        details = details.with_content_type(ct.clone());
                    }

                    output_classifications.push(crate::types::OutputClassificationData::new(
                        out.vout,
                        crate::types::ProtocolType::BitcoinStamps,
                        variant.clone(),
                        details,
                    ));
                }

                // Return transaction-level classification (no spendability - that's per-output)
                let tx_classification = ClassificationResult {
                    txid: tx.txid.clone(),
                    protocol: ProtocolType::BitcoinStamps,
                    variant,
                    classification_details: crate::types::ClassificationDetails {
                        burn_patterns_detected: tx
                            .burn_patterns_detected
                            .iter()
                            .map(|p| p.pattern_type.clone())
                            .collect(),
                        height_check_passed: true,
                        protocol_signature_found: true,
                        classification_method: classification_method.to_string(),
                        additional_metadata: Some(meta),
                        content_type,
                    },
                    classification_timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                return Some((tx_classification, output_classifications));
            }
        }

        // Fallback: If no definitive P2MS+ARC4 signature found, but Stage 2 found burns, classify.
        if !stamps_patterns.is_empty() {
            // Collect all pattern types for transaction-level details
            let all_pattern_types: Vec<_> = stamps_patterns
                .iter()
                .map(|p| p.pattern_type.clone())
                .collect();

            // Build per-output classifications for each burn pattern detected
            // Each output gets its own spendability analysis for accurate key counts
            let mut output_classifications = Vec::new();
            for p in &stamps_patterns {
                // Find the actual output for this burn pattern
                let output = p2ms_outputs.iter().find(|o| o.vout == p.vout);

                // Burn-key-only detection: treat as Pure (no Counterparty transport signature)
                let spendability_result = if let Some(out) = output {
                    SpendabilityAnalyser::analyse_stamps_output(out, StampsTransport::Pure)
                } else {
                    // Fallback if output not found - assume all burn keys
                    crate::types::spendability::SpendabilityResult::all_burn_keys(1)
                };

                // StampsUnknown variant: ARC4 decryption failed or 'stamp:' signature not found.
                // Content type remains None because we cannot extract/validate the payload.
                // This is correct behaviour - failed decryption = no content to classify.
                let details = crate::types::OutputClassificationDetails::new(
                    vec![p.pattern_type.clone()],
                    true,
                    false,
                    "Bitcoin Stamps burn key only; ARC4 'stamp:' not validated".to_string(),
                    spendability_result,
                );
                // No .with_content_type() - intentionally None

                output_classifications.push(crate::types::OutputClassificationData::new(
                    p.vout,
                    crate::types::ProtocolType::BitcoinStamps,
                    Some(crate::types::ProtocolVariant::StampsUnknown),
                    details,
                ));
            }

            let tx_classification = ClassificationResult {
                txid: tx.txid.clone(),
                protocol: ProtocolType::BitcoinStamps,
                variant: Some(crate::types::ProtocolVariant::StampsUnknown),
                classification_details: crate::types::ClassificationDetails {
                    burn_patterns_detected: all_pattern_types,
                    height_check_passed: true,
                    protocol_signature_found: false,
                    classification_method:
                        "Bitcoin Stamps burn key only; ARC4 'stamp:' not validated".to_string(),
                    additional_metadata: None,
                    content_type: None,
                },
                classification_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            return Some((tx_classification, output_classifications));
        }

        None
    }
}
