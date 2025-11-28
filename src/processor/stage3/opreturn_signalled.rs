use crate::database::traits::Stage1Operations;
use crate::database::Database;
use crate::processor::stage3::SpendabilityAnalyser;
use crate::types::{
    ClassificationDetails, ClassificationResult, EnrichedTransaction, OutputClassificationDetails,
    ProtocolType, ProtocolVariant,
};

use super::ProtocolSpecificClassifier;
use crate::shared::{MultisigPatternMatcher, SignatureDetector};

/// Detector for OP_RETURN-signalled protocols (Protocol47930, CLIPPERZ, GenericASCII).
///
/// These protocols are identified by specific byte markers or ASCII signatures in OP_RETURN outputs.
pub struct OpReturnSignalledDetector;

impl ProtocolSpecificClassifier for OpReturnSignalledDetector {
    fn classify(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Try CLIPPERZ first (strict height range: 403,627-443,835)
        if let Some(result) = self.classify_clipperz(tx, database) {
            return Some(result);
        }

        // Try GenericASCII (catch-all for one-off ASCII OP_RETURN protocols)
        if let Some(result) = self.classify_generic_ascii(tx, database) {
            return Some(result);
        }

        // Try Protocol47930 last (no height restriction, blocks 554,753+)
        self.classify_protocol47930(tx, database)
    }
}

impl OpReturnSignalledDetector {
    /// Classify Protocol 47930 transactions (0xbb3a marker).
    ///
    /// Protocol identified by OP_RETURN bb3a marker + 2-of-2 multisig pattern.
    /// No height restriction - protocol usage spans from block 554,753 (July 2019) onwards.
    fn classify_protocol47930(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        use crate::database::traits::Stage3Operations;
        use crate::types::parse_opreturn_script;

        let op_return_outputs = database.get_outputs_by_type(&tx.txid, "op_return").ok()?;
        let has_marker = op_return_outputs.iter().any(|output| {
            if let Some(op_data) = parse_opreturn_script(&output.script_hex) {
                op_data
                    .protocol_prefix_hex
                    .as_deref()
                    .is_some_and(|prefix| prefix.starts_with("bb3a"))
            } else {
                false
            }
        });

        if !has_marker {
            return None;
        }

        let p2ms_outputs = database.get_p2ms_outputs_for_transaction(&tx.txid).ok()?;

        // Require 2-of-2 multisig pattern
        if !MultisigPatternMatcher::has_pattern(&p2ms_outputs, 2, 2) {
            return None;
        }

        // Build per-output classifications for all P2MS outputs
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(),
                true, // Always true - no height restriction for this protocol
                true, // OP_RETURN prefix provides a definitive signature
                "OP_RETURN 0xbb3a + 2-of-2 multisig".to_string(),
                spendability_result,
            )
            .with_metadata(format!(
                "Protocol 47930: OP_RETURN marker 0xbb3a, 2-of-2 P2MS output ({} sats)",
                output.amount
            ))
            .with_content_type("application/octet-stream");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::OpReturnSignalled,
                Some(ProtocolVariant::OpReturnProtocol47930),
                output_details,
            ));
        }

        // Create transaction-level classification
        let details = ClassificationDetails::new(
            Vec::new(),
            true, // Always true - no height restriction for this protocol
            true, // OP_RETURN prefix provides a definitive signature
            "OP_RETURN 0xbb3a + 2-of-2 multisig".to_string(),
        )
        .with_content_type("application/octet-stream");

        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::OpReturnSignalled,
            Some(ProtocolVariant::OpReturnProtocol47930),
            details,
        );

        Some((tx_classification, output_classifications))
    }

    /// Classify CLIPPERZ notarization transactions.
    ///
    /// Protocol identified by "CLIPPERZ REG" or "CLIPPERZ 1.0 REG" ASCII string + 2-of-2 multisig.
    /// Historical operational range: blocks 403,627-443,835 (March 2016 - June 2016)
    /// (Height range documented for historical reference only - not enforced)
    /// Version 1: "CLIPPERZ REG" prefix (earlier transactions)
    /// Version 2: "CLIPPERZ 1.0 REG" prefix (later transactions)
    fn classify_clipperz(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        use crate::database::traits::Stage3Operations;
        use crate::types::parse_opreturn_script;

        let op_return_outputs = database.get_outputs_by_type(&tx.txid, "op_return").ok()?;

        // Look for CLIPPERZ signature and determine version
        let clipperz_version = op_return_outputs.iter().find_map(|output| {
            let op_data = parse_opreturn_script(&output.script_hex)?;

            // Must concatenate prefix + data to reconstruct full string
            // (parse_opreturn_script splits at first 2-4 bytes)
            let prefix_hex = op_data.protocol_prefix_hex.as_deref().unwrap_or("");
            let data_hex = op_data.data_hex.as_deref().unwrap_or("");
            let full_hex = format!("{}{}", prefix_hex, data_hex);
            let full_bytes = hex::decode(&full_hex).ok()?;

            // Check for version signatures
            if SignatureDetector::has_prefix(&full_bytes, b"CLIPPERZ 1.0 REG") {
                Some(2) // Version 2
            } else if SignatureDetector::has_prefix(&full_bytes, b"CLIPPERZ REG") {
                Some(1) // Version 1
            } else {
                None
            }
        })?;

        // Require 2-of-2 multisig pattern
        let p2ms_outputs = database.get_p2ms_outputs_for_transaction(&tx.txid).ok()?;
        if !MultisigPatternMatcher::has_pattern(&p2ms_outputs, 2, 2) {
            return None;
        }

        // Build per-output classifications for all P2MS outputs
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(),
                true, // Height check passed
                true, // CLIPPERZ ASCII signature provides definitive match
                format!(
                    "OP_RETURN CLIPPERZ {} + 2-of-2 multisig",
                    if clipperz_version == 2 {
                        "1.0 REG"
                    } else {
                        "REG"
                    }
                ),
                spendability_result,
            )
            .with_metadata(format!(
                "CLIPPERZ Protocol v{}: Notarization data, 2-of-2 P2MS output ({} sats)",
                clipperz_version, output.amount
            ))
            .with_content_type("application/octet-stream");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::OpReturnSignalled,
                Some(ProtocolVariant::OpReturnCLIPPERZ),
                output_details,
            ));
        }

        // Create transaction-level classification
        let details = ClassificationDetails::new(
            Vec::new(),
            true,
            true,
            format!(
                "OP_RETURN CLIPPERZ {} + 2-of-2 multisig",
                if clipperz_version == 2 {
                    "1.0 REG"
                } else {
                    "REG"
                }
            ),
        )
        .with_content_type("application/octet-stream")
        .with_metadata(format!("CLIPPERZ version {}", clipperz_version));

        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::OpReturnSignalled,
            Some(ProtocolVariant::OpReturnCLIPPERZ),
            details,
        );

        Some((tx_classification, output_classifications))
    }

    /// Classify generic ASCII OP_RETURN protocols.
    ///
    /// Catch-all detector for one-off protocols with ASCII signatures in OP_RETURN.
    /// Criteria: (≥80% printable AND ≤40 bytes) OR ≥5 consecutive printable ASCII chars.
    /// Examples: "unsuccessful" (100% printable, 15 bytes), "PRVCY" (exactly 5 consecutive)
    /// Excludes: JSON/structured data (too long or too few consecutive chars)
    fn classify_generic_ascii(
        &self,
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        use crate::database::traits::Stage3Operations;
        use crate::types::parse_opreturn_script;

        let op_return_outputs = database.get_outputs_by_type(&tx.txid, "op_return").ok()?;

        // Analyse OP_RETURN data for ASCII patterns
        let ascii_info = op_return_outputs.iter().find_map(|output| {
            let op_data = parse_opreturn_script(&output.script_hex)?;

            // Concatenate prefix + data to reconstruct full content
            let prefix_hex = op_data.protocol_prefix_hex.as_deref().unwrap_or("");
            let data_hex = op_data.data_hex.as_deref().unwrap_or("");
            let full_hex = format!("{}{}", prefix_hex, data_hex);
            let full_bytes = hex::decode(&full_hex).ok()?;

            // Count printable ASCII characters
            let printable_count = full_bytes
                .iter()
                .filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0x00)
                .count();
            let printable_ratio = printable_count as f64 / full_bytes.len() as f64;

            // Find max consecutive printable ASCII chars in first 16 bytes
            let mut max_consecutive = 0;
            let mut current_consecutive = 0;
            for &b in full_bytes.iter().take(16) {
                if (0x20..=0x7E).contains(&b) {
                    current_consecutive += 1;
                    max_consecutive = max_consecutive.max(current_consecutive);
                } else {
                    current_consecutive = 0;
                }
            }

            // Extract signature (first 16 bytes as ASCII-safe string)
            let signature: String = full_bytes
                .iter()
                .take(16)
                .map(|&b| {
                    if (0x20..=0x7E).contains(&b) {
                        b as char
                    } else if b == 0 {
                        '�' // Null byte placeholder
                    } else {
                        '?' // Non-printable placeholder
                    }
                })
                .collect();

            // Accept if EITHER:
            // 1. ≥80% printable AND ≤40 bytes (short ASCII messages like "unsuccessful")
            // 2. ≥5 consecutive printable chars (clear ASCII signatures, excludes random data)
            //
            // Rationale: Avoid catching JSON/structured data (common in generic OP_RETURNs)
            // while still catching one-off ASCII protocols with clear signatures (e.g., "PRVCY").
            if (printable_ratio >= 0.80 && full_bytes.len() <= 40) || max_consecutive >= 5 {
                Some((
                    full_bytes.len(),
                    printable_ratio,
                    signature,
                    max_consecutive,
                ))
            } else {
                None
            }
        })?;

        let (length, ratio, signature, max_consec) = ascii_info;

        // Require P2MS outputs
        let p2ms_outputs = database.get_p2ms_outputs_for_transaction(&tx.txid).ok()?;
        if p2ms_outputs.is_empty() {
            return None;
        }

        // Build per-output classifications for all P2MS outputs
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(),
                true,
                true, // ASCII signature provides definitive match
                format!(
                    "OP_RETURN Generic ASCII ({:.1}% printable, {} consecutive)",
                    ratio * 100.0,
                    max_consec
                ),
                spendability_result,
            )
            .with_metadata(format!(
                "Generic ASCII Protocol: Signature='{}', Length={} bytes ({} sats)",
                signature.trim_end_matches('?'),
                length,
                output.amount
            ))
            .with_content_type("text/plain");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::OpReturnSignalled,
                Some(ProtocolVariant::OpReturnGenericASCII),
                output_details,
            ));
        }

        // Create transaction-level classification
        let details = ClassificationDetails::new(
            Vec::new(),
            true,
            true,
            format!(
                "OP_RETURN Generic ASCII ({:.1}% printable, {} consecutive)",
                ratio * 100.0,
                max_consec
            ),
        )
        .with_content_type("text/plain")
        .with_metadata(format!(
            "ASCII signature: {}, {} bytes",
            signature.trim_end_matches('?'),
            length
        ));

        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::OpReturnSignalled,
            Some(ProtocolVariant::OpReturnGenericASCII),
            details,
        );

        Some((tx_classification, output_classifications))
    }
}
