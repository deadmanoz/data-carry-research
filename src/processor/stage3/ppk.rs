//! PPk Protocol Classifier
//!
//! PPk is a blockchain infrastructure protocol with multiple applications.
//! Primary detection: marker pubkey 0320a0de...3e12 in position 2 of multisig.

use crate::database::{
    traits::{Stage1Operations, Stage3Operations},
    Database,
};
use crate::processor::stage3::{
    multisig_patterns::MultisigPatternMatcher, signature_detection::SignatureDetector,
    spendability::SpendabilityAnalyser,
};
use crate::types::{
    parse_opreturn_script, ClassificationDetails, ClassificationResult, EnrichedTransaction,
    OutputClassificationDetails, ProtocolType, ProtocolVariant, TransactionOutput,
};

pub struct PPkClassifier;

impl PPkClassifier {
    const PPK_MARKER_PUBKEY: &'static str =
        "0320a0de360cc2ae8672db7d557086a4e7c8eca062c0a5a4ba9922dee0aacf3e12";

    /// Extract full OP_RETURN payload (not split into prefix/data)
    fn extract_full_opreturn_data(script_hex: &str) -> Option<Vec<u8>> {
        let script_bytes = hex::decode(script_hex).ok()?;

        if script_bytes.len() < 2 || script_bytes[0] != 0x6a {
            return None; // Not OP_RETURN
        }

        let (data_start, declared_len) = match script_bytes[1] {
            op @ 0x01..=0x4b => (2, Some(op as usize)),
            0x4c => {
                if script_bytes.len() < 3 {
                    return None;
                }
                (3, Some(script_bytes[2] as usize))
            }
            0x4d => {
                if script_bytes.len() < 4 {
                    return None;
                }
                let len = u16::from_le_bytes([script_bytes[2], script_bytes[3]]) as usize;
                (4, Some(len))
            }
            _ => return None,
        };

        if script_bytes.len() <= data_start {
            return None;
        }

        let remaining = &script_bytes[data_start..];
        let data = if let Some(len) = declared_len {
            let clamped = len.min(remaining.len());
            &remaining[..clamped]
        } else {
            remaining
        };

        Some(data.to_vec())
    }

    pub fn classify(
        tx: &EnrichedTransaction,
        database: &Database,
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Step 1: PRIMARY PPk detection - check for marker pubkey in position 2
        let p2ms_outputs = database.get_p2ms_outputs_for_transaction(&tx.txid).ok()?;

        let has_ppk_marker = p2ms_outputs
            .iter()
            .any(|output| Self::has_marker(&output.script_hex));

        if !has_ppk_marker {
            return None;
        }

        // Step 2: Determine PPk variant (try in specificity order)

        Self::classify_rt_standard(tx, database, &p2ms_outputs)
            .or_else(|| Self::classify_rt_p2ms_embedded(tx, database, &p2ms_outputs))
            .or_else(|| Self::classify_registration(tx, database, &p2ms_outputs))
            .or_else(|| Self::classify_message(tx, database, &p2ms_outputs))
            .or_else(|| Self::classify_unknown(tx, database, &p2ms_outputs))
    }

    /// Check if script has PPk marker pubkey in position 2
    fn has_marker(script_hex: &str) -> bool {
        if let Some(pubkeys) = Self::parse_p2ms_script(script_hex) {
            pubkeys.len() >= 2 && pubkeys[1] == Self::PPK_MARKER_PUBKEY
        } else {
            false
        }
    }

    /// Variant: RT Standard (OP_RETURN has RT marker)
    /// Detection: OP_RETURN with "RT" TLV + 1-of-2 multisig + PPk marker
    fn classify_rt_standard(
        tx: &EnrichedTransaction,
        database: &Database,
        p2ms_outputs: &[TransactionOutput],
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Check for 1-of-2 multisig pattern
        if !MultisigPatternMatcher::has_pattern(p2ms_outputs, 1, 2) {
            return None;
        }

        // Look for RT marker in OP_RETURN
        let op_return_outputs = database.get_outputs_by_type(&tx.txid, "op_return").ok()?;

        let rt_json = op_return_outputs.iter().find_map(|output| {
            let op_data = parse_opreturn_script(&output.script_hex)?;
            let prefix_hex = op_data.protocol_prefix_hex.as_deref()?;
            let data_hex = op_data.data_hex.as_deref()?;

            let prefix_bytes = hex::decode(prefix_hex).ok()?;
            if prefix_bytes.len() < 4 {
                return None;
            }

            // Check for "RT" marker
            if !SignatureDetector::has_prefix(&prefix_bytes, b"RT") {
                return None;
            }

            let declared_length = prefix_bytes[2] as usize;
            let first_json_byte = prefix_bytes[3];

            let mut full_json_bytes = vec![first_json_byte];
            full_json_bytes.extend_from_slice(&hex::decode(data_hex).ok()?);

            if full_json_bytes.len() != declared_length {
                return None;
            }

            String::from_utf8(full_json_bytes).ok()
        })?;

        // Build classifications for ALL P2MS outputs
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(),
                true,
                true,
                "PPk marker + RT in OP_RETURN + 1-of-2 multisig".to_string(),
                spendability_result,
            )
            .with_metadata(format!("PPk RT Standard variant, JSON: {}", rt_json))
            .with_content_type("application/json");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::PPk,
                Some(ProtocolVariant::PPkRTStandard),
                output_details,
            ));
        }

        let details = ClassificationDetails::new(
            Vec::new(),
            true,
            true,
            "PPk marker + RT in OP_RETURN + 1-of-2 multisig".to_string(),
        )
        .with_content_type("application/json")
        .with_metadata(format!("RT JSON: {}", rt_json));

        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::PPk,
            Some(ProtocolVariant::PPkRTStandard),
            details,
        );

        Some((tx_classification, output_classifications))
    }

    /// Variant: RT P2MS-Embedded (RT in pubkey #3, JSON split between P2MS + OP_RETURN)
    /// Detection: 1-of-3 multisig + RT in pubkey #3 + OP_RETURN completion + PPk marker
    /// CRITICAL: Byte 4 MUST be space (0x20), json_end = 2 + length_byte
    fn classify_rt_p2ms_embedded(
        tx: &EnrichedTransaction,
        database: &Database,
        p2ms_outputs: &[TransactionOutput],
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Check for 1-of-3 multisig pattern
        if !MultisigPatternMatcher::has_pattern(p2ms_outputs, 1, 3) {
            return None;
        }

        // Require OP_RETURN present
        let op_return_outputs = database.get_outputs_by_type(&tx.txid, "op_return").ok()?;
        if op_return_outputs.is_empty() {
            return None;
        }

        // Extract full OP_RETURN data
        let op_return_data = op_return_outputs
            .iter()
            .find_map(|output| Self::extract_full_opreturn_data(&output.script_hex))?;

        // SCAN ALL P2MS OUTPUTS for RT in pubkey #3 (not just first)
        let mut combined_json_string = None;

        for output in p2ms_outputs.iter() {
            let pubkeys = Self::parse_p2ms_script(&output.script_hex)?;

            if pubkeys.len() != 3 {
                continue;
            }

            // Check pubkey #3
            let pubkey3_bytes = hex::decode(&pubkeys[2]).ok()?;
            if pubkey3_bytes.len() != 33 {
                continue;
            }

            // Validate pubkey prefix
            if pubkey3_bytes[0] != 0x02 && pubkey3_bytes[0] != 0x03 {
                continue;
            }

            // Validate RT marker at bytes 2-3
            if &pubkey3_bytes[2..4] != b"RT" {
                continue;
            }

            // Validate length byte
            let length_byte = pubkey3_bytes[1] as usize;
            if length_byte + 2 != 33 {
                continue;
            }

            // CRITICAL: Validate byte 4 is space (filters 77.9% false positives)
            if pubkey3_bytes.len() < 5 || pubkey3_bytes[4] != 0x20 {
                continue;
            }

            // Extract JSON using length byte
            // FIXED: json_end = 2 + length_byte (not 1 + length_byte)
            let json_end = 2 + length_byte;
            if pubkey3_bytes.len() < json_end {
                continue;
            }

            let json_start = &pubkey3_bytes[5..json_end];

            // Concatenate P2MS + OP_RETURN
            let mut combined_json_bytes = json_start.to_vec();
            combined_json_bytes.extend_from_slice(&op_return_data);

            // Validate JSON
            let json_string = String::from_utf8(combined_json_bytes).ok()?;

            if json_string.len() < 5 || json_string.len() > 1000 {
                continue;
            }

            if serde_json::from_str::<serde_json::Value>(&json_string).is_err() {
                continue;
            }

            // Found valid RT!
            combined_json_string = Some(json_string);
            break;
        }

        let json_string = combined_json_string?;

        // Classify ALL P2MS outputs
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(),
                true,
                true,
                "PPk marker + RT in P2MS pubkey #3 + OP_RETURN".to_string(),
                spendability_result,
            )
            .with_metadata(format!(
                "PPk RT P2MS-Embedded variant, JSON: {}",
                json_string
            ))
            .with_content_type("application/json");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::PPk,
                Some(ProtocolVariant::PPkRTP2MSEmbedded),
                output_details,
            ));
        }

        let details = ClassificationDetails::new(
            Vec::new(),
            true,
            true,
            "PPk marker + RT in P2MS pubkey #3 + OP_RETURN".to_string(),
        )
        .with_content_type("application/json")
        .with_metadata(format!("RT JSON: {}", json_string));

        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::PPk,
            Some(ProtocolVariant::PPkRTP2MSEmbedded),
            details,
        );

        Some((tx_classification, output_classifications))
    }

    /// Variant: Registration (number strings like "315", "421")
    /// Heuristic: OP_RETURN contains quoted number string
    fn classify_registration(
        tx: &EnrichedTransaction,
        database: &Database,
        p2ms_outputs: &[TransactionOutput],
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        let op_return_outputs = database.get_outputs_by_type(&tx.txid, "op_return").ok()?;

        let registration_number = op_return_outputs.iter().find_map(|output| {
            // Use full OP_RETURN data (not split into prefix/data)
            let data = Self::extract_full_opreturn_data(&output.script_hex)?;

            // Registration pattern: "123", "456", etc.
            // Format: starts with '"', ends with '"}', all digits between
            if data.len() >= 4 && data.starts_with(b"\"") && data.ends_with(b"\"}") {
                let content = &data[1..data.len() - 2];
                if content.iter().all(|&b| b.is_ascii_digit()) {
                    return String::from_utf8(content.to_vec()).ok();
                }
            }
            None
        })?;

        // Build classifications
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(),
                true,
                true,
                "PPk marker + registration number in OP_RETURN".to_string(),
                spendability_result,
            )
            .with_metadata(format!("PPk Registration: {}", registration_number))
            .with_content_type("text/plain");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::PPk,
                Some(ProtocolVariant::PPkRegistration),
                output_details,
            ));
        }

        let details = ClassificationDetails::new(
            Vec::new(),
            true,
            true,
            "PPk marker + registration number in OP_RETURN".to_string(),
        )
        .with_content_type("text/plain")
        .with_metadata(format!("Registration number: {}", registration_number));

        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::PPk,
            Some(ProtocolVariant::PPkRegistration),
            details,
        );

        Some((tx_classification, output_classifications))
    }

    /// Variant: Message (promotional text like "PPk is future", version strings)
    /// Heuristic: OP_RETURN contains "PPk" or "ppk" substring, OR >=80% printable ASCII
    fn classify_message(
        tx: &EnrichedTransaction,
        database: &Database,
        p2ms_outputs: &[TransactionOutput],
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        let op_return_outputs = database.get_outputs_by_type(&tx.txid, "op_return").ok()?;

        let message_text = op_return_outputs.iter().find_map(|output| {
            // Use full OP_RETURN data (not split into prefix/data)
            let data = Self::extract_full_opreturn_data(&output.script_hex)?;

            // Message pattern: contains "PPk" or "ppk" substring
            let has_ppk_substring =
                data.windows(3).any(|w| w == b"PPk") || data.windows(3).any(|w| w == b"ppk");

            // OR >=80% printable ASCII
            let printable_count = data.iter().filter(|&&b| (32..127).contains(&b)).count();
            let is_mostly_printable = printable_count >= (data.len() * 4) / 5;

            if has_ppk_substring || is_mostly_printable {
                String::from_utf8(data).ok()
            } else {
                None
            }
        })?;

        // Build classifications
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(),
                true,
                true,
                "PPk marker + text message in OP_RETURN".to_string(),
                spendability_result,
            )
            .with_metadata(format!("PPk Message: {}", message_text))
            .with_content_type("text/plain");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::PPk,
                Some(ProtocolVariant::PPkMessage),
                output_details,
            ));
        }

        let details = ClassificationDetails::new(
            Vec::new(),
            true,
            true,
            "PPk marker + text message in OP_RETURN".to_string(),
        )
        .with_content_type("text/plain")
        .with_metadata(format!("Message: {}", message_text));

        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::PPk,
            Some(ProtocolVariant::PPkMessage),
            details,
        );

        Some((tx_classification, output_classifications))
    }

    /// Variant: Unknown (catch-all for PPk marker present but no specific variant)
    /// Fallback for unidentified PPk applications
    fn classify_unknown(
        tx: &EnrichedTransaction,
        database: &Database,
        p2ms_outputs: &[TransactionOutput],
    ) -> Option<(
        ClassificationResult,
        Vec<crate::types::OutputClassificationData>,
    )> {
        // Get OP_RETURN data (if present)
        let raw_data = database
            .get_outputs_by_type(&tx.txid, "op_return")
            .ok()
            .and_then(|outputs| outputs.first().map(|o| o.script_hex.clone()))
            .unwrap_or_else(|| "None".to_string());

        // Build classifications
        let mut output_classifications = Vec::new();
        for output in p2ms_outputs.iter() {
            let spendability_result = SpendabilityAnalyser::analyse_generic_output(output);

            let output_details = OutputClassificationDetails::new(
                Vec::new(),
                true,
                true,
                "PPk marker + unidentified application".to_string(),
                spendability_result,
            )
            .with_metadata("PPk Unknown variant - application not yet identified".to_string())
            .with_content_type("application/octet-stream");

            output_classifications.push(crate::types::OutputClassificationData::new(
                output.vout,
                ProtocolType::PPk,
                Some(ProtocolVariant::PPkUnknown),
                output_details,
            ));
        }

        let details = ClassificationDetails::new(
            Vec::new(),
            true,
            true,
            "PPk marker + unidentified application".to_string(),
        )
        .with_content_type("application/octet-stream")
        .with_metadata(format!("OP_RETURN data: {}", raw_data));

        let tx_classification = ClassificationResult::new(
            tx.txid.clone(),
            ProtocolType::PPk,
            Some(ProtocolVariant::PPkUnknown),
            details,
        );

        Some((tx_classification, output_classifications))
    }

    /// Parse P2MS script to extract pubkeys
    fn parse_p2ms_script(script_hex: &str) -> Option<Vec<String>> {
        let bytes = hex::decode(script_hex).ok()?;
        if bytes.is_empty() {
            return None;
        }

        let mut pubkeys = Vec::new();
        let mut i = 1; // Skip OP_M

        while i < bytes.len() {
            let opcode = bytes[i];

            if opcode == 0x21 {
                // Compressed pubkey (33 bytes)
                if i + 34 > bytes.len() {
                    return None;
                }
                let pubkey = hex::encode(&bytes[i + 1..i + 34]);
                pubkeys.push(pubkey);
                i += 34;
            } else if opcode == 0x41 {
                // Uncompressed pubkey (65 bytes)
                if i + 66 > bytes.len() {
                    return None;
                }
                let pubkey = hex::encode(&bytes[i + 1..i + 66]);
                pubkeys.push(pubkey);
                i += 66;
            } else if (opcode >= 0x51 && opcode <= 0x60) || opcode == 0xae {
                // OP_N or OP_CHECKMULTISIG - end of pubkeys
                break;
            } else {
                return None;
            }
        }

        if pubkeys.is_empty() {
            None
        } else {
            Some(pubkeys)
        }
    }
}
