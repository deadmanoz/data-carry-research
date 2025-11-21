//! Shared PPk Protocol Detection Module
//!
//! PPk (PPkPub) is an abandoned blockchain infrastructure protocol from Beijing University
//! of Posts and Telecommunications (2015-2019) that attempted to create a decentralised
//! naming and identity system built on Bitcoin.
//!
//! This module provides the SINGLE SOURCE OF TRUTH for PPk protocol detection.
//! Both Stage 3 classification and Stage 4 decoding use these functions.

use crate::types::script_metadata::parse_p2ms_script;
use crate::types::{ProtocolVariant, TransactionOutput};

/// PPk marker pubkey (must appear in position 2 of P2MS script)
const PPK_MARKER: &str = "0320a0de360cc2ae8672db7d557086a4e7c8eca062c0a5a4ba9922dee0aacf3e12";

/// PPk protocol detection result
#[derive(Debug, Clone)]
pub struct PPkDetectionResult {
    /// Protocol variant (from existing ProtocolVariant enum)
    pub variant: ProtocolVariant,
    /// Parsed RT JSON (for RT variants only)
    pub rt_json: Option<serde_json::Value>,
    /// Full OP_RETURN bytes (COMPLETE data, not trimmed)
    pub raw_opreturn_bytes: Option<Vec<u8>>,
    /// Extracted/parsed data (JSON string, registration number, message text)
    pub parsed_data: Option<Vec<u8>>,
    /// Content type for this variant
    pub content_type: &'static str,
}

/// ODIN identifier for PPk resources
/// Format: ppk:[BLOCK_HEIGHT].[TRANSACTION_INDEX]/[DSS]
#[derive(Debug, Clone)]
pub struct OdinIdentifier {
    pub block_height: u64,
    pub tx_index: usize,
    pub dss: String,
    pub full_identifier: String,
    pub block_time: u64,
}

impl OdinIdentifier {
    pub fn new(block_height: u64, tx_index: usize, dss: String, block_time: u64) -> Self {
        let full_identifier = format!("ppk:{}.{}/{}", block_height, tx_index, dss);
        Self {
            block_height,
            tx_index,
            dss,
            full_identifier,
            block_time,
        }
    }
}

/// Detect PPk protocol variant from transaction outputs
///
/// This is the ONLY function Stage 3 and Stage 4 should call.
/// Returns None if no PPk marker found OR no variant matches.
pub fn detect_ppk_variant(
    op_return_outputs: &[TransactionOutput],
    p2ms_outputs: &[TransactionOutput],
) -> Option<PPkDetectionResult> {
    // Step 1: Check for PPk marker in position 2 of ANY P2MS output
    let has_marker = p2ms_outputs.iter().any(|output| {
        parse_p2ms_script(&output.script_hex)
            .ok()
            .map(|(pubkeys, _, _)| pubkeys.len() >= 2 && pubkeys[1] == PPK_MARKER)
            .unwrap_or(false)
    });

    if !has_marker {
        return None; // NOT a PPk transaction
    }

    // Step 2: Try variants in specificity order
    detect_rt_standard(op_return_outputs, p2ms_outputs)
        .or_else(|| detect_rt_p2ms_embedded(op_return_outputs, p2ms_outputs))
        .or_else(|| detect_registration(op_return_outputs))
        .or_else(|| detect_message(op_return_outputs))
        .or({
            // Fallback: PPk marker found but no specific variant
            Some(PPkDetectionResult {
                variant: ProtocolVariant::PPkUnknown,
                rt_json: None,
                raw_opreturn_bytes: None,
                parsed_data: None,
                content_type: "application/octet-stream",
            })
        })
}

/// Check if any P2MS output matches m-of-n pattern
fn has_multisig_pattern(
    p2ms_outputs: &[TransactionOutput],
    required_sigs: u32,
    total_keys: u32,
) -> bool {
    p2ms_outputs.iter().any(|output| {
        parse_p2ms_script(&output.script_hex)
            .ok()
            .map(|(_, m, n)| m == required_sigs && n == total_keys)
            .unwrap_or(false)
    })
}

/// Extract full OP_RETURN bytes from script hex
///
/// IMPORTANT: Returns COMPLETE OP_RETURN data (not trimmed to declared length)
/// This preserves trailing padding/data for archival purposes.
fn extract_opreturn_bytes(script_hex: &str) -> Option<Vec<u8>> {
    let script_bytes = hex::decode(script_hex).ok()?;

    if script_bytes.len() < 2 || script_bytes[0] != 0x6a {
        return None; // Not OP_RETURN
    }

    let data_start = match script_bytes[1] {
        0x01..=0x4b => 2,
        0x4c if script_bytes.len() >= 3 => 3,
        0x4d if script_bytes.len() >= 4 => 4,
        0x4e if script_bytes.len() >= 6 => 6,
        _ => return None,
    };

    if script_bytes.len() <= data_start {
        return None;
    }

    // Return FULL remaining data (not trimmed to declared length)
    Some(script_bytes[data_start..].to_vec())
}

/// Parse RT TLV structure from OP_RETURN data
///
/// PERMISSIVE: Allows trailing data after declared length (matches Stage 3 behaviour)
/// Format: [RT:2][Length:1][JSON:Length]
pub fn parse_rt_tlv(op_return_bytes: &[u8]) -> Option<String> {
    if op_return_bytes.len() < 4 {
        return None;
    }

    // Check for "RT" marker
    if &op_return_bytes[0..2] != b"RT" {
        return None;
    }

    let declared_length = op_return_bytes[2] as usize;

    // PERMISSIVE: Extract exactly declared_length bytes (ignore trailing data)
    if op_return_bytes.len() < 3 + declared_length {
        return None; // Not enough data
    }

    let json_bytes = &op_return_bytes[3..3 + declared_length];

    String::from_utf8(json_bytes.to_vec()).ok()
}

/// Detect Profile variant (OP_RETURN transport)
/// Pattern: OP_RETURN with RT TLV + 1-of-2 multisig + PPk marker
fn detect_rt_standard(
    op_return_outputs: &[TransactionOutput],
    p2ms_outputs: &[TransactionOutput],
) -> Option<PPkDetectionResult> {
    // Check for 1-of-2 multisig pattern
    if !has_multisig_pattern(p2ms_outputs, 1, 2) {
        return None;
    }

    // Look for RT TLV in OP_RETURN
    for output in op_return_outputs.iter() {
        if let Some(opreturn_bytes) = extract_opreturn_bytes(&output.script_hex) {
            if let Some(rt_json_string) = parse_rt_tlv(&opreturn_bytes) {
                let rt_json = serde_json::from_str(&rt_json_string).ok();
                return Some(PPkDetectionResult {
                    variant: ProtocolVariant::PPkProfile,
                    rt_json,
                    raw_opreturn_bytes: Some(opreturn_bytes), // FULL bytes
                    parsed_data: Some(rt_json_string.into_bytes()), // Parsed JSON
                    content_type: "application/json",
                });
            }
        }
    }

    None
}

/// Detect Profile variant (P2MS-embedded transport)
/// Pattern: RT in pubkey #3, JSON split between P2MS + OP_RETURN, 1-of-3 multisig
fn detect_rt_p2ms_embedded(
    op_return_outputs: &[TransactionOutput],
    p2ms_outputs: &[TransactionOutput],
) -> Option<PPkDetectionResult> {
    // Check for 1-of-3 multisig pattern
    if !has_multisig_pattern(p2ms_outputs, 1, 3) {
        return None;
    }

    // Require OP_RETURN present
    if op_return_outputs.is_empty() {
        return None;
    }

    // Extract OP_RETURN data
    let op_return_bytes = extract_opreturn_bytes(&op_return_outputs[0].script_hex)?;

    // Scan ALL P2MS outputs for RT in pubkey #3
    for output in p2ms_outputs.iter() {
        let (pubkeys, _, _) = parse_p2ms_script(&output.script_hex).ok()?;

        if pubkeys.len() != 3 {
            continue;
        }

        // Check pubkey #3
        let pubkey3_bytes = hex::decode(&pubkeys[2]).ok()?;
        if pubkey3_bytes.len() != 33 {
            continue;
        }

        // Validate pubkey prefix (0x02 or 0x03)
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

        // CRITICAL: Validate byte 4 is space (0x20)
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
        combined_json_bytes.extend_from_slice(&op_return_bytes);

        // Validate JSON
        let json_string = String::from_utf8(combined_json_bytes.clone()).ok()?;

        if json_string.len() < 5 || json_string.len() > 1000 {
            continue;
        }

        if let Ok(rt_json) = serde_json::from_str::<serde_json::Value>(&json_string) {
            return Some(PPkDetectionResult {
                variant: ProtocolVariant::PPkProfile,
                rt_json: Some(rt_json),
                raw_opreturn_bytes: Some(op_return_bytes), // OP_RETURN part
                parsed_data: Some(json_string.into_bytes()), // Full combined JSON
                content_type: "application/json",
            });
        }
    }

    None
}

/// Detect Registration variant
/// Pattern: OP_RETURN contains quoted number string like "315"}
fn detect_registration(op_return_outputs: &[TransactionOutput]) -> Option<PPkDetectionResult> {
    for output in op_return_outputs.iter() {
        if let Some(opreturn_bytes) = extract_opreturn_bytes(&output.script_hex) {
            // Registration pattern: "123"} (quoted digits + trailing "}")
            if opreturn_bytes.len() >= 4
                && opreturn_bytes.starts_with(b"\"")
                && opreturn_bytes.ends_with(b"\"}")
            {
                let content = &opreturn_bytes[1..opreturn_bytes.len() - 2];
                if content.iter().all(|&b| b.is_ascii_digit()) {
                    if let Ok(reg_number) = String::from_utf8(content.to_vec()) {
                        return Some(PPkDetectionResult {
                            variant: ProtocolVariant::PPkRegistration,
                            rt_json: None,
                            raw_opreturn_bytes: Some(opreturn_bytes),
                            parsed_data: Some(reg_number.into_bytes()),
                            content_type: "text/plain",
                        });
                    }
                }
            }
        }
    }

    None
}

/// Detect Message variant
/// Pattern: OP_RETURN contains "PPk"/"ppk" substring OR ≥80% printable ASCII
fn detect_message(op_return_outputs: &[TransactionOutput]) -> Option<PPkDetectionResult> {
    for output in op_return_outputs.iter() {
        if let Some(opreturn_bytes) = extract_opreturn_bytes(&output.script_hex) {
            // Message pattern: contains "PPk" or "ppk" substring
            let has_ppk = opreturn_bytes
                .windows(3)
                .any(|w| w == b"PPk" || w == b"ppk");

            // OR ≥80% printable ASCII
            let printable_count = opreturn_bytes
                .iter()
                .filter(|&&b| (32..127).contains(&b))
                .count();
            let is_mostly_printable = printable_count >= (opreturn_bytes.len() * 4) / 5;

            if has_ppk || is_mostly_printable {
                if let Ok(message_text) = String::from_utf8(opreturn_bytes.clone()) {
                    return Some(PPkDetectionResult {
                        variant: ProtocolVariant::PPkMessage,
                        rt_json: None,
                        raw_opreturn_bytes: Some(opreturn_bytes),
                        parsed_data: Some(message_text.into_bytes()),
                        content_type: "text/plain",
                    });
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create test TransactionOutput with proper P2MS script
    fn create_test_p2ms_output(pubkeys: Vec<&str>, vout: u32) -> TransactionOutput {
        let metadata = serde_json::json!({
            "required_sigs": 1,
            "total_pubkeys": pubkeys.len(),
            "pubkeys": pubkeys,
        });

        // Build proper P2MS script: OP_1 <pk1> <pk2> ... OP_N OP_CHECKMULTISIG
        let mut script_hex = String::from("51"); // OP_1 (required sigs)

        for pubkey in &pubkeys {
            let pk_bytes = hex::decode(pubkey).expect("Invalid pubkey hex");
            script_hex.push_str(&format!("{:02x}", pk_bytes.len())); // Pubkey length
            script_hex.push_str(pubkey); // Pubkey data
        }

        // OP_N (total pubkeys) - 0x51 = OP_1, 0x52 = OP_2, 0x53 = OP_3, etc.
        let op_n = 0x50 + pubkeys.len() as u8;
        script_hex.push_str(&format!("{:02x}", op_n));

        script_hex.push_str("ae"); // OP_CHECKMULTISIG

        TransactionOutput {
            txid: "test_txid".to_string(),
            vout,
            height: 100000,
            amount: 10000,
            script_hex,
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata,
            address: None,
        }
    }

    fn create_test_opreturn_output(hex_data: &str, vout: u32) -> TransactionOutput {
        let metadata = serde_json::json!({
            "data": hex_data,
        });

        // Build proper OP_RETURN script: OP_RETURN + length byte + data
        let data_bytes = hex::decode(hex_data).expect("Invalid hex data");
        let data_len = data_bytes.len();

        // Encode length byte (simplified - only handles <76 bytes)
        let length_byte = if data_len <= 75 {
            format!("{:02x}", data_len)
        } else {
            panic!("Test data too long (>75 bytes)");
        };

        let script_hex = format!("6a{}{}", length_byte, hex_data);
        let script_size = script_hex.len() / 2;

        TransactionOutput {
            txid: "test_txid".to_string(),
            vout,
            height: 100000,
            amount: 0,
            script_hex,
            script_type: "op_return".to_string(),
            is_coinbase: false,
            script_size,
            metadata,
            address: None,
        }
    }

    #[test]
    fn test_ppk_marker_detection() {
        let real_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        // Test 1: Transaction WITH PPk marker should be detected
        let p2ms_with_marker = create_test_p2ms_output(
            vec![
                real_pubkey,
                PPK_MARKER, // Index 1 (second position)
            ],
            0,
        );

        // Verify marker is detected (should match 1-of-2 pattern AND have marker)
        assert!(has_multisig_pattern(&[p2ms_with_marker.clone()], 1, 2));

        // Verify full detection works
        let opreturn = create_test_opreturn_output(&hex::encode(b"test"), 0);
        let result = detect_ppk_variant(&[opreturn.clone()], &[p2ms_with_marker]);
        assert!(result.is_some(), "PPk marker should be detected");

        // Test 2: Transaction WITHOUT PPk marker should NOT be detected
        let p2ms_without_marker = create_test_p2ms_output(vec![real_pubkey, real_pubkey], 0);
        let result = detect_ppk_variant(&[opreturn], &[p2ms_without_marker]);
        assert!(result.is_none(), "Should not detect PPk without marker");
    }

    #[test]
    fn test_parse_rt_tlv() {
        // Valid RT TLV: RT + length + JSON
        let json_str = r#"{"ver":1,"title":"test"}"#;
        let json_bytes = json_str.as_bytes();
        let length = json_bytes.len() as u8;

        let mut tlv_data = b"RT".to_vec();
        tlv_data.push(length);
        tlv_data.extend_from_slice(json_bytes);

        let result = parse_rt_tlv(&tlv_data);
        assert!(result.is_some());

        let json_text = result.unwrap();
        assert!(json_text.contains("\"ver\":1"));
        assert!(json_text.contains("\"title\":\"test\""));
    }

    #[test]
    fn test_parse_rt_tlv_with_trailing_data() {
        // RT TLV with trailing garbage (should still parse)
        let json_str = r#"{"ver":1}"#;
        let json_bytes = json_str.as_bytes();
        let length = json_bytes.len() as u8;

        let mut tlv_data = b"RT".to_vec();
        tlv_data.push(length);
        tlv_data.extend_from_slice(json_bytes);
        tlv_data.extend_from_slice(b"TRAILING_GARBAGE"); // Extra bytes

        let result = parse_rt_tlv(&tlv_data);
        assert!(result.is_some());

        let json_text = result.unwrap();
        assert!(json_text.contains("\"ver\":1"));
        assert!(!json_text.contains("TRAILING_GARBAGE")); // Should not include trailing data
    }

    #[test]
    fn test_detect_rt_standard() {
        let real_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        // Create RT JSON OP_RETURN
        let json_str = r#"{"ver":1,"title":"RNG"}"#;
        let json_bytes = json_str.as_bytes();
        let length = json_bytes.len() as u8;

        let mut rt_data = b"RT".to_vec();
        rt_data.push(length);
        rt_data.extend_from_slice(json_bytes);

        let opreturn = create_test_opreturn_output(&hex::encode(&rt_data), 0);

        // Create 1-of-2 multisig with PPk marker in position 2
        let p2ms = create_test_p2ms_output(vec![real_pubkey, PPK_MARKER], 1);

        let result = detect_ppk_variant(&[opreturn], &[p2ms]);
        assert!(result.is_some());

        let detection = result.unwrap();
        assert!(matches!(detection.variant, ProtocolVariant::PPkProfile));
        assert_eq!(detection.content_type, "application/json");
        assert!(detection.rt_json.is_some());
        assert_eq!(detection.rt_json.unwrap()["title"], "RNG");
    }

    #[test]
    fn test_detect_registration() {
        let real_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        // Create OP_RETURN with quoted number
        let registration_data = b"\"315\"}";
        let opreturn = create_test_opreturn_output(&hex::encode(registration_data), 0);

        // Create 1-of-2 multisig with PPk marker
        let p2ms = create_test_p2ms_output(vec![real_pubkey, PPK_MARKER], 1);

        let result = detect_ppk_variant(&[opreturn], &[p2ms]);
        assert!(result.is_some());

        let detection = result.unwrap();
        assert!(matches!(
            detection.variant,
            ProtocolVariant::PPkRegistration
        ));
        assert_eq!(detection.content_type, "text/plain");
    }

    #[test]
    fn test_detect_message_with_ppk_substring() {
        let real_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        // Create OP_RETURN with "PPk" substring
        let message_data = b"Welcome to PPk Public Group!";
        let opreturn = create_test_opreturn_output(&hex::encode(message_data), 0);

        // Create 1-of-2 multisig with PPk marker
        let p2ms = create_test_p2ms_output(vec![real_pubkey, PPK_MARKER], 1);

        let result = detect_ppk_variant(&[opreturn], &[p2ms]);
        assert!(result.is_some());

        let detection = result.unwrap();
        assert!(matches!(detection.variant, ProtocolVariant::PPkMessage));
        assert_eq!(detection.content_type, "text/plain");
    }

    #[test]
    fn test_detect_unknown_variant() {
        let real_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        // Create OP_RETURN with binary data (no RT, no registration, no message pattern)
        let unknown_data = &[0x00, 0x01, 0x02, 0xFF, 0xFE];
        let opreturn = create_test_opreturn_output(&hex::encode(unknown_data), 0);

        // Create 1-of-2 multisig with PPk marker
        let p2ms = create_test_p2ms_output(vec![real_pubkey, PPK_MARKER], 1);

        let result = detect_ppk_variant(&[opreturn], &[p2ms]);
        assert!(result.is_some());

        let detection = result.unwrap();
        assert!(matches!(detection.variant, ProtocolVariant::PPkUnknown));
        assert_eq!(detection.content_type, "application/octet-stream");
    }

    #[test]
    fn test_no_ppk_marker() {
        let real_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        let opreturn = create_test_opreturn_output(&hex::encode(b"test data"), 0);

        // Create 1-of-2 multisig WITHOUT PPk marker
        let p2ms = create_test_p2ms_output(vec![real_pubkey, real_pubkey], 1);

        let result = detect_ppk_variant(&[opreturn], &[p2ms]);
        assert!(result.is_none()); // Should return None without marker
    }

    #[test]
    fn test_extract_opreturn_bytes() {
        let test_data = b"Hello, PPk!";

        // Create proper OP_RETURN output (includes length byte)
        let output = create_test_opreturn_output(&hex::encode(test_data), 0);

        let extracted = extract_opreturn_bytes(&output.script_hex);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap(), test_data);
    }
}
