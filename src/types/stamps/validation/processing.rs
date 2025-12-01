//! Multi-output processing for Bitcoin Stamps
//!
//! Functions for processing multiple P2MS outputs to extract Bitcoin Stamps data.

use super::super::signature::StampSignature;
use super::extraction::find_stamp_signature;
use super::helpers::{extract_data_chunk, is_stamps_p2ms};
use crate::crypto::arc4;
use crate::types::TransactionOutput;

/// Result of processing multiple P2MS outputs for Bitcoin Stamps
#[derive(Debug, Clone)]
pub struct StampsProcessingResult<'a> {
    pub valid_outputs: Vec<&'a TransactionOutput>,
    pub concatenated_data_size: usize,
    pub decrypted_data: Vec<u8>,
    pub stamp_signature_offset: usize,
    pub stamp_signature_variant: StampSignature,
}

/// Process multiple P2MS outputs for Bitcoin Stamps - tries both processing methods
///
/// Bitcoin Stamps has two main variants:
/// 1. Counterparty-Embedded: Complex length-based extraction with CNTRPRTY + STAMP signatures
/// 2. Pure Bitcoin Stamps: Simple concatenation -> ARC4 decrypt -> 'stamp:' signature only
///
/// We try Counterparty-embedded first since it has more specific requirements.
pub fn process_multioutput_stamps<'a>(
    p2ms_outputs: &'a [TransactionOutput],
    arc4_key: &[u8],
) -> Option<StampsProcessingResult<'a>> {
    if p2ms_outputs.is_empty() || arc4_key.is_empty() {
        return None;
    }

    // Try Counterparty-embedded processing first (more specific requirements)
    if let Some(result) = process_counterparty_embedded_stamps(p2ms_outputs, arc4_key) {
        return Some(result);
    }

    // Fallback to pure Bitcoin Stamps processing
    process_pure_stamps(p2ms_outputs, arc4_key)
}

/// Process pure Bitcoin Stamps using simple concatenation + ARC4 decryption
///
/// This handles the majority of Bitcoin Stamps transactions:
/// - Concatenate all data chunks from P2MS outputs
/// - Single ARC4 decrypt of the concatenated data
/// - Look for 'stamp:' signature (but NOT CNTRPRTY to avoid false positives)
pub fn process_pure_stamps<'a>(
    p2ms_outputs: &'a [TransactionOutput],
    arc4_key: &[u8],
) -> Option<StampsProcessingResult<'a>> {
    if p2ms_outputs.is_empty() || arc4_key.is_empty() {
        return None;
    }

    // Sort outputs by vout for sequential processing
    let mut sorted_outputs: Vec<_> = p2ms_outputs.iter().collect();
    sorted_outputs.sort_by_key(|output| output.vout);

    // Extract and concatenate all data chunks
    let mut concatenated_data = Vec::new();
    let mut valid_outputs = Vec::new();

    for output in sorted_outputs.iter() {
        if let Some(info) = output.multisig_info() {
            if is_stamps_p2ms(
                info.required_sigs as u8,
                info.total_pubkeys as u8,
                &info.pubkeys,
            ) {
                if let Some(chunk) = extract_data_chunk(&info.pubkeys) {
                    concatenated_data.extend(chunk);
                    valid_outputs.push(*output);
                }
            }
        }
    }

    if concatenated_data.is_empty() || valid_outputs.is_empty() {
        return None;
    }

    // Single ARC4 decrypt of all concatenated data
    let decrypted_data = arc4::decrypt(&concatenated_data, arc4_key)?;

    // Check that this is pure Stamps (has STAMP but NOT CNTRPRTY)
    let has_cntrprty = decrypted_data
        .windows(crate::types::counterparty::COUNTERPARTY_PREFIX.len())
        .any(|window| window == crate::types::counterparty::COUNTERPARTY_PREFIX);

    if has_cntrprty {
        // This should be handled by Counterparty-embedded path, not pure path
        return None;
    }

    // Look for stamp signature in pure Stamps data
    let (stamp_offset, variant) = find_stamp_signature(&decrypted_data)?;

    Some(StampsProcessingResult {
        valid_outputs,
        concatenated_data_size: concatenated_data.len(),
        decrypted_data,
        stamp_signature_offset: stamp_offset,
        stamp_signature_variant: variant,
    })
}

/// Process Counterparty-embedded Bitcoin Stamps using length-based extraction
///
/// This handles complex multi-packet Stamps that use Counterparty transport:
/// - Per-output ARC4 decrypt -> length-based extraction -> reassemble
/// - Requires BOTH CNTRPRTY and STAMP signatures for validation
/// - Handles CNTRPRTY prefix logic like Electrum-Counterparty
pub fn process_counterparty_embedded_stamps<'a>(
    p2ms_outputs: &'a [TransactionOutput],
    arc4_key: &[u8],
) -> Option<StampsProcessingResult<'a>> {
    if p2ms_outputs.is_empty() || arc4_key.is_empty() {
        return None;
    }

    // Sort outputs by vout for sequential processing
    let mut sorted_outputs: Vec<_> = p2ms_outputs.iter().collect();
    sorted_outputs.sort_by_key(|output| output.vout);

    // Process each output individually with length-based extraction (like Electrum-Counterparty)
    let mut valid_outputs = Vec::new();
    let mut cp_msg = String::new();
    let mut total_raw_data_size = 0;

    for (i, output) in sorted_outputs.iter().enumerate() {
        if let Some(info) = output.multisig_info() {
            if is_stamps_p2ms(
                info.required_sigs as u8,
                info.total_pubkeys as u8,
                &info.pubkeys,
            ) {
                if let Some(chunk) = extract_data_chunk(&info.pubkeys) {
                    total_raw_data_size += chunk.len();

                    // ARC4 decrypt this specific chunk (key difference from regular Counterparty)
                    if let Some(raw_decrypted) = arc4::decrypt(&chunk, arc4_key) {
                        let raw_hex = hex::encode(&raw_decrypted);

                        if raw_hex.len() >= 2 {
                            // Extract length from first byte (2 hex chars)
                            if let Ok(len) = u8::from_str_radix(&raw_hex[0..2], 16) {
                                let len_chars = (len as usize) * 2; // Convert bytes to hex chars

                                if raw_hex.len() >= 2 + len_chars {
                                    let mut raw = raw_hex[2..2 + len_chars].to_string();

                                    // Handle CNTRPRTY prefix logic like Electrum-Counterparty
                                    if raw.len() >= 16 && &raw[0..16] == "434e545250525459" {
                                        // "CNTRPRTY"
                                        if i == 0
                                            || (cp_msg.len() >= 16
                                                && &cp_msg[0..16] != "434e545250525459")
                                        {
                                            // First message or cp_msg doesn't start with CNTRPRTY, keep prefix
                                        } else {
                                            // Subsequent message with CNTRPRTY, remove duplicate prefix
                                            raw = raw[16..].to_string();
                                        }
                                    } else if raw.is_empty() {
                                        continue; // Skip empty chunks
                                    }

                                    valid_outputs.push(*output);
                                    cp_msg.push_str(&raw);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if valid_outputs.is_empty() || cp_msg.is_empty() {
        return None;
    }

    // Convert final hex message back to bytes
    let final_decoded_bytes = hex::decode(&cp_msg).ok()?;

    // Require BOTH CNTRPRTY and STAMP signatures for Counterparty-embedded
    let has_cntrprty = final_decoded_bytes
        .windows(crate::types::counterparty::COUNTERPARTY_PREFIX.len())
        .any(|window| window == crate::types::counterparty::COUNTERPARTY_PREFIX);

    let stamp_result = find_stamp_signature(&final_decoded_bytes);

    // Must have both signatures to qualify as Counterparty-embedded
    if let Some((stamp_offset, variant)) = stamp_result.filter(|_| has_cntrprty) {
        Some(StampsProcessingResult {
            valid_outputs,
            concatenated_data_size: total_raw_data_size,
            decrypted_data: final_decoded_bytes,
            stamp_signature_offset: stamp_offset,
            stamp_signature_variant: variant,
        })
    } else {
        None
    }
}
