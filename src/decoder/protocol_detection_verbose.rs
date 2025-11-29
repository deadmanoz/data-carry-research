//! Verbose protocol detection with detailed debug output
//!
//! This module provides enhanced versions of protocol detection functions
//! that capture detailed information about the decoding process.

use crate::decoder::protocol_detection::{
    has_counterparty_signature, DecodedProtocol, TransactionData,
};
use crate::types::counterparty::COUNTERPARTY_PREFIX;
use crate::types::debug::{P2MSOutputDebugInfo, TransactionDebugInfo};
use crate::types::stamps::validation;
use tracing::{debug, info};

/// Enhanced Counterparty detection with detailed debug output
pub fn try_counterparty_verbose(
    tx_data: &TransactionData,
    verbose: bool,
) -> Option<DecodedProtocol> {
    debug!("Trying Counterparty decoder for {}", tx_data.txid);

    let p2ms_outputs = tx_data.p2ms_outputs();
    if p2ms_outputs.is_empty() {
        return None;
    }

    let first_input_txid = tx_data.first_input_txid()?;

    // Create debug info if verbose mode is enabled
    let mut debug_info = if verbose {
        let mut info = TransactionDebugInfo::new(
            tx_data.txid.clone(),
            "Counterparty (pending validation)".to_string(),
        );
        info.arc4_key_txid = Some(first_input_txid.clone());
        Some(info)
    } else {
        None
    };

    // Use existing Counterparty extraction logic
    let classifier = crate::processor::stage3::counterparty::CounterpartyClassifier::new(
        &crate::types::Stage3Config::default(),
    );

    // Try multi-output extraction first
    if let Some((raw_data, mut output_debug_infos)) =
        extract_multi_output_with_debug(&p2ms_outputs, &classifier, verbose)
    {
        // Decrypt each chunk individually for verbose output
        if verbose {
            decrypt_chunks_individually(&mut output_debug_infos, &first_input_txid);
        }

        // Add debug info for each output if verbose
        if let Some(ref mut debug_info) = debug_info {
            for output_info in output_debug_infos {
                debug_info.add_output(output_info);
            }
        }

        if let Some(decrypted) =
            classifier.decrypt_counterparty_data_with_txid(&raw_data, &first_input_txid)
        {
            if has_counterparty_signature(&decrypted).is_some() {
                // Check for Bitcoin Stamps
                let stamp_sig = validation::find_stamp_signature(&decrypted);

                if let Some((stamp_offset, variant)) = stamp_sig {
                    info!(
                        "✅ Bitcoin Stamps (via Counterparty transport) detected in {} ({} bytes, signature: {:?} at offset {})",
                        tx_data.txid,
                        decrypted.len(),
                        variant,
                        stamp_offset
                    );

                    if let Some(ref mut debug_info) = debug_info {
                        debug_info.protocol =
                            "Bitcoin Stamps (via Counterparty transport)".to_string();
                        debug_info.message_type = Some(format!("Stamps {:?}", variant));
                    }

                    let stamps_data = decrypted[stamp_offset..].to_vec();
                    return Some(DecodedProtocol::BitcoinStamps {
                        txid: tx_data.txid.clone(),
                        decrypted_data: stamps_data,
                        debug_info,
                    });
                }

                // Pure Counterparty
                info!(
                    "✅ Counterparty detected in {} ({} bytes)",
                    tx_data.txid,
                    decrypted.len()
                );

                if let Some(ref mut debug_info) = debug_info {
                    debug_info.protocol = "Counterparty".to_string();
                    // Parse message type
                    if decrypted.len() >= COUNTERPARTY_PREFIX.len() + 4 {
                        let msg_type_start = if decrypted.starts_with(COUNTERPARTY_PREFIX) {
                            COUNTERPARTY_PREFIX.len()
                        } else if decrypted.len() > COUNTERPARTY_PREFIX.len() + 1
                            && &decrypted[1..1 + COUNTERPARTY_PREFIX.len()] == COUNTERPARTY_PREFIX
                        {
                            1 + COUNTERPARTY_PREFIX.len()
                        } else {
                            COUNTERPARTY_PREFIX.len()
                        };

                        if msg_type_start + 4 <= decrypted.len() {
                            let msg_type_bytes = &decrypted[msg_type_start..msg_type_start + 4];
                            let msg_type = u32::from_be_bytes([
                                msg_type_bytes[0],
                                msg_type_bytes[1],
                                msg_type_bytes[2],
                                msg_type_bytes[3],
                            ]);
                            debug_info.message_type =
                                Some(format!("Type {} (0x{:08X})", msg_type, msg_type));
                        }
                    }
                }

                return Some(DecodedProtocol::Counterparty {
                    txid: tx_data.txid.clone(),
                    decrypted_data: decrypted,
                    debug_info,
                });
            }
        }
    }

    // Try single-output fallback
    let mut all_data = Vec::new();
    let mut single_output_debug = Vec::new();

    for output in p2ms_outputs.iter() {
        if let Some(chunk) = classifier.extract_single_output_raw_data(output) {
            if verbose {
                let mut output_debug =
                    P2MSOutputDebugInfo::from_output(output).unwrap_or_else(|| {
                        P2MSOutputDebugInfo {
                            vout: output.vout,
                            multisig_type: "unknown".to_string(),
                            pubkey_count: 0,
                            pubkey_previews: Vec::new(),
                            extraction_method: "Single output extraction".to_string(),
                            raw_chunk: chunk.clone(),
                            decrypted_chunk: None,
                            has_cntrprty_prefix: false,
                            length_prefix: None,
                            has_stamp_signature: false,
                            stamp_signature: None,
                            notes: Vec::new(),
                        }
                    });
                output_debug.set_extraction("Single output pattern".to_string(), chunk.clone());
                single_output_debug.push(output_debug);
            }
            all_data.extend_from_slice(&chunk);
        }
    }

    if !all_data.is_empty() {
        // Decrypt each chunk individually for verbose output
        if verbose {
            decrypt_chunks_individually(&mut single_output_debug, &first_input_txid);
        }

        // Add debug info for single outputs if verbose
        if let Some(ref mut debug_info) = debug_info {
            for output_info in single_output_debug {
                debug_info.add_output(output_info);
            }
        }

        if let Some(decrypted) =
            classifier.decrypt_counterparty_data_with_txid(&all_data, &first_input_txid)
        {
            if has_counterparty_signature(&decrypted).is_some() {
                // Check for Bitcoin Stamps
                let stamp_sig = validation::find_stamp_signature(&decrypted);

                if let Some((stamp_offset, variant)) = stamp_sig {
                    info!(
                        "✅ Bitcoin Stamps (via Counterparty transport) detected in {} ({} bytes)",
                        tx_data.txid,
                        decrypted.len()
                    );

                    if let Some(ref mut debug_info) = debug_info {
                        debug_info.protocol =
                            "Bitcoin Stamps (via Counterparty transport)".to_string();
                        debug_info.message_type = Some(format!("Stamps {:?}", variant));
                    }

                    let stamps_data = decrypted[stamp_offset..].to_vec();
                    return Some(DecodedProtocol::BitcoinStamps {
                        txid: tx_data.txid.clone(),
                        decrypted_data: stamps_data,
                        debug_info,
                    });
                }

                // Pure Counterparty
                info!(
                    "✅ Counterparty detected in {} ({} bytes)",
                    tx_data.txid,
                    decrypted.len()
                );

                if let Some(ref mut debug_info) = debug_info {
                    debug_info.protocol = "Counterparty".to_string();
                }

                return Some(DecodedProtocol::Counterparty {
                    txid: tx_data.txid.clone(),
                    decrypted_data: decrypted,
                    debug_info,
                });
            }
        }
    }

    None
}

/// Extract multi-output data with debug information
fn extract_multi_output_with_debug(
    outputs: &[crate::types::TransactionOutput],
    classifier: &crate::processor::stage3::counterparty::CounterpartyClassifier,
    verbose: bool,
) -> Option<(Vec<u8>, Vec<P2MSOutputDebugInfo>)> {
    let mut combined_raw_data = Vec::new();
    let mut debug_infos = Vec::new();

    for output in outputs.iter() {
        if let Some(multisig_info) = output.multisig_info() {
            let mut output_debug = if verbose {
                P2MSOutputDebugInfo::from_output(output)
            } else {
                None
            };

            // Unified extraction - handles all M-of-N patterns
            let chunk_data = if let Some(chunk) = classifier.extract_raw_data_chunk(output) {
                if let Some(ref mut debug) = output_debug {
                    // Generate pattern description for debug output
                    let pattern_desc = match (multisig_info.required_sigs, multisig_info.total_pubkeys) {
                        (m, 3) => format!("{}-of-3 Counterparty pattern (31 bytes from pubkey[0] + 31 bytes from pubkey[1])", m),
                        (m, 2) => format!("{}-of-2 Counterparty pattern (length-prefixed data from pubkey[1])", m),
                        (m, n) => format!("{}-of-{} Counterparty pattern", m, n),
                    };
                    debug.set_extraction(pattern_desc, chunk.clone());
                }
                Some(chunk)
            } else {
                None
            };

            if let Some(chunk) = chunk_data {
                combined_raw_data.extend_from_slice(&chunk);
                if let Some(debug) = output_debug {
                    debug_infos.push(debug);
                }
            }
        }
    }

    if debug_infos.len() < 2 {
        return None; // Multi-output needs at least 2 outputs
    }

    Some((combined_raw_data, debug_infos))
}

/// Decrypt each chunk individually to show per-output decryption details
fn decrypt_chunks_individually(
    output_debug_infos: &mut [P2MSOutputDebugInfo],
    first_input_txid: &str,
) {
    use crate::crypto::arc4;

    let arc4_key = match arc4::prepare_key_from_txid(first_input_txid) {
        Some(key) => key,
        None => return,
    };

    for (idx, output_info) in output_debug_infos.iter_mut().enumerate() {
        if let Some(decrypted) = arc4::decrypt(&output_info.raw_chunk, &arc4_key) {
            output_info.set_decrypted(decrypted, idx == 0);
        }
    }
}
