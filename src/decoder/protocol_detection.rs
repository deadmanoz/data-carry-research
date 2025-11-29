/// Simplified protocol detection for Bitcoin data-carrying protocols
///
/// This module provides a clean, extensible interface for detecting and decoding
/// various Bitcoin protocols (Bitcoin Stamps, Counterparty, Omni, etc.)
///
/// Design philosophy:
/// - Each protocol has a simple `try_*()` method that returns Option<DecodedProtocol>
/// - Linear decode flow: try protocols in priority order
/// - Easy to add new protocols - just add a new `try_*()` method
/// - No complex abstractions or priority logic
/// - Protocol-agnostic transaction data (full transaction access)
use crate::crypto::arc4;
use crate::decoder::DecoderResult;
use crate::rpc::BitcoinRpcClient;
use crate::types::counterparty::COUNTERPARTY_PREFIX;
use crate::types::stamps::validation;
use crate::types::TransactionOutput;
use corepc_client::bitcoin::Transaction;
use hex;
use tracing::{debug, info};

/// Generic transaction data for protocol detection
///
/// Provides full transaction access - each protocol extracts what it needs:
/// - Bitcoin Stamps: P2MS outputs + first input TXID (for ARC4)
/// - Counterparty: P2MS outputs + first input TXID (for ARC4)
/// - Omni: P2MS outputs + Exodus address presence
#[derive(Debug)]
pub struct TransactionData {
    pub txid: String,
    pub transaction: Transaction,
}

/// Decoded protocol-specific data
#[derive(Debug)]
pub enum DecodedProtocol {
    BitcoinStamps {
        txid: String,
        decrypted_data: Vec<u8>,
        debug_info: Option<crate::types::debug::TransactionDebugInfo>,
    },
    Counterparty {
        txid: String,
        decrypted_data: Vec<u8>,
        debug_info: Option<crate::types::debug::TransactionDebugInfo>,
    },
    Omni {
        txid: String,
        decrypted_data: Vec<u8>,
        sender_address: String,
        packet_count: u8,
        debug_info: Option<crate::types::debug::TransactionDebugInfo>,
    },
    Chancecoin {
        txid: String,
        message: crate::types::chancecoin::ChancecoinMessage,
        debug_info: Option<crate::types::debug::TransactionDebugInfo>,
    },
    PPk {
        txid: String,
        variant: crate::types::ProtocolVariant,
        rt_json: Option<serde_json::Value>,
        raw_opreturn_bytes: Option<Vec<u8>>,
        parsed_data: Option<Vec<u8>>,
        content_type: String,
        odin_identifier: Option<crate::types::ppk::OdinIdentifier>,
        debug_info: Option<crate::types::debug::TransactionDebugInfo>,
    },
    LikelyLegitimateMultisig {
        txid: String,
        validation_summary: String,
        has_duplicates: bool,
        debug_info: Option<crate::types::debug::TransactionDebugInfo>,
    },
    LikelyDataStorage {
        txid: String,
        pattern_type: String, // "InvalidECPoint", "HighOutputCount", "DustAmount"
        details: String,
        debug_info: Option<crate::types::debug::TransactionDebugInfo>,
    },
    DataStorage {
        txid: String,
        pattern: String,
        decoded_data: Vec<u8>,
        metadata: serde_json::Value,
        debug_info: Option<crate::types::debug::TransactionDebugInfo>,
    },
}

impl TransactionData {
    /// Get the first input TXID (used for ARC4 key in Stamps/Counterparty)
    pub fn first_input_txid(&self) -> Option<String> {
        self.transaction
            .input
            .first()
            .map(|input| input.previous_output.txid.to_string())
    }

    /// Prepare ARC4 key from first input TXID (for Stamps/Counterparty)
    pub fn arc4_key(&self) -> Option<Vec<u8>> {
        let first_input_txid = self.first_input_txid()?;
        arc4::prepare_key_from_txid(&first_input_txid)
    }

    /// Extract P2MS outputs (used by Stamps, Counterparty, and possibly Omni)
    /// Also handles "nonstandard" outputs that may be P2MS (Bitcoin Core sometimes misclassifies them)
    pub fn p2ms_outputs(&self) -> Vec<TransactionOutput> {
        let mut outputs = Vec::new();

        for (vout, output) in self.transaction.output.iter().enumerate() {
            let script_hex = hex::encode(output.script_pubkey.to_bytes());
            let script_bytes = output.script_pubkey.to_bytes();

            // First try standard P2MS parsing using shared parser
            if let Ok((pubkeys, required_sigs, total_pubkeys)) =
                crate::types::script_metadata::parse_p2ms_script(&script_hex)
            {
                use crate::types::script_metadata::MultisigInfo;

                let multisig_info = MultisigInfo {
                    pubkeys,
                    required_sigs,
                    total_pubkeys,
                };

                outputs.push(TransactionOutput {
                    txid: self.txid.clone(),
                    vout: vout as u32,
                    height: 0,
                    amount: output.value.to_sat(),
                    script_hex: script_hex.clone(),
                    script_type: "multisig".to_string(),
                    is_coinbase: false,
                    script_size: script_bytes.len(),
                    metadata: serde_json::to_value(multisig_info)
                        .unwrap_or_else(|_| serde_json::json!({})),
                    address: None, // Address extraction not needed for decoder
                });
            } else {
                // Check if this might be a "nonstandard" P2MS that Bitcoin Core misclassified
                // These were correctly identified as P2MS in the UTXO dump extraction
                // Look for patterns like: OP_1 <pubkey> <pubkey> OP_2 OP_CHECKMULTISIG
                if let Some(p2ms_output) = self.try_parse_nonstandard_p2ms(
                    &script_hex,
                    &script_bytes,
                    vout as u32,
                    output.value.to_sat(),
                ) {
                    debug!("Found nonstandard P2MS output at vout {}", vout);
                    outputs.push(p2ms_output);
                }
            }
        }

        outputs
    }

    /// Try to parse a nonstandard script as P2MS
    /// Bitcoin Core sometimes marks valid P2MS scripts as "nonstandard"
    fn try_parse_nonstandard_p2ms(
        &self,
        script_hex: &str,
        script_bytes: &[u8],
        vout: u32,
        amount: u64,
    ) -> Option<TransactionOutput> {
        // Check for basic P2MS structure markers
        // Look for OP_CHECKMULTISIG (0xae) at the end
        if script_bytes.is_empty() || script_bytes[script_bytes.len() - 1] != 0xae {
            return None;
        }

        // Look for common patterns:
        // 1-of-2: OP_1 (0x51) ... OP_2 (0x52) OP_CHECKMULTISIG (0xae)
        // 1-of-3: OP_1 (0x51) ... OP_3 (0x53) OP_CHECKMULTISIG (0xae)
        // 2-of-3: OP_2 (0x52) ... OP_3 (0x53) OP_CHECKMULTISIG (0xae)

        // Try to extract pubkeys manually
        let mut pubkeys = Vec::new();
        let mut i = 0;
        let mut required_sigs = 0;
        let mut total_pubkeys = 0;

        // Check for M-of-N signature requirement at start
        if !script_bytes.is_empty() && script_bytes[0] >= 0x51 && script_bytes[0] <= 0x60 {
            required_sigs = (script_bytes[0] - 0x50) as u32;
            i = 1;
        }

        // Extract pubkeys
        while i < script_bytes.len() - 2 {
            // -2 to leave room for N and OP_CHECKMULTISIG
            // Check for pubkey length prefix
            if i >= script_bytes.len() {
                break;
            }

            let len = script_bytes[i] as usize;

            // Valid pubkey lengths are 33 (compressed) or 65 (uncompressed)
            if len == 33 || len == 65 {
                let start = i + 1;
                let end = start + len;

                if end <= script_bytes.len() {
                    let pubkey_hex = hex::encode(&script_bytes[start..end]);

                    // Validate it looks like a pubkey (compressed or uncompressed)
                    let is_valid_pubkey = (len == 33
                        && (script_bytes[start] == 0x02 || script_bytes[start] == 0x03))
                        || (len == 65 && script_bytes[start] == 0x04);

                    if is_valid_pubkey {
                        pubkeys.push(pubkey_hex);
                        i = end;
                    } else {
                        // Not a valid pubkey prefix, skip
                        i += 1;
                    }
                } else {
                    break;
                }
            } else if len > 0 && len < 66 {
                // Arbitrary data push (includes Chancecoin 16-byte, 20-byte, etc.)
                // Accept any reasonable length data segment
                let start = i + 1;
                let end = start + len;
                if end <= script_bytes.len() {
                    let data_hex = hex::encode(&script_bytes[start..end]);
                    pubkeys.push(data_hex);
                    i = end;
                } else {
                    break;
                }
            } else {
                // Invalid/unsupported length, try to skip
                i += 1;
            }
        }

        // Check for N (total pubkeys) before OP_CHECKMULTISIG
        if script_bytes.len() >= 2 {
            let n_byte = script_bytes[script_bytes.len() - 2];
            if (0x51..=0x60).contains(&n_byte) {
                total_pubkeys = (n_byte - 0x50) as u32;
            }
        }

        // Validate we found something that looks like P2MS
        if !pubkeys.is_empty() && total_pubkeys > 0 {
            // If we didn't find required_sigs, assume 1-of-N
            if required_sigs == 0 {
                required_sigs = 1;
            }

            debug!(
                "Parsed nonstandard P2MS: {}-of-{} with {} pubkeys found",
                required_sigs,
                total_pubkeys,
                pubkeys.len()
            );

            use crate::types::script_metadata::MultisigInfo;

            let multisig_info = MultisigInfo {
                pubkeys,
                required_sigs,
                total_pubkeys,
            };

            return Some(TransactionOutput {
                txid: self.txid.clone(),
                vout,
                height: 0,
                amount,
                script_hex: script_hex.to_string(),
                script_type: "nonstandard".to_string(), // Mark as nonstandard
                is_coinbase: false,
                script_size: script_bytes.len(),
                metadata: serde_json::to_value(multisig_info)
                    .unwrap_or_else(|_| serde_json::json!({})),
                address: None, // Address extraction not needed for decoder
            });
        }

        None
    }

    /// Extract OP_RETURN outputs from transaction
    ///
    /// Returns all outputs with OP_RETURN scripts (script_type: "nulldata")
    pub fn op_return_outputs(&self) -> Vec<TransactionOutput> {
        let mut outputs = Vec::new();

        for (vout, output) in self.transaction.output.iter().enumerate() {
            let script_hex = hex::encode(output.script_pubkey.to_bytes());
            let script_bytes = output.script_pubkey.to_bytes();

            // OP_RETURN scripts start with 0x6a
            if !script_bytes.is_empty() && script_bytes[0] == 0x6a {
                // Try to parse OP_RETURN data using shared parser
                if let Some(op_return_data) =
                    crate::types::script_metadata::parse_opreturn_script(&script_hex)
                {
                    outputs.push(TransactionOutput {
                        txid: self.txid.clone(),
                        vout: vout as u32,
                        height: 0,
                        amount: output.value.to_sat(),
                        script_hex: script_hex.clone(),
                        script_type: "nulldata".to_string(), // Bitcoin Core uses "nulldata" for OP_RETURN
                        is_coinbase: false,
                        script_size: script_bytes.len(),
                        metadata: serde_json::to_value(op_return_data)
                            .unwrap_or_else(|_| serde_json::json!({})),
                        address: None, // OP_RETURN has no address
                    });
                }
            }
        }

        outputs
    }

    /// Check if transaction has Exodus address output (for Omni)
    ///
    /// Uses canonical Exodus script constant from types::omni module.
    pub fn has_exodus_address(&self) -> bool {
        use crate::types::omni::is_exodus_script;

        for output in &self.transaction.output {
            let script_bytes = output.script_pubkey.to_bytes();

            if is_exodus_script(&script_bytes) {
                debug!("✅ Exodus address detected in transaction {}", self.txid);
                return true;
            }
        }

        false
    }
}

/// Fetch transaction data from Bitcoin Core RPC
///
/// Returns None if transaction doesn't exist
pub async fn fetch_transaction(
    rpc_client: &BitcoinRpcClient,
    txid: &str,
) -> DecoderResult<Option<TransactionData>> {
    debug!("Fetching transaction: {}", txid);

    let transaction = rpc_client.get_transaction(txid).await?;

    debug!(
        "Transaction {} has {} inputs and {} outputs",
        txid,
        transaction.input.len(),
        transaction.output.len()
    );

    Ok(Some(TransactionData {
        txid: txid.to_string(),
        transaction,
    }))
}

/// Try to decode as Bitcoin Stamps protocol
///
/// Priority: Try AFTER Omni/Chancecoin but BEFORE Counterparty
/// (Stamps can be embedded in Counterparty transactions)
///
/// Returns Some(DecodedProtocol::BitcoinStamps) if:
/// - Transaction has P2MS outputs
/// - Valid Bitcoin Stamps burn patterns detected
/// - ARC4 decryption succeeds
/// - Stamp signature found in decrypted data (any variant: stamp:/STAMP:/stamps:/STAMPS:)
pub fn try_bitcoin_stamps(tx_data: &TransactionData) -> Option<DecodedProtocol> {
    debug!("Trying Bitcoin Stamps decoder for {}", tx_data.txid);

    let p2ms_outputs = tx_data.p2ms_outputs();
    if p2ms_outputs.is_empty() {
        return None;
    }

    let arc4_key = tx_data.arc4_key()?;

    // Try multi-output Bitcoin Stamps processing (production code path)
    if let Some(stamps_result) = validation::process_multioutput_stamps(&p2ms_outputs, &arc4_key) {
        if let Some((offset, variant)) =
            validation::find_stamp_signature(&stamps_result.decrypted_data)
        {
            info!(
                "✅ Bitcoin Stamps detected in {} ({} bytes, signature: {:?} at offset {})",
                tx_data.txid,
                stamps_result.decrypted_data.len(),
                variant,
                offset
            );
            return Some(DecodedProtocol::BitcoinStamps {
                txid: tx_data.txid.clone(),
                decrypted_data: stamps_result.decrypted_data,
                debug_info: None,
            });
        }
    }

    // Try Counterparty-embedded Bitcoin Stamps (Stamps transported via Counterparty)
    if let Some(embedded_result) =
        validation::process_counterparty_embedded_stamps(&p2ms_outputs, &arc4_key)
    {
        if let Some((offset, variant)) =
            validation::find_stamp_signature(&embedded_result.decrypted_data)
        {
            info!(
                "✅ Bitcoin Stamps (via Counterparty transport) detected in {} ({} bytes, signature: {:?} at offset {})",
                tx_data.txid,
                embedded_result.decrypted_data.len(),
                variant,
                offset
            );
            return Some(DecodedProtocol::BitcoinStamps {
                txid: tx_data.txid.clone(),
                decrypted_data: embedded_result.decrypted_data,
                debug_info: None,
            });
        }
    }

    debug!("No Bitcoin Stamps signature found in {}", tx_data.txid);
    None
}

/// Try to decode as Counterparty protocol
///
/// Priority: Try AFTER Bitcoin Stamps to avoid misclassifying Stamps-over-Counterparty
///
/// Returns Some(DecodedProtocol::Counterparty) if:
/// - Transaction has P2MS outputs
/// - P2MS pattern matches Counterparty encoding
/// - ARC4 decryption succeeds
/// - "CNTRPRTY" signature found in decrypted data
/// - NO stamp signature (if any stamp variant found, return BitcoinStamps instead)
pub fn try_counterparty(tx_data: &TransactionData) -> Option<DecodedProtocol> {
    try_counterparty_verbose(tx_data, false)
}

/// Try to decode as Counterparty with optional verbose debug output
pub fn try_counterparty_verbose(
    tx_data: &TransactionData,
    _verbose: bool,
) -> Option<DecodedProtocol> {
    debug!("Trying Counterparty decoder for {}", tx_data.txid);

    let p2ms_outputs = tx_data.p2ms_outputs();
    if p2ms_outputs.is_empty() {
        return None;
    }

    let first_input_txid = tx_data.first_input_txid()?;

    // Use existing Counterparty extraction logic
    let classifier = crate::processor::stage3::counterparty::CounterpartyClassifier::new(
        &crate::types::Stage3Config::default(),
    );

    // Try multi-output extraction first
    if let Some(raw_data) = classifier.extract_multi_output_raw_data(&p2ms_outputs) {
        if let Some(decrypted) =
            classifier.decrypt_counterparty_data_with_txid(&raw_data, &first_input_txid)
        {
            if has_counterparty_signature(&decrypted).is_some() {
                // Check if this is actually Bitcoin Stamps transported via Counterparty
                // Bitcoin Stamps can be embedded in Counterparty Type 20/22 Issuance description fields
                // The description field contains a stamp signature followed by base64 image data
                debug!(
                    "Checking {} bytes of decrypted data for stamp signature",
                    decrypted.len()
                );
                debug!(
                    "First 60 bytes (hex): {}",
                    hex::encode(&decrypted[..decrypted.len().min(60)])
                );
                let stamp_sig = validation::find_stamp_signature(&decrypted);
                debug!("Stamp signature check result: {:?}", stamp_sig);

                if let Some((stamp_offset, variant)) = stamp_sig {
                    info!(
                        "✅ Bitcoin Stamps (via Counterparty transport) detected in {} ({} bytes, signature: {:?} at offset {})",
                        tx_data.txid,
                        decrypted.len(),
                        variant,
                        stamp_offset
                    );
                    // Extract just the stamp signature portion (description field) for Bitcoin Stamps decoder
                    // This removes the Counterparty headers (type, asset_id, etc.)
                    let stamps_data = decrypted[stamp_offset..].to_vec();
                    debug!(
                        "Extracted {} bytes of stamps data starting from stamp signature:",
                        stamps_data.len()
                    );
                    return Some(DecodedProtocol::BitcoinStamps {
                        txid: tx_data.txid.clone(),
                        decrypted_data: stamps_data,
                        debug_info: None,
                    });
                }

                // Pure Counterparty
                info!(
                    "✅ Counterparty detected in {} ({} bytes)",
                    tx_data.txid,
                    decrypted.len()
                );
                return Some(DecodedProtocol::Counterparty {
                    txid: tx_data.txid.clone(),
                    decrypted_data: decrypted,
                    debug_info: None,
                });
            }
        }
    }

    // Try single-output fallback
    let mut all_data = Vec::new();
    for output in &p2ms_outputs {
        if let Some(chunk) = classifier.extract_single_output_raw_data(output) {
            all_data.extend_from_slice(&chunk);
        }
    }

    if !all_data.is_empty() {
        if let Some(decrypted) =
            classifier.decrypt_counterparty_data_with_txid(&all_data, &first_input_txid)
        {
            if has_counterparty_signature(&decrypted).is_some() {
                // Check if this is actually Bitcoin Stamps transported via Counterparty
                // Bitcoin Stamps can be embedded in Counterparty Type 20/22 Issuance description fields
                // The description field contains a stamp signature followed by base64 image data
                debug!(
                    "Checking {} bytes of decrypted data for stamp signature",
                    decrypted.len()
                );
                debug!(
                    "First 60 bytes (hex): {}",
                    hex::encode(&decrypted[..decrypted.len().min(60)])
                );
                let stamp_sig = validation::find_stamp_signature(&decrypted);
                debug!("Stamp signature check result: {:?}", stamp_sig);

                if let Some((stamp_offset, variant)) = stamp_sig {
                    info!(
                        "✅ Bitcoin Stamps (via Counterparty transport) detected in {} ({} bytes, signature: {:?} at offset {})",
                        tx_data.txid,
                        decrypted.len(),
                        variant,
                        stamp_offset
                    );
                    // Extract just the stamp signature portion (description field) for Bitcoin Stamps decoder
                    // This removes the Counterparty headers (type, asset_id, etc.)
                    let stamps_data = decrypted[stamp_offset..].to_vec();
                    debug!(
                        "Extracted {} bytes of stamps data starting from stamp signature:",
                        stamps_data.len()
                    );
                    return Some(DecodedProtocol::BitcoinStamps {
                        txid: tx_data.txid.clone(),
                        decrypted_data: stamps_data,
                        debug_info: None,
                    });
                }

                // Pure Counterparty
                info!(
                    "✅ Counterparty detected in {} ({} bytes)",
                    tx_data.txid,
                    decrypted.len()
                );
                return Some(DecodedProtocol::Counterparty {
                    txid: tx_data.txid.clone(),
                    decrypted_data: decrypted,
                    debug_info: None,
                });
            }
        }
    }

    debug!("No Counterparty signature found in {}", tx_data.txid);
    None
}

/// Try to decode as Omni Layer protocol
///
/// Priority: Try FIRST (exclusive transport via Exodus address)
///
/// Omni Layer uses exclusive Exodus address outputs:
/// 1. Check for Exodus address (see `types::omni::EXODUS_ADDRESS`) in outputs
/// 2. Extract data from P2MS outputs (Omni uses Class B encoding with SHA256 obfuscation)
/// 3. Deobfuscate using sender address and sequence number detection
/// 4. Return Some(DecodedProtocol::Omni) if valid
pub async fn try_omni(
    tx_data: &TransactionData,
    rpc_client: &BitcoinRpcClient,
) -> Option<DecodedProtocol> {
    // Step 1: Check for Exodus address (required for Omni)
    if !tx_data.has_exodus_address() {
        return None;
    }

    debug!(
        "✅ Exodus address found in {}, trying Omni decode",
        tx_data.txid
    );

    // Step 2: Extract P2MS outputs
    let p2ms_outputs = tx_data.p2ms_outputs();
    if p2ms_outputs.is_empty() {
        debug!("No P2MS outputs found");
        return None;
    }

    // Step 3: Get sender address from largest input
    let sender_address = rpc_client
        .get_sender_address_from_largest_input(&tx_data.transaction)
        .await
        .ok()
        .flatten()?;

    debug!("Sender address for Omni deobfuscation: {}", sender_address);

    // Step 4: Extract raw packets from P2MS outputs
    let mut raw_packets = extract_p2ms_packets_no_sequence(&p2ms_outputs)?;

    debug!("Extracted {} raw Omni packets", raw_packets.len());

    // Step 5: Deobfuscate with sequence detection (brute-force 1-255)
    deobfuscate_packets_with_sequence_detection(&mut raw_packets, &sender_address)?;

    // Step 6: Sort by sequence and concatenate payloads
    raw_packets.sort_by_key(|p| p.sequence_number);

    let mut combined_data = Vec::new();
    for packet in &raw_packets {
        if let Some(deobfuscated) = &packet.deobfuscated_data {
            // Skip the sequence byte (first byte), take payload (remaining 30 bytes)
            combined_data.extend_from_slice(&deobfuscated[1..]);
        }
    }

    // Step 7: Parse Omni message header (version + message type)
    if combined_data.len() < 4 {
        debug!("Omni data too short: {} bytes", combined_data.len());
        return None;
    }

    let version = u16::from_be_bytes([combined_data[0], combined_data[1]]);
    let message_type = u16::from_be_bytes([combined_data[2], combined_data[3]]);

    debug!(
        "✅ Omni detected: version={}, message_type={}",
        version, message_type
    );

    Some(DecodedProtocol::Omni {
        txid: tx_data.txid.clone(),
        decrypted_data: combined_data,
        sender_address,
        packet_count: raw_packets.len() as u8,
        debug_info: None,
    })
}

/// Omni packet structure (31 bytes from P2MS pubkey)
#[derive(Debug, Clone)]
struct OmniPacket {
    vout: u32,
    position: u8, // 2 or 3 (P2MS pubkey position)
    sequence_number: u8,
    obfuscated_data: [u8; 31],
    deobfuscated_data: Option<[u8; 31]>,
}

/// Extract P2MS packets from pubkey positions 2 and 3 (Omni Class B format)
fn extract_p2ms_packets_no_sequence(p2ms_outputs: &[TransactionOutput]) -> Option<Vec<OmniPacket>> {
    let mut packets = Vec::new();

    for output in p2ms_outputs {
        // Omni uses pubkeys at positions 2 and 3 (indices 1 and 2)
        if let Some(multisig_info) = output.multisig_info() {
            if multisig_info.pubkeys.len() > 1 {
                if let Some(packet) =
                    extract_packet_from_pubkey(&multisig_info.pubkeys[1], output.vout, 2)
                {
                    packets.push(packet);
                }
            }
            if multisig_info.pubkeys.len() > 2 {
                if let Some(packet) =
                    extract_packet_from_pubkey(&multisig_info.pubkeys[2], output.vout, 3)
                {
                    packets.push(packet);
                }
            }
        }
    }

    if packets.is_empty() {
        None
    } else {
        Some(packets)
    }
}

/// Extract 31-byte packet from compressed pubkey
fn extract_packet_from_pubkey(pubkey_hex: &str, vout: u32, position: u8) -> Option<OmniPacket> {
    let pubkey_bytes = hex::decode(pubkey_hex).ok()?;

    // Compressed pubkey must be 33 bytes
    if pubkey_bytes.len() != 33 {
        return None;
    }

    // Extract 31 bytes (skip first byte, take next 31, drop last byte)
    let mut obfuscated_data = [0u8; 31];
    obfuscated_data.copy_from_slice(&pubkey_bytes[1..32]);

    Some(OmniPacket {
        vout,
        position,
        sequence_number: 0, // Unknown until deobfuscation
        obfuscated_data,
        deobfuscated_data: None,
    })
}

/// Deobfuscate Omni packets with sequence number detection
///
/// Tries all possible sequence numbers (1-255) and checks if the first byte
/// matches the sequence number after deobfuscation.
fn deobfuscate_packets_with_sequence_detection(
    packets: &mut [OmniPacket],
    sender_address: &str,
) -> Option<()> {
    use sha2::{Digest, Sha256};

    let mut success_count = 0;

    for packet in packets.iter_mut() {
        for seq in 1..=255u8 {
            // Generate deobfuscation key via SHA256 chain
            let mut hash_input = sender_address.as_bytes().to_vec();
            let mut last_digest: Option<[u8; 32]> = None;

            for _ in 0..seq {
                let mut hasher = Sha256::new();
                hasher.update(&hash_input);
                let digest = hasher.finalize();

                // Save this digest - the LAST one will be our deobfuscation key
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&digest);
                last_digest = Some(arr);

                // Next iteration uses hex-encoded uppercase hash
                let hex_string = hex::encode_upper(digest);
                hash_input = hex_string.as_bytes().to_vec();
            }

            // The last digest from the loop IS the deobfuscation key
            let final_hash = last_digest?;
            let deobfuscation_key = &final_hash[..31];

            // XOR to deobfuscate
            let mut deobfuscated = [0u8; 31];
            for i in 0..31 {
                deobfuscated[i] = packet.obfuscated_data[i] ^ deobfuscation_key[i];
            }

            // Check if first byte matches sequence number
            if deobfuscated[0] == seq {
                packet.sequence_number = seq;
                packet.deobfuscated_data = Some(deobfuscated);
                success_count += 1;
                debug!(
                    "✅ Packet at vout {} position {} deobfuscated with sequence {}",
                    packet.vout, packet.position, seq
                );
                break;
            }
        }
    }

    if success_count == 0 {
        None
    } else {
        Some(())
    }
}

/// Check for Counterparty signature in decrypted data
pub fn has_counterparty_signature(data: &[u8]) -> Option<usize> {
    if data.len() < COUNTERPARTY_PREFIX.len() {
        return None;
    }

    // Check for CNTRPRTY prefix at the beginning
    if data.starts_with(COUNTERPARTY_PREFIX) {
        return Some(0);
    }

    // Check for CNTRPRTY prefix at offset 1 (after 1-byte length/format indicator)
    // Modern Counterparty messages may have a 1-byte prefix before CNTRPRTY
    if data.len() > COUNTERPARTY_PREFIX.len()
        && &data[1..1 + COUNTERPARTY_PREFIX.len()] == COUNTERPARTY_PREFIX
    {
        return Some(1);
    }

    // Search for the prefix at other positions
    (0..=data.len().saturating_sub(COUNTERPARTY_PREFIX.len()))
        .find(|&i| data[i..].starts_with(COUNTERPARTY_PREFIX))
}

/// Try to classify as LikelyDataStorage using shared detection logic
///
/// Uses unified detection module to ensure consistency with Stage 3 (classification).
///
/// **Detects three patterns**:
/// 1. InvalidECPoint - ≥1 pubkey fails secp256k1 validation
/// 2. HighOutputCount - ≥5 P2MS outputs with ALL valid EC points
/// 3. DustAmount - ALL outputs ≤1000 sats with ALL valid EC points
///
/// Returns `Some(DecodedProtocol::LikelyDataStorage)` if a pattern is detected.
pub fn try_likely_data_storage(tx_data: &TransactionData) -> Option<DecodedProtocol> {
    use crate::detection::likely_data_storage::{detect, LikelyDataStorageVariant};
    use tracing::debug;

    // Get P2MS outputs (returns Vec<TransactionOutput> - same type as Stage 3)
    let p2ms_outputs = tx_data.p2ms_outputs();

    // Single call to unified detection logic (shared with Stage 3)
    if let Some(result) = detect(&p2ms_outputs) {
        // Map shared variant to pattern_type string (exact match with Stage 3)
        let pattern_type = match result.variant {
            LikelyDataStorageVariant::InvalidECPoint => "InvalidECPoint",
            LikelyDataStorageVariant::HighOutputCount => "HighOutputCount",
            LikelyDataStorageVariant::DustAmount => "DustAmount",
        };

        debug!(
            "Transaction {} classified as LikelyDataStorage ({}): {}",
            tx_data.txid, pattern_type, result.details
        );

        return Some(DecodedProtocol::LikelyDataStorage {
            txid: tx_data.txid.clone(),
            pattern_type: pattern_type.to_string(),
            details: result.details,
            debug_info: None,
        });
    }

    None
}

/// Try to classify as likely legitimate multisig based on public key validation
///
/// Returns Some(DecodedProtocol::LikelyLegitimateMultisig) if ALL public keys are valid EC points.
pub fn try_likely_legitimate_p2ms(tx_data: &TransactionData) -> Option<DecodedProtocol> {
    use crate::analysis::validate_from_metadata;

    let p2ms_outputs = tx_data.p2ms_outputs();
    if p2ms_outputs.is_empty() {
        return None;
    }

    // Validate all outputs - aggregate results
    let mut all_valid = true;
    let mut has_any_duplicates = false;

    for output in &p2ms_outputs {
        if let Some(validation) = validate_from_metadata(&output.metadata) {
            if !validation.all_valid_ec_points {
                all_valid = false;
                break; // One invalid key means NOT legitimate
            }
            if validation.has_duplicate_keys {
                has_any_duplicates = true;
            }
        }
    }

    // Only classify as likely legitimate if ALL keys are valid
    if all_valid {
        Some(DecodedProtocol::LikelyLegitimateMultisig {
            txid: tx_data.txid.clone(),
            validation_summary: if has_any_duplicates {
                "All valid EC points, duplicate keys detected".to_string()
            } else {
                "All valid EC points, standard multisig".to_string()
            },
            has_duplicates: has_any_duplicates,
            debug_info: None,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counterparty_signature_detection() {
        let mut data_with_cntrprty = b"CNTRPRTY".to_vec();
        data_with_cntrprty.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(has_counterparty_signature(&data_with_cntrprty), Some(0));

        let data_without_cntrprty = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(has_counterparty_signature(&data_without_cntrprty), None);
    }
}
