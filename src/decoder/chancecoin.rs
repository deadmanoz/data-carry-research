//! Chancecoin Protocol Decoder
//!
//! Chancecoin is a gambling protocol built on Bitcoin that uses P2MS outputs
//! for data storage. It does NOT use obfuscation.
//!
//! Key characteristics:
//! - 1-of-2 or 1-of-3 multisig structure
//! - Data split across multiple P2MS outputs (32 bytes per chunk)
//! - Each chunk has length prefix (first byte = actual data size)
//! - Message format: [CHANCECO:8][MessageID:4][Data:variable]
//!
//! Data Encoding (from Blocks.java:782-800):
//! ```java
//! for (int i = 0; i < dataArrayList.size(); i+=32) {
//!     // Extract chunk (max 32 bytes)
//!     List<Byte> chunk = dataArrayList.subList(i, Math.min(i+32, dataArrayList.size()));
//!
//!     // Prepend length byte
//!     chunk.add(0, (byte) chunk.size());
//!
//!     // Pad to 33 bytes
//!     while (chunk.size()<32+1) chunk.add((byte) 0);
//!
//!     // Create MULTISIG with data as "pubkey"
//!     keys.add(new ECKey(null, chunk));
//!     Script script = ScriptBuilder.createMultiSigOutputScript(1, keys);
//! }
//! ```
//!
//! References:
//! - https://github.com/chancecoin/chancecoinj/blob/master/src/Bet.java
//! - https://github.com/chancecoin/chancecoinj/blob/master/src/Blocks.java
//!
//! NOTE: Message parsing logic has been moved here from types/chancecoin.rs
//! to maintain separation of concerns (types vs business logic).

use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

use crate::decoder::protocol_detection::{DecodedProtocol, TransactionData};
use crate::types::chancecoin::{
    ChancecoinMessage, ChancecoinMessageContent, ChancecoinMessageType, CHANCECOIN_SIGNATURE,
};
use tracing::{debug, info, warn};

// ===== MESSAGE PARSING FUNCTIONS =====
// These were moved from types/chancecoin.rs to maintain separation of concerns.

/// Parse raw Chancecoin data into a ChancecoinMessage
///
/// Expected format:
/// - Bytes 0-7: "CHANCECO" signature
/// - Bytes 8-11: Message ID (4-byte big-endian u32)
/// - Bytes 12+: Message-specific data
pub fn parse_chancecoin_message(txid: String, raw_data: Vec<u8>) -> Option<ChancecoinMessage> {
    // Verify signature
    if raw_data.len() < 8 || &raw_data[..8] != CHANCECOIN_SIGNATURE {
        return None;
    }

    // Need at least signature + message_id
    if raw_data.len() < 12 {
        return None;
    }

    // Extract message ID (4 bytes after signature, big-endian)
    let mut cursor = Cursor::new(&raw_data[8..12]);
    let message_id = cursor.read_u32::<BigEndian>().ok()?;

    // Determine message type
    let message_type = ChancecoinMessageType::from_id(message_id);

    // Extract message data (after signature + message_id)
    let data = if raw_data.len() > 12 {
        raw_data[12..].to_vec()
    } else {
        Vec::new()
    };

    // Parse message content based on type
    let content = parse_content(&message_type, &data);

    Some(ChancecoinMessage {
        txid,
        message_id,
        message_type,
        content,
        data,
        raw_data,
    })
}

/// Parse message content based on message type
fn parse_content(message_type: &ChancecoinMessageType, data: &[u8]) -> ChancecoinMessageContent {
    match message_type {
        ChancecoinMessageType::Send => {
            parse_send(data).unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec()))
        }
        ChancecoinMessageType::Order => {
            parse_order(data).unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec()))
        }
        ChancecoinMessageType::BTCPay => {
            parse_btcpay(data).unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec()))
        }
        ChancecoinMessageType::Roll => {
            parse_roll(data).unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec()))
        }
        ChancecoinMessageType::DiceBet => {
            parse_dice_bet(data).unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec()))
        }
        ChancecoinMessageType::PokerBet => {
            parse_poker_bet(data).unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec()))
        }
        ChancecoinMessageType::Cancel => {
            parse_cancel(data).unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec()))
        }
        ChancecoinMessageType::Unknown => ChancecoinMessageContent::Raw(data.to_vec()),
    }
}

/// Parse Send message data
///
/// Format (from Send.java:77-80):
/// - Bytes 0-7: assetId (8-byte long)
/// - Bytes 8-15: amount (8-byte long)
fn parse_send(data: &[u8]) -> Option<ChancecoinMessageContent> {
    if data.len() < 16 {
        return None;
    }

    let mut cursor = Cursor::new(data);
    let asset_id = cursor.read_u64::<BigEndian>().ok()?;
    let amount = cursor.read_u64::<BigEndian>().ok()?;

    Some(ChancecoinMessageContent::Send { asset_id, amount })
}

/// Parse Order message data
///
/// Format (from Order.java:90-97):
/// - Bytes 0-7: giveId (8-byte long)
/// - Bytes 8-15: giveAmount (8-byte long)
/// - Bytes 16-23: getId (8-byte long)
/// - Bytes 24-31: getAmount (8-byte long)
/// - Bytes 32-33: expiration (2-byte short)
/// - Bytes 34-41: feeRequired (8-byte long)
fn parse_order(data: &[u8]) -> Option<ChancecoinMessageContent> {
    if data.len() < 42 {
        return None;
    }

    let mut cursor = Cursor::new(data);
    let give_id = cursor.read_u64::<BigEndian>().ok()?;
    let give_amount = cursor.read_u64::<BigEndian>().ok()?;
    let get_id = cursor.read_u64::<BigEndian>().ok()?;
    let get_amount = cursor.read_u64::<BigEndian>().ok()?;
    let expiration = cursor.read_u16::<BigEndian>().ok()?;
    let fee_required = cursor.read_u64::<BigEndian>().ok()?;

    Some(ChancecoinMessageContent::Order {
        give_id,
        give_amount,
        get_id,
        get_amount,
        expiration,
        fee_required,
    })
}

/// Parse BTCPay message data
///
/// Format (from BTCPay.java:121-124):
/// - Bytes 0-31: tx0Hash (32 bytes)
/// - Bytes 32-63: tx1Hash (32 bytes)
fn parse_btcpay(data: &[u8]) -> Option<ChancecoinMessageContent> {
    if data.len() < 64 {
        return None;
    }

    let tx0_hash = hex::encode(&data[0..32]);
    let tx1_hash = hex::encode(&data[32..64]);

    Some(ChancecoinMessageContent::BTCPay { tx0_hash, tx1_hash })
}

/// Parse Roll message data
///
/// Format (from Roll.java:144-156):
/// Version 1: rollTxHash (32) + roll (8) = 40 bytes
/// Version 2: rollTxHash (32) + roll (8) + chaAmount (8) = 48 bytes
fn parse_roll(data: &[u8]) -> Option<ChancecoinMessageContent> {
    if data.len() < 40 {
        return None;
    }

    let roll_tx_hash = hex::encode(&data[0..32]);

    let mut cursor = Cursor::new(&data[32..]);
    let roll = cursor.read_f64::<BigEndian>().ok()?;

    let cha_amount = if data.len() >= 48 {
        cursor.read_u64::<BigEndian>().ok()
    } else {
        None
    };

    Some(ChancecoinMessageContent::Roll {
        roll_tx_hash,
        roll,
        cha_amount,
    })
}

/// Parse Cancel message data
///
/// Format (from Cancel.java:83-85):
/// - Bytes 0-31: offerHash (32 bytes)
fn parse_cancel(data: &[u8]) -> Option<ChancecoinMessageContent> {
    if data.len() < 32 {
        return None;
    }

    let offer_hash = hex::encode(&data[0..32]);

    Some(ChancecoinMessageContent::Cancel { offer_hash })
}

/// Parse Dice bet data
///
/// Format (from Bet.java:342-346):
/// - Bytes 0-7: bet amount (8-byte long)
/// - Bytes 8-15: chance (8-byte double, 0-100)
/// - Bytes 16-23: payout multiplier (8-byte double)
fn parse_dice_bet(data: &[u8]) -> Option<ChancecoinMessageContent> {
    if data.len() < 24 {
        return None;
    }

    let mut cursor = Cursor::new(data);

    let bet = cursor.read_u64::<BigEndian>().ok()?;
    let chance = cursor.read_f64::<BigEndian>().ok()?;
    let payout = cursor.read_f64::<BigEndian>().ok()?;

    Some(ChancecoinMessageContent::DiceBet {
        bet,
        chance,
        payout,
    })
}

/// Parse Poker bet data
///
/// Format (from Bet.java:422-428):
/// - Bytes 0-7: bet amount (8-byte long)
/// - Bytes 8-25: 9 cards (each 2-byte short)
///   - Cards 0-1: Player cards
///   - Cards 2-6: Board cards
///   - Cards 7-8: Opponent cards
fn parse_poker_bet(data: &[u8]) -> Option<ChancecoinMessageContent> {
    if data.len() < 26 {
        return None;
    }

    let mut cursor = Cursor::new(data);

    let bet = cursor.read_u64::<BigEndian>().ok()?;

    let mut cards = Vec::with_capacity(9);
    for _ in 0..9 {
        let card = cursor.read_u16::<BigEndian>().ok()?;
        cards.push(card);
    }

    Some(ChancecoinMessageContent::PokerBet { bet, cards })
}

// ===== DECODER FUNCTIONS =====

/// Try to decode transaction as Chancecoin
///
/// Returns Some(DecodedProtocol::Chancecoin) if valid Chancecoin data found
pub fn try_chancecoin(tx_data: &TransactionData) -> Option<DecodedProtocol> {
    debug!("Attempting Chancecoin decode for txid: {}", tx_data.txid);

    let p2ms_outputs = tx_data.p2ms_outputs();
    if p2ms_outputs.is_empty() {
        debug!("No P2MS outputs found");
        return None;
    }

    // Extract and concatenate all data chunks from P2MS outputs
    let concatenated_data = extract_and_concatenate_chunks(&p2ms_outputs, &tx_data.txid)?;

    // Verify Chancecoin signature
    if concatenated_data.len() < 8 || &concatenated_data[..8] != CHANCECOIN_SIGNATURE {
        debug!("No Chancecoin signature found in concatenated data");
        return None;
    }

    info!("✅ Chancecoin signature detected!");
    info!("   • Total data length: {} bytes", concatenated_data.len());

    // Create Chancecoin message using parser
    match parse_chancecoin_message(tx_data.txid.clone(), concatenated_data) {
        Some(message) => {
            info!("🎰 Chancecoin Message Decoded:");
            info!("   • Transaction: {}", tx_data.txid);
            info!("   • Message ID: {}", message.message_id);
            info!("   • Message Type: {}", message.message_type.description());
            info!("   • Summary: {}", message.summary());

            Some(DecodedProtocol::Chancecoin {
                txid: tx_data.txid.clone(),
                message,
                debug_info: None,
            })
        }
        None => {
            warn!(
                "Found Chancecoin signature but failed to create message (txid: {})",
                tx_data.txid
            );
            None
        }
    }
}

/// Extract data chunks from all P2MS outputs and concatenate them
///
/// Each P2MS output contains data in the second pubkey slot (index 1).
/// The data format is:
/// - Byte 0: Length of actual data (1-32)
/// - Bytes 1-N: Actual data
/// - Bytes N+1-32: Padding zeros (total 33 bytes)
///
/// This function:
/// 1. Extracts data from each P2MS output's second pubkey
/// 2. Strips the length prefix (first byte)
/// 3. Strips trailing padding zeros
/// 4. Concatenates all chunks in order
fn extract_and_concatenate_chunks(
    p2ms_outputs: &[crate::types::TransactionOutput],
    _txid: &str,
) -> Option<Vec<u8>> {
    let mut all_chunks = Vec::new();

    debug!("Extracting chunks from {} P2MS outputs", p2ms_outputs.len());

    for (output_idx, output) in p2ms_outputs.iter().enumerate() {
        // Chancecoin uses 1-of-2 or 1-of-3 multisig
        // Data is in the second pubkey slot (index 1)
        let info = match output.multisig_info() {
            Some(i) => i,
            None => {
                debug!("Output {} has no multisig info, skipping", output_idx);
                continue;
            }
        };

        if info.pubkeys.len() < 2 {
            debug!("Output {} has < 2 pubkeys, skipping", output_idx);
            continue;
        }

        let data_hex = &info.pubkeys[1];
        let data_bytes = match hex::decode(data_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                debug!("Failed to decode hex for output {}: {}", output_idx, e);
                continue;
            }
        };

        // Extract chunk with length prefix stripping
        if let Some(chunk) = extract_chunk(&data_bytes, output_idx) {
            debug!(
                "Output {}: extracted {} bytes (original {} bytes)",
                output_idx,
                chunk.len(),
                data_bytes.len()
            );
            all_chunks.push(chunk);
        }
    }

    if all_chunks.is_empty() {
        debug!("No valid chunks extracted");
        return None;
    }

    // Concatenate all chunks
    let concatenated: Vec<u8> = all_chunks.into_iter().flatten().collect();
    debug!("Total concatenated data: {} bytes", concatenated.len());

    Some(concatenated)
}

/// Extract and strip a single data chunk
///
/// Format:
/// - Byte 0: Length indicator (1-32)
/// - Bytes 1-N: Actual data
/// - Bytes N+1-32: Padding zeros
///
/// Returns: The actual data without length prefix or padding
fn extract_chunk(data: &[u8], output_idx: usize) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }

    // Check if this has a length prefix (typical format)
    let length = data[0] as usize;

    debug!(
        "Output {}: length prefix = {}, data size = {}",
        output_idx,
        length,
        data.len()
    );

    // Validate length prefix
    if length > 32 || length == 0 {
        // No valid length prefix - might be raw data
        debug!(
            "Output {}: Invalid length prefix, trying raw extraction",
            output_idx
        );

        // Try to extract without length prefix
        // Look for Chancecoin signature to determine if this is start of data
        if data.len() >= 8 && &data[0..8] == CHANCECOIN_SIGNATURE {
            debug!(
                "Output {}: Found signature at start (no length prefix)",
                output_idx
            );
            return Some(data.to_vec());
        }

        return None;
    }

    // Extract actual data (skip length prefix, take 'length' bytes)
    let end_pos = std::cmp::min(1 + length, data.len());
    let chunk = data[1..end_pos].to_vec();

    debug!(
        "Output {}: extracted chunk {} bytes (length prefix indicated {})",
        output_idx,
        chunk.len(),
        length
    );

    Some(chunk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use corepc_client::bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Txid};
    use std::str::FromStr;

    /// Create a test transaction with Chancecoin data across multiple outputs
    fn create_multi_output_transaction(chunks: Vec<Vec<u8>>) -> TransactionData {
        let txid =
            Txid::from_str("a9b505f1edb8fedaa7c1edb96cdd622b72b0623b1a5fafa7a1eac97f1a377889")
                .unwrap();

        let real_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        let mut outputs = Vec::new();

        for chunk in chunks {
            // Create length-prefixed chunk (as Chancecoin does)
            let mut prefixed_chunk = vec![chunk.len() as u8];
            prefixed_chunk.extend_from_slice(&chunk);

            // Pad to 33 bytes
            while prefixed_chunk.len() < 33 {
                prefixed_chunk.push(0);
            }

            // Build P2MS script: OP_1 <real_pubkey> <data_chunk> OP_2 OP_CHECKMULTISIG
            let mut script_bytes = vec![0x51]; // OP_1

            // Add first pubkey (real)
            let pubkey1_bytes = hex::decode(real_pubkey).unwrap();
            script_bytes.push(pubkey1_bytes.len() as u8);
            script_bytes.extend_from_slice(&pubkey1_bytes);

            // Add second pubkey (Chancecoin data chunk)
            script_bytes.push(prefixed_chunk.len() as u8);
            script_bytes.extend_from_slice(&prefixed_chunk);

            script_bytes.push(0x52); // OP_2
            script_bytes.push(0xae); // OP_CHECKMULTISIG

            outputs.push(TxOut {
                value: Amount::from_sat(780), // Dust size
                script_pubkey: ScriptBuf::from_bytes(script_bytes),
            });
        }

        // Add dummy input
        let input = TxIn {
            previous_output: corepc_client::bitcoin::OutPoint {
                txid: Txid::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: corepc_client::bitcoin::Sequence::MAX,
            witness: corepc_client::bitcoin::Witness::new(),
        };

        let transaction = Transaction {
            version: corepc_client::bitcoin::transaction::Version::TWO,
            lock_time: corepc_client::bitcoin::absolute::LockTime::ZERO,
            input: vec![input],
            output: outputs,
        };

        TransactionData {
            txid: txid.to_string(),
            transaction,
        }
    }

    #[test]
    fn test_chancecoin_multi_output_concatenation() {
        // Create a Dice bet message split across 2 outputs
        // Message: CHANCECO(8) + MessageID(4) + bet(8) + chance(8) + payout(8) = 36 bytes

        let mut full_message = Vec::new();
        full_message.extend_from_slice(b"CHANCECO"); // 8 bytes
        full_message.extend_from_slice(&40u32.to_be_bytes()); // Message ID (Dice)
        full_message.extend_from_slice(&1000u64.to_be_bytes()); // Bet
        full_message.extend_from_slice(&50.0f64.to_be_bytes()); // Chance
        full_message.extend_from_slice(&2.0f64.to_be_bytes()); // Payout

        // Split into two chunks (32 bytes + 4 bytes)
        let chunk1 = full_message[..32].to_vec();
        let chunk2 = full_message[32..].to_vec();

        let tx_data = create_multi_output_transaction(vec![chunk1, chunk2]);
        let result = try_chancecoin(&tx_data);

        assert!(
            result.is_some(),
            "Should decode Chancecoin from multiple outputs"
        );

        match result.unwrap() {
            DecodedProtocol::Chancecoin {
                txid,
                message,
                debug_info: _,
            } => {
                assert_eq!(txid, tx_data.txid);
                assert_eq!(message.message_id, 40);

                // Verify dice bet parsing
                match message.content {
                    crate::types::chancecoin::ChancecoinMessageContent::DiceBet {
                        bet,
                        chance,
                        payout,
                    } => {
                        assert_eq!(bet, 1000);
                        assert_eq!(chance, 50.0);
                        assert_eq!(payout, 2.0);
                    }
                    _ => panic!("Expected DiceBet content"),
                }
            }
            _ => panic!("Expected Chancecoin protocol"),
        }
    }

    #[test]
    fn test_chancecoin_single_output() {
        // Create a short message in single output
        let mut message = Vec::new();
        message.extend_from_slice(b"CHANCECO");
        message.extend_from_slice(&40u32.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0]); // Minimal data

        let tx_data = create_multi_output_transaction(vec![message]);
        let result = try_chancecoin(&tx_data);

        assert!(
            result.is_some(),
            "Should decode Chancecoin from single output"
        );
    }

    #[test]
    fn test_non_chancecoin_data() {
        // Random data without Chancecoin signature
        let random_data = b"RANDOMDATA1234567890".to_vec();
        let tx_data = create_multi_output_transaction(vec![random_data]);

        let result = try_chancecoin(&tx_data);
        assert!(result.is_none(), "Should not detect non-Chancecoin data");
    }
}
