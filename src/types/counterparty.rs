use super::ProtocolVariant;
use serde::{Deserialize, Serialize};

// Core protocol constants (Source: counterpartycore/lib/config.py)
pub const COUNTERPARTY_PREFIX: &[u8] = b"CNTRPRTY"; // 8-byte protocol identifier

/// Message type definitions from Counterparty Core codebase
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CounterpartyMessageType {
    Send = 0,         // versions/send1.py:15 - Basic asset transfer
    EnhancedSend = 2, // versions/enhancedsend.py:18 - Enhanced send with memo field
    Mpma = 3,         // versions/mpma.py:18 - Multi-peer multi-asset send
    Sweep = 4,        // sweep.py:20 - Sweep transaction
    Order = 10,       // order.py:21 - DEX order
    BtcPay = 11,      // btcpay.py:18 - BTC payment for DEX
    Dispenser = 12,   // dispenser.py:28 - Asset dispenser
    Issuance = 20,    // issuance.py:25 - Asset creation/issuance
    Broadcast = 30,   // broadcast.py:46 - Oracle broadcast
    Bet = 40,         // bet.py:33 - Betting transaction
    Dividend = 50,    // dividend.py:23 - Dividend payment
    Burn = 60,        // burn.py:15 - XCP burn transaction
    Cancel = 70,      // cancel.py:18 - Cancel order/bet
    Rps = 80,         // rps.py:30 - Rock paper scissors
    RpsResolve = 81,  // rpsresolve.py:10 - RPS resolution
    FairMinter = 90,  // fairminter.py:15 - Fair minter creation
    FairMint = 91,    // fairmint.py:14 - Fair mint transaction
    Utxo = 100,       // utxo.py:12 - UTXO transaction
    Attach = 101,     // attach.py:12 - Attach to UTXO
    Detach = 102,     // detach.py:10 - Detach from UTXO
    Destroy = 110,    // destroy.py:15 - Destroy asset
}

impl CounterpartyMessageType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Send),
            2 => Some(Self::EnhancedSend),
            3 => Some(Self::Mpma),
            4 => Some(Self::Sweep),
            10 => Some(Self::Order),
            11 => Some(Self::BtcPay),
            12 => Some(Self::Dispenser),
            20 => Some(Self::Issuance), // Legacy issuance
            21 => Some(Self::Issuance), // Subasset issuance (2023+ format)
            22 => Some(Self::Issuance), // Modern issuance (SKYROCK transaction)
            30 => Some(Self::Broadcast),
            40 => Some(Self::Bet),
            50 => Some(Self::Dividend),
            60 => Some(Self::Burn),
            70 => Some(Self::Cancel),
            80 => Some(Self::Rps),
            81 => Some(Self::RpsResolve),
            90 => Some(Self::FairMinter),
            91 => Some(Self::FairMint),
            100 => Some(Self::Utxo),
            101 => Some(Self::Attach),
            102 => Some(Self::Detach),
            110 => Some(Self::Destroy),
            _ => None,
        }
    }

    pub fn get_variant(&self) -> ProtocolVariant {
        match self {
            // Asset Transfers - Moving value between parties
            Self::Send => ProtocolVariant::CounterpartyTransfer,
            Self::EnhancedSend => ProtocolVariant::CounterpartyTransfer,
            Self::Mpma => ProtocolVariant::CounterpartyTransfer,
            Self::Sweep => ProtocolVariant::CounterpartyTransfer,
            Self::Dividend => ProtocolVariant::CounterpartyTransfer,

            // Asset Creation - Creating new assets
            Self::Issuance => ProtocolVariant::CounterpartyIssuance,
            Self::FairMinter => ProtocolVariant::CounterpartyIssuance,
            Self::FairMint => ProtocolVariant::CounterpartyIssuance,

            // Asset Destruction - Burning/destroying assets
            Self::Destroy => ProtocolVariant::CounterpartyDestruction,
            Self::Burn => ProtocolVariant::CounterpartyDestruction,

            // Decentralised Exchange
            Self::Order => ProtocolVariant::CounterpartyDEX,
            Self::BtcPay => ProtocolVariant::CounterpartyDEX,
            Self::Dispenser => ProtocolVariant::CounterpartyDEX,
            Self::Cancel => ProtocolVariant::CounterpartyDEX,

            // Oracle/Broadcasting
            Self::Broadcast => ProtocolVariant::CounterpartyOracle,

            // Gaming/Betting
            Self::Bet => ProtocolVariant::CounterpartyGaming,
            Self::Rps => ProtocolVariant::CounterpartyGaming,
            Self::RpsResolve => ProtocolVariant::CounterpartyGaming,

            // UTXO Technical Operations
            Self::Utxo => ProtocolVariant::CounterpartyUtility,
            Self::Attach => ProtocolVariant::CounterpartyUtility,
            Self::Detach => ProtocolVariant::CounterpartyUtility,
        }
    }
}

/// P2MS-specific data extraction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterpartyP2msData {
    pub raw_data: Vec<u8>,
    pub decrypted_data: Vec<u8>,
    pub vout_index: u32,
    pub message_type: CounterpartyMessageType,
    pub payload: Vec<u8>,
    pub multisig_pattern: MultisigPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultisigPattern {
    // === PRIMARY PATTERNS (99%+ of UTXO set) ===
    OneOfTwo {
        // 1-of-2: 1 <source> <data> 2 OP_CHECKMULTISIG
        data_capacity: usize,
    },
    OneOfThree {
        // 1-of-3: 1 <data1> <data2> <source> 3 OP_CHECKMULTISIG
        data_capacity: usize,
    },

    // === COMPLETE COVERAGE PATTERNS ===
    TwoOfTwo {
        // 2-of-2: 2 <source> <data> 2 OP_CHECKMULTISIG
        data_capacity: usize,
    },
    TwoOfThree {
        // 2-of-3: 2 <data1> <data2> <source> 3 OP_CHECKMULTISIG
        data_capacity: usize,
    },
    ThreeOfThree {
        // 3-of-3: 3 <data1> <data2> <source> 3 OP_CHECKMULTISIG
        data_capacity: usize,
    },
    ThreeOfTwo {
        // 3-of-2: 3 <source> <data> 2 OP_CHECKMULTISIG
        data_capacity: usize,
    },

    // Multi-output data combination
    MultiOutput {
        primary_pattern: Box<MultisigPattern>,
        output_count: u32,
        output_indices: Vec<u32>,
        total_capacity: usize,
    },
}

// ===== COUNTERPARTY MESSAGE PARSING INFRASTRUCTURE =====

/// Parsed Counterparty message content with structured data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParsedMessage {
    /// Basic asset transfer (message type 0)
    Send {
        asset_id: u64,
        asset_name: String,
        quantity: u64,
        human_readable_quantity: String,
    },

    /// Enhanced send with memo field (message type 2)
    EnhancedSend {
        asset_id: u64,
        asset_name: String,
        quantity: u64,
        human_readable_quantity: String,
        memo: String,
    },

    /// Asset creation/issuance (message types 20, 21, 22)
    Issuance {
        asset_id: u64,
        asset_name: String,
        quantity: u64,
        human_readable_quantity: String,
        divisible: bool,
        lock: Option<bool>,          // Modern format only (block ≥753,500)
        reset: Option<bool>,         // Modern format only (block ≥753,500)
        description: Option<String>, // Optional description text
    },

    /// Oracle broadcast (message type 30)
    Broadcast {
        timestamp: u32,
        value: f64,
        fee_fraction: u32,
        text: String,
    },

    /// Raw/unparsed message (fallback for unsupported types)
    Raw {
        message_type: u32,
        payload: Vec<u8>,
        payload_hex: String,
    },
}

/// Parsing errors for Counterparty messages
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Insufficient payload length: expected at least {expected} bytes, got {actual}")]
    InsufficientLength { expected: usize, actual: usize },

    #[error("Invalid asset ID: {asset_id}")]
    InvalidAssetId { asset_id: u64 },

    #[error("Invalid UTF-8 in text field: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("Unsupported message type: {message_type}")]
    UnsupportedMessageType { message_type: u32 },

    #[error("Invalid message format or corrupted payload")]
    InvalidFormat,

    #[error("Malformed message data")]
    MalformedData,
}

impl CounterpartyMessageType {
    /// Parse the payload bytes for this message type into structured data
    pub fn parse_payload(&self, payload: &[u8]) -> Result<ParsedMessage, ParseError> {
        match self {
            CounterpartyMessageType::Send => parse_send_message(payload),
            CounterpartyMessageType::EnhancedSend => parse_enhanced_send_message(payload),
            CounterpartyMessageType::Issuance => parse_issuance_message(payload),
            CounterpartyMessageType::Broadcast => parse_broadcast_message(payload),
            _ => {
                // For unsupported message types, return raw data
                Ok(ParsedMessage::Raw {
                    message_type: *self as u32,
                    payload: payload.to_vec(),
                    payload_hex: hex::encode(payload),
                })
            }
        }
    }
}

/// Parse Send message (message type 0)
/// Format: [8 bytes: asset_id][8 bytes: quantity]
fn parse_send_message(payload: &[u8]) -> Result<ParsedMessage, ParseError> {
    if payload.len() < 16 {
        return Err(ParseError::InsufficientLength {
            expected: 16,
            actual: payload.len(),
        });
    }

    // Extract asset ID (8 bytes, big-endian)
    let asset_id = u64::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]);

    // Extract quantity (8 bytes, big-endian)
    let quantity = u64::from_be_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]);

    let asset_name = resolve_asset_name(asset_id);
    let human_readable_quantity = format_quantity(quantity, is_divisible_asset(asset_id));

    Ok(ParsedMessage::Send {
        asset_id,
        asset_name,
        quantity,
        human_readable_quantity,
    })
}

/// Parse Enhanced Send message (message type 2) - placeholder for now
fn parse_enhanced_send_message(payload: &[u8]) -> Result<ParsedMessage, ParseError> {
    // For now, fall back to raw parsing - Enhanced Send has more complex structure
    Ok(ParsedMessage::Raw {
        message_type: 2,
        payload: payload.to_vec(),
        payload_hex: hex::encode(payload),
    })
}

/// Helper: Check if bytes could be a plausible Unix timestamp for Counterparty
fn is_plausible_counterparty_timestamp(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let timestamp = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    // Bitcoin genesis: Jan 3, 2009 (timestamp 1231006505)
    // Counterparty launch: Jan 2, 2014 (timestamp ~1388620800)
    // Use conservative threshold: Jan 1, 2009
    // A timestamp < 1230768000 is implausible for Counterparty data
    timestamp >= 1230768000
}

/// Parse modern format issuance (≥block 753,500)
/// Format: >QQ??? (19 bytes) + optional UTF-8 description
fn parse_modern_issuance(payload: &[u8]) -> Result<ParsedMessage, ParseError> {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Cursor;

    if payload.len() < 19 {
        return Err(ParseError::InsufficientLength {
            expected: 19,
            actual: payload.len(),
        });
    }

    let mut cursor = Cursor::new(payload);
    let asset_id = cursor
        .read_u64::<BigEndian>()
        .map_err(|_| ParseError::InvalidFormat)?;
    let quantity = cursor
        .read_u64::<BigEndian>()
        .map_err(|_| ParseError::InvalidFormat)?;
    let divisible = cursor.read_u8().map_err(|_| ParseError::InvalidFormat)? != 0;

    // Modern format fields
    let lock = cursor.read_u8().ok().map(|v| v != 0);
    let reset = cursor.read_u8().ok().map(|v| v != 0);

    // Description is remaining bytes as UTF-8
    let description = if payload.len() > 19 {
        let desc = String::from_utf8_lossy(&payload[19..]).trim().to_string();
        if desc.is_empty() {
            None
        } else {
            Some(desc)
        }
    } else {
        None
    };

    let asset_name = resolve_asset_name(asset_id);
    let human_readable_quantity = format_quantity(quantity, divisible);

    Ok(ParsedMessage::Issuance {
        asset_id,
        asset_name,
        quantity,
        human_readable_quantity,
        divisible,
        lock,
        reset,
        description,
    })
}

/// Parse legacy format issuance (<block 753,500)
/// Format: >QQ??If (26 bytes) + optional UTF-8 description
fn parse_legacy_issuance(payload: &[u8]) -> Result<ParsedMessage, ParseError> {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Cursor;

    if payload.len() < 26 {
        return Err(ParseError::InsufficientLength {
            expected: 26,
            actual: payload.len(),
        });
    }

    let mut cursor = Cursor::new(payload);
    let asset_id = cursor
        .read_u64::<BigEndian>()
        .map_err(|_| ParseError::InvalidFormat)?;
    let quantity = cursor
        .read_u64::<BigEndian>()
        .map_err(|_| ParseError::InvalidFormat)?;
    let divisible = cursor.read_u8().map_err(|_| ParseError::InvalidFormat)? != 0;

    // Legacy format has callable, call_date, call_price (skip for simplified parsing)
    let _callable = cursor.read_u8().ok();
    let _call_date = cursor.read_u32::<BigEndian>().ok();
    let _call_price = cursor.read_f32::<BigEndian>().ok();

    // Description is remaining bytes as UTF-8
    let description = if payload.len() > 26 {
        let desc = String::from_utf8_lossy(&payload[26..]).trim().to_string();
        if desc.is_empty() {
            None
        } else {
            Some(desc)
        }
    } else {
        None
    };

    let asset_name = resolve_asset_name(asset_id);
    let human_readable_quantity = format_quantity(quantity, divisible);

    Ok(ParsedMessage::Issuance {
        asset_id,
        asset_name,
        quantity,
        human_readable_quantity,
        divisible,
        lock: None,
        reset: None,
        description,
    })
}

/// Parse Issuance message (message types 20, 21, 22)
///
/// Source: counterparty-core/counterpartycore/lib/messages/issuance.py
/// Format varies by block height (mainnet cutoff: 753,500):
/// - Modern (≥753,500): >QQ??? (19 bytes) + description
/// - Legacy (<753,500): >QQ??If (26 bytes) + description
/// - Very early: >QQ? (17 bytes, no description)
fn parse_issuance_message(payload: &[u8]) -> Result<ParsedMessage, ParseError> {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Cursor;

    // Format detection strategy:
    // - Legacy format: 26 bytes base + optional description
    // - Modern format: 19 bytes base + optional description
    // - Very early format: exactly 17 bytes (no description)
    //
    // CRITICAL CHALLENGE: Both modern and legacy can be ≥26 bytes with descriptions.
    // Example: Modern issuance with "Test Asset" (10 bytes) = 29 bytes total.
    //
    // Discrimination for payloads ≥26 bytes:
    // 1. Check if bytes 17-18 are both ≤1 (potential modern lock/reset booleans)
    // 2. If yes, check if bytes 18-21 would form a plausible Unix timestamp
    //    - If timestamp ≥ Jan 1, 2009 → Legacy format (has call_date field)
    //    - If timestamp < Jan 1, 2009 → Modern format (lock/reset are 0/1)
    // 3. If bytes 17-18 aren't both ≤1 → Must be legacy
    //
    // For payloads 19-25 bytes: Must be modern (not enough room for call fields)
    // For payloads 17-18 bytes: Very early format
    // For payloads <17 bytes: Invalid

    // Discrimination for payloads ≥26 bytes
    // This is the most challenging case as both formats can be ≥26 bytes
    // Modern: 19 base + description (e.g., 7-byte description = 26 total)
    // Legacy: 26 base + description (e.g., 0-byte description = 26 total)
    if payload.len() >= 26 {
        let byte17 = payload[17];
        let byte18 = payload[18];

        // For payloads with ambiguous byte patterns, use description quality heuristics
        if byte17 <= 1 && byte18 <= 1 {
            // Check modern description quality (bytes 19+)
            let modern_desc_bytes = &payload[19..];
            let modern_desc_looks_valid = std::str::from_utf8(modern_desc_bytes).is_ok()
                && (modern_desc_bytes.is_empty()
                    || !modern_desc_bytes[0..modern_desc_bytes.len().min(6)]
                        .iter()
                        .all(|&b| b == 0));

            // Check legacy description quality (bytes 26+, if exists)
            let legacy_desc_looks_valid = if payload.len() > 26 {
                let legacy_desc_bytes = &payload[26..];
                std::str::from_utf8(legacy_desc_bytes).is_ok()
                    && (legacy_desc_bytes.is_empty()
                        || !legacy_desc_bytes[0..legacy_desc_bytes.len().min(6)]
                            .iter()
                            .all(|&b| b == 0))
            } else {
                true // No description in legacy is valid
            };

            // Prefer the format whose description looks better
            if modern_desc_looks_valid && !legacy_desc_looks_valid {
                return parse_modern_issuance(payload);
            } else if legacy_desc_looks_valid && !modern_desc_looks_valid {
                return parse_legacy_issuance(payload);
            } else if modern_desc_looks_valid && legacy_desc_looks_valid {
                // Both look valid - use timestamp heuristic as tiebreaker
                if is_plausible_counterparty_timestamp(&payload[18..22]) {
                    return parse_legacy_issuance(payload);
                } else {
                    return parse_modern_issuance(payload);
                }
            } else {
                // Neither looks valid - default to legacy (more common historically)
                return parse_legacy_issuance(payload);
            }
        } else {
            // Bytes 17-18 aren't both ≤1 → Must be legacy format
            // (Modern lock/reset are always booleans 0 or 1)
            return parse_legacy_issuance(payload);
        }
    }

    // Payloads 19-25 bytes: Modern format (not enough room for legacy call fields)
    if payload.len() >= 19 {
        return parse_modern_issuance(payload);
    }

    // Very early format: >QQ? (17-18 bytes, no lock/reset/description)
    if payload.len() >= 17 {
        let mut cursor = Cursor::new(payload);

        let asset_id = cursor
            .read_u64::<BigEndian>()
            .map_err(|_| ParseError::InvalidFormat)?;
        let quantity = cursor
            .read_u64::<BigEndian>()
            .map_err(|_| ParseError::InvalidFormat)?;
        let divisible = cursor.read_u8().map_err(|_| ParseError::InvalidFormat)? != 0;

        let asset_name = resolve_asset_name(asset_id);
        let human_readable_quantity = format_quantity(quantity, divisible);

        return Ok(ParsedMessage::Issuance {
            asset_id,
            asset_name,
            quantity,
            human_readable_quantity,
            divisible,
            lock: None,
            reset: None,
            description: None,
        });
    }

    // Payload too short for any known format
    Err(ParseError::InvalidFormat)
}

/// Parse Broadcast message (message type 30)
///
/// Source: counterparty-core/counterpartycore/lib/messages/broadcast.py
/// Format: >IdI (16 bytes) + variable-length UTF-8 text
/// - timestamp (4 bytes): Unix timestamp
/// - value (8 bytes): f64 price/value for betting
/// - fee_fraction_int (4 bytes): Fee as integer (divide by 1e8 for fraction)
/// - text (variable): UTF-8 text content
fn parse_broadcast_message(payload: &[u8]) -> Result<ParsedMessage, ParseError> {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Cursor;

    // Minimum 16 bytes for fixed header
    if payload.len() < 16 {
        return Err(ParseError::InsufficientLength {
            expected: 16,
            actual: payload.len(),
        });
    }

    let mut cursor = Cursor::new(payload);

    // Read fixed 16-byte header
    let timestamp = cursor
        .read_u32::<BigEndian>()
        .map_err(|_| ParseError::InvalidFormat)?;
    let value = cursor
        .read_f64::<BigEndian>()
        .map_err(|_| ParseError::InvalidFormat)?;
    let fee_fraction_int = cursor
        .read_u32::<BigEndian>()
        .map_err(|_| ParseError::InvalidFormat)?;

    // Convert fee_fraction_int to actual fee fraction
    let fee_fraction = fee_fraction_int;

    // Text is remaining bytes as UTF-8
    let text = if payload.len() > 16 {
        String::from_utf8_lossy(&payload[16..]).trim().to_string()
    } else {
        String::new()
    };

    Ok(ParsedMessage::Broadcast {
        timestamp,
        value,
        fee_fraction,
        text,
    })
}

/// Resolve asset ID to human-readable asset name
fn resolve_asset_name(asset_id: u64) -> String {
    match asset_id {
        0 => "BTC".to_string(),
        1 => "XCP".to_string(),
        _ => {
            // For named assets, we'd need to decode the asset name from the ID
            // For now, just show the numeric ID
            format!("ASSET_{}", asset_id)
        }
    }
}

/// Check if an asset is divisible (affects quantity display)
fn is_divisible_asset(asset_id: u64) -> bool {
    match asset_id {
        0 => true, // BTC is divisible
        1 => true, // XCP is divisible
        _ => true, // Default to divisible for now
    }
}

/// Format quantity for human-readable display
fn format_quantity(quantity: u64, is_divisible: bool) -> String {
    if is_divisible {
        // Divisible assets have 8 decimal places (like BTC/XCP)
        let integer_part = quantity / 100_000_000;
        let fractional_part = quantity % 100_000_000;
        format!("{}.{:08}", integer_part, fractional_part)
    } else {
        // Indivisible assets show as whole numbers
        quantity.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, WriteBytesExt};

    /// Test parsing modern format issuance (≥753,500)
    /// Format: >QQ??? (19 bytes) + optional description
    #[test]
    fn test_parse_issuance_modern_format() {
        let mut payload = Vec::new();

        // Asset ID: 1234567890 (8 bytes, big-endian)
        payload.write_u64::<BigEndian>(1234567890).unwrap();
        // Quantity: 100000000 (8 bytes, big-endian) - 1.0 divisible units
        payload.write_u64::<BigEndian>(100000000).unwrap();
        // Divisible: true (1 byte)
        payload.write_u8(1).unwrap();
        // Lock: false (1 byte)
        payload.write_u8(0).unwrap();
        // Reset: false (1 byte)
        payload.write_u8(0).unwrap();
        // Description: "Test Asset" (10 bytes, total = 29 bytes ≥ 26)
        // This tests the critical ≥26 byte discrimination logic
        payload.extend_from_slice(b"Test Asset");

        let result = parse_issuance_message(&payload);
        assert!(
            result.is_ok(),
            "Failed to parse modern issuance: {:?}",
            result
        );

        match result.unwrap() {
            ParsedMessage::Issuance {
                asset_id,
                quantity,
                divisible,
                lock,
                reset,
                description,
                ..
            } => {
                assert_eq!(asset_id, 1234567890);
                assert_eq!(quantity, 100000000);
                assert!(divisible);
                assert_eq!(lock, Some(false));
                assert_eq!(reset, Some(false));
                // CRITICAL: Description must be preserved despite payload being ≥26 bytes
                assert_eq!(description, Some("Test Asset".to_string()));
            }
            _ => panic!("Expected Issuance variant"),
        }
    }

    /// Test parsing modern format issuance without description
    #[test]
    fn test_parse_issuance_modern_format_no_description() {
        let mut payload = Vec::new();

        payload.write_u64::<BigEndian>(9876543210).unwrap();
        payload.write_u64::<BigEndian>(5000000000).unwrap();
        payload.write_u8(0).unwrap(); // indivisible
        payload.write_u8(1).unwrap(); // locked
        payload.write_u8(1).unwrap(); // reset

        let result = parse_issuance_message(&payload);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedMessage::Issuance {
                asset_id,
                quantity,
                divisible,
                lock,
                reset,
                description,
                ..
            } => {
                assert_eq!(asset_id, 9876543210);
                assert_eq!(quantity, 5000000000);
                assert!(!divisible);
                assert_eq!(lock, Some(true));
                assert_eq!(reset, Some(true));
                assert_eq!(description, None); // Empty description returns None
            }
            _ => panic!("Expected Issuance variant"),
        }
    }

    /// Test parsing modern format with exactly 7-byte description (total = 26 bytes)
    /// CRITICAL REGRESSION TEST: Modern issuances with 7-byte descriptions
    /// must NOT be misclassified as legacy format despite being exactly 26 bytes
    #[test]
    fn test_parse_issuance_modern_format_seven_byte_description() {
        let mut payload = Vec::new();

        // Asset ID: 111111111 (8 bytes)
        payload.write_u64::<BigEndian>(111111111).unwrap();
        // Quantity: 25000000 (8 bytes)
        payload.write_u64::<BigEndian>(25000000).unwrap();
        // Divisible: true (1 byte)
        payload.write_u8(1).unwrap();
        // Lock: false (1 byte)
        payload.write_u8(0).unwrap();
        // Reset: true (1 byte)
        payload.write_u8(1).unwrap();
        // Description: "EXAMPLE" (7 bytes) - CRITICAL: Total payload = 26 bytes
        payload.extend_from_slice(b"EXAMPLE");

        // Verify payload is exactly 26 bytes
        assert_eq!(
            payload.len(),
            26,
            "Test setup error: payload should be 26 bytes"
        );

        let result = parse_issuance_message(&payload);
        assert!(
            result.is_ok(),
            "Failed to parse modern 26-byte issuance: {:?}",
            result
        );

        match result.unwrap() {
            ParsedMessage::Issuance {
                asset_id,
                quantity,
                divisible,
                lock,
                reset,
                description,
                ..
            } => {
                assert_eq!(asset_id, 111111111);
                assert_eq!(quantity, 25000000);
                assert!(divisible);
                // CRITICAL: Must preserve modern format fields, not return None
                assert_eq!(
                    lock,
                    Some(false),
                    "Modern format lock field must be preserved at 26 bytes"
                );
                assert_eq!(
                    reset,
                    Some(true),
                    "Modern format reset field must be preserved at 26 bytes"
                );
                // CRITICAL: Description must be intact, not None or corrupted
                assert_eq!(
                    description,
                    Some("EXAMPLE".to_string()),
                    "Modern format description must be preserved at 26 bytes"
                );
            }
            _ => panic!("Expected Issuance variant"),
        }
    }

    /// Test parsing legacy format issuance (<753,500)
    /// Format: >QQ??If (26 bytes) + optional description
    #[test]
    fn test_parse_issuance_legacy_format() {
        let mut payload = Vec::new();

        // Asset ID
        payload.write_u64::<BigEndian>(555555555).unwrap();
        // Quantity
        payload.write_u64::<BigEndian>(1000000).unwrap();
        // Divisible: true
        payload.write_u8(1).unwrap();
        // Callable: false
        payload.write_u8(0).unwrap();
        // Call date: 1609459200 (Jan 1, 2021)
        payload.write_u32::<BigEndian>(1609459200).unwrap();
        // Call price: 1.5
        payload.write_f32::<BigEndian>(1.5).unwrap();
        // Description
        payload.extend_from_slice(b"Legacy Asset");

        let result = parse_issuance_message(&payload);
        assert!(
            result.is_ok(),
            "Failed to parse legacy issuance: {:?}",
            result
        );

        match result.unwrap() {
            ParsedMessage::Issuance {
                asset_id,
                quantity,
                divisible,
                lock,
                reset,
                description,
                ..
            } => {
                assert_eq!(asset_id, 555555555);
                assert_eq!(quantity, 1000000);
                assert!(divisible);
                // Legacy format doesn't have lock/reset - must be None
                assert_eq!(lock, None, "Legacy format should not have lock field");
                assert_eq!(reset, None, "Legacy format should not have reset field");
                assert_eq!(description, Some("Legacy Asset".to_string()));
            }
            _ => panic!("Expected Issuance variant"),
        }
    }

    /// Test parsing legacy format with all-zero call fields
    /// CRITICAL REGRESSION TEST: Ensures callable=0, call_date=0, call_price=0
    /// doesn't get misclassified as modern format
    #[test]
    fn test_parse_issuance_legacy_format_zero_call_fields() {
        let mut payload = Vec::new();

        // Asset ID
        payload.write_u64::<BigEndian>(123456789).unwrap();
        // Quantity
        payload.write_u64::<BigEndian>(50000000).unwrap();
        // Divisible: false
        payload.write_u8(0).unwrap();
        // Callable: false (0)
        payload.write_u8(0).unwrap();
        // Call date: 0 (never callable)
        payload.write_u32::<BigEndian>(0).unwrap();
        // Call price: 0.0
        payload.write_f32::<BigEndian>(0.0).unwrap();
        // Description
        payload.extend_from_slice(b"Non-Callable Asset");

        let result = parse_issuance_message(&payload);
        assert!(
            result.is_ok(),
            "Failed to parse legacy issuance with zero call fields: {:?}",
            result
        );

        match result.unwrap() {
            ParsedMessage::Issuance {
                asset_id,
                quantity,
                divisible,
                lock,
                reset,
                description,
                ..
            } => {
                assert_eq!(asset_id, 123456789);
                assert_eq!(quantity, 50000000);
                assert!(!divisible);
                // CRITICAL: Must be None, not Some(false)
                // This proves we used legacy parser, not modern parser
                assert_eq!(
                    lock, None,
                    "Legacy format with zero call fields should not have lock field"
                );
                assert_eq!(
                    reset, None,
                    "Legacy format with zero call fields should not have reset field"
                );
                // Description should be clean, not corrupted by call_date/call_price bytes
                assert_eq!(description, Some("Non-Callable Asset".to_string()));
            }
            _ => panic!("Expected Issuance variant"),
        }
    }

    /// Test parsing very early format issuance
    /// Format: >QQ? (17 bytes, no description)
    #[test]
    fn test_parse_issuance_very_early_format() {
        let mut payload = Vec::new();

        payload.write_u64::<BigEndian>(111111111).unwrap();
        payload.write_u64::<BigEndian>(999999999).unwrap();
        payload.write_u8(0).unwrap(); // indivisible

        let result = parse_issuance_message(&payload);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedMessage::Issuance {
                asset_id,
                quantity,
                divisible,
                description,
                ..
            } => {
                assert_eq!(asset_id, 111111111);
                assert_eq!(quantity, 999999999);
                assert!(!divisible);
                assert_eq!(description, None); // Very early format has no description
            }
            _ => panic!("Expected Issuance variant"),
        }
    }

    /// Test issuance with insufficient data
    #[test]
    fn test_parse_issuance_insufficient_length() {
        let payload = vec![0x00, 0x01, 0x02]; // Only 3 bytes

        let result = parse_issuance_message(&payload);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ParseError::InvalidFormat));
    }

    /// Test parsing broadcast message
    /// Format: >IdI (16 bytes) + variable text
    #[test]
    fn test_parse_broadcast_message() {
        let mut payload = Vec::new();

        // Timestamp: 1609459200 (Jan 1, 2021, 00:00:00 UTC)
        payload.write_u32::<BigEndian>(1609459200).unwrap();
        // Value: 100.5 (betting price)
        payload.write_f64::<BigEndian>(100.5).unwrap();
        // Fee fraction: 5000000 (5%)
        payload.write_u32::<BigEndian>(5000000).unwrap();
        // Text content
        payload.extend_from_slice(b"Market opens at 100.5");

        let result = parse_broadcast_message(&payload);
        assert!(result.is_ok(), "Failed to parse broadcast: {:?}", result);

        match result.unwrap() {
            ParsedMessage::Broadcast {
                timestamp,
                value,
                fee_fraction,
                text,
            } => {
                assert_eq!(timestamp, 1609459200);
                assert_eq!(value, 100.5);
                assert_eq!(fee_fraction, 5000000);
                assert_eq!(text, "Market opens at 100.5");
            }
            _ => panic!("Expected Broadcast variant"),
        }
    }

    /// Test parsing broadcast without text content
    #[test]
    fn test_parse_broadcast_no_text() {
        let mut payload = Vec::new();

        payload.write_u32::<BigEndian>(1700000000).unwrap();
        payload.write_f64::<BigEndian>(0.0).unwrap();
        payload.write_u32::<BigEndian>(0).unwrap();

        let result = parse_broadcast_message(&payload);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedMessage::Broadcast {
                timestamp,
                value,
                fee_fraction,
                text,
            } => {
                assert_eq!(timestamp, 1700000000);
                assert_eq!(value, 0.0);
                assert_eq!(fee_fraction, 0);
                assert_eq!(text, "");
            }
            _ => panic!("Expected Broadcast variant"),
        }
    }

    /// Test broadcast with insufficient length
    #[test]
    fn test_parse_broadcast_insufficient_length() {
        let payload = vec![0x00, 0x01, 0x02]; // Only 3 bytes, need 16

        let result = parse_broadcast_message(&payload);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ParseError::InsufficientLength { expected: 16, .. }
        ));
    }

    /// Test parsing Send message (Type 0)
    #[test]
    fn test_parse_send_message() {
        let mut payload = Vec::new();

        // Asset ID: 1 (XCP)
        payload.write_u64::<BigEndian>(1).unwrap();
        // Quantity: 100000000 (1.0 XCP)
        payload.write_u64::<BigEndian>(100000000).unwrap();

        let result = parse_send_message(&payload);
        assert!(result.is_ok());

        match result.unwrap() {
            ParsedMessage::Send {
                asset_id, quantity, ..
            } => {
                assert_eq!(asset_id, 1);
                assert_eq!(quantity, 100000000);
            }
            _ => panic!("Expected Send variant"),
        }
    }

    /// Test asset name resolution
    #[test]
    fn test_resolve_asset_name() {
        assert_eq!(resolve_asset_name(0), "BTC");
        assert_eq!(resolve_asset_name(1), "XCP");
        assert_eq!(resolve_asset_name(12345), "ASSET_12345");
    }

    /// Test quantity formatting
    #[test]
    fn test_format_quantity() {
        // Divisible: 1.0 units
        assert_eq!(format_quantity(100000000, true), "1.00000000");
        // Divisible: 0.5 units
        assert_eq!(format_quantity(50000000, true), "0.50000000");
        // Indivisible: 100 units
        assert_eq!(format_quantity(100, false), "100");
        // Divisible: 123.456789 units
        assert_eq!(format_quantity(12345678900, true), "123.45678900");
    }
}
