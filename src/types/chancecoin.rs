//! Chancecoin protocol types and message structures
//!
//! Chancecoin is a gambling protocol built on Bitcoin that uses P2MS outputs
//! for data storage. Unlike Counterparty, it does NOT use obfuscation.
//!
//! Key characteristics:
//! - 1-of-2 or 1-of-3 multisig structure
//! - Data split across multiple P2MS outputs (32 bytes per chunk)
//! - Each chunk has length prefix (first byte = actual data size)
//! - Message format: [CHANCECO:8][MessageID:4][Data:variable]
//! - Data in second pubkey slot (no obfuscation)
//!
//! References:
//! - https://github.com/chancecoin/chancecoinj/blob/master/src/Bet.java
//! - https://github.com/chancecoin/chancecoinj/blob/master/src/Blocks.java

use byteorder::{BigEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// Chancecoin message signature (8 bytes)
pub const CHANCECOIN_SIGNATURE: &[u8] = b"CHANCECO";

/// Chancecoin message ID constants
/// References:
/// - Send.java:28-29
/// - Order.java:28-29
/// - BTCPay.java:30-31
/// - Roll.java:33-35
/// - Bet.java:33-36
/// - Cancel.java:30-31
pub const MESSAGE_ID_SEND: u32 = 0;
pub const MESSAGE_ID_ORDER: u32 = 10;
pub const MESSAGE_ID_BTCPAY: u32 = 11;
pub const MESSAGE_ID_ROLL: u32 = 14;
pub const MESSAGE_ID_DICE: u32 = 40;
pub const MESSAGE_ID_POKER: u32 = 41;
pub const MESSAGE_ID_CANCEL: u32 = 70;

/// Chancecoin protocol message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChancecoinMessage {
    /// Transaction ID
    pub txid: String,

    /// Message ID (4-byte value after signature)
    pub message_id: u32,

    /// Message type (parsed from message_id)
    pub message_type: ChancecoinMessageType,

    /// Parsed message content
    pub content: ChancecoinMessageContent,

    /// Raw message data (after signature + message_id)
    pub data: Vec<u8>,

    /// Full extracted data including signature
    pub raw_data: Vec<u8>,
}

/// Chancecoin message types based on message ID
/// From chancecoinj source code
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChancecoinMessageType {
    /// Send/transfer transaction (ID=0)
    /// Purpose: Transfer CHA tokens between addresses
    /// Data: assetId (8 bytes) + amount (8 bytes)
    Send,

    /// DEX order transaction (ID=10)
    /// Purpose: Create decentralised exchange order (CHA/BTC trading)
    /// Data: giveId + giveAmount + getId + getAmount + expiration + feeRequired
    Order,

    /// BTC payment transaction (ID=11)
    /// Purpose: Complete BTC side of order match
    /// Data: tx0Hash (32 bytes) + tx1Hash (32 bytes)
    BTCPay,

    /// Roll transaction (ID=14)
    /// Purpose: Resolve instant bets with provably fair randomness
    /// Data: rollTxHash (32 bytes) + roll (8 bytes) + [optional chaAmount (8 bytes)]
    Roll,

    /// Dice betting transaction (ID=40)
    /// Purpose: Place dice bet on gambling platform
    /// Data: bet (8 bytes) + chance (8 bytes) + payout (8 bytes)
    DiceBet,

    /// Poker betting transaction (ID=41)
    /// Purpose: Place poker bet (Texas Hold'em)
    /// Data: bet (8 bytes) + 9 cards (18 bytes)
    PokerBet,

    /// Cancel order transaction (ID=70)
    /// Purpose: Cancel an open order
    /// Data: offerHash (32 bytes)
    Cancel,

    /// Unknown message type
    Unknown(u32),
}

/// Chancecoin message content (parsed data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChancecoinMessageContent {
    /// Send: assetId (8 bytes) + amount (8 bytes) = 16 bytes
    Send { asset_id: u64, amount: u64 },

    /// Order: 6 fields totaling 42 bytes
    Order {
        give_id: u64,      // Asset being offered
        give_amount: u64,  // Amount being offered
        get_id: u64,       // Asset being requested
        get_amount: u64,   // Amount being requested
        expiration: u16,   // Blocks until expiry
        fee_required: u64, // Required BTC fee
    },

    /// BTCPay: tx0Hash (32 bytes) + tx1Hash (32 bytes) = 64 bytes
    BTCPay {
        tx0_hash: String, // Hex string
        tx1_hash: String, // Hex string
    },

    /// Roll: rollTxHash (32) + roll (8) + [optional chaAmount (8)] = 40 or 48 bytes
    Roll {
        roll_tx_hash: String,    // Hex string
        roll: f64,               // Random value 0-1
        cha_amount: Option<u64>, // Optional CHA amount for BTC bets
    },

    /// Dice bet: bet (8) + chance (8) + payout (8) = 24 bytes
    DiceBet { bet: u64, chance: f64, payout: f64 },

    /// Poker bet: bet (8) + 9 cards (18) = 26 bytes
    PokerBet {
        bet: u64,
        cards: Vec<u16>, // 9 cards
    },

    /// Cancel: offerHash (32 bytes) = 32 bytes
    Cancel {
        offer_hash: String, // Hex string
    },

    /// Raw unparsed data
    Raw(Vec<u8>),
}

impl ChancecoinMessageType {
    /// Get human-readable description
    pub fn description(&self) -> &str {
        match self {
            ChancecoinMessageType::Send => "Chancecoin Send",
            ChancecoinMessageType::Order => "Chancecoin Order",
            ChancecoinMessageType::BTCPay => "Chancecoin BTCPay",
            ChancecoinMessageType::Roll => "Chancecoin Roll",
            ChancecoinMessageType::DiceBet => "Chancecoin Dice Bet",
            ChancecoinMessageType::PokerBet => "Chancecoin Poker Bet",
            ChancecoinMessageType::Cancel => "Chancecoin Cancel",
            ChancecoinMessageType::Unknown(_) => "Chancecoin Unknown",
        }
    }

    /// Create from message ID
    pub fn from_id(id: u32) -> Self {
        match id {
            MESSAGE_ID_SEND => ChancecoinMessageType::Send,
            MESSAGE_ID_ORDER => ChancecoinMessageType::Order,
            MESSAGE_ID_BTCPAY => ChancecoinMessageType::BTCPay,
            MESSAGE_ID_ROLL => ChancecoinMessageType::Roll,
            MESSAGE_ID_DICE => ChancecoinMessageType::DiceBet,
            MESSAGE_ID_POKER => ChancecoinMessageType::PokerBet,
            MESSAGE_ID_CANCEL => ChancecoinMessageType::Cancel,
            _ => ChancecoinMessageType::Unknown(id),
        }
    }
}

impl ChancecoinMessage {
    /// Create a new Chancecoin message from concatenated P2MS data
    ///
    /// Expected format:
    /// - Bytes 0-7: "CHANCECO" signature
    /// - Bytes 8-11: Message ID (4-byte big-endian u32)
    /// - Bytes 12+: Message-specific data
    pub fn new(txid: String, raw_data: Vec<u8>) -> Option<Self> {
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
        let content = Self::parse_content(&message_type, &data);

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
    fn parse_content(
        message_type: &ChancecoinMessageType,
        data: &[u8],
    ) -> ChancecoinMessageContent {
        match message_type {
            ChancecoinMessageType::Send => Self::parse_send(data)
                .unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec())),
            ChancecoinMessageType::Order => Self::parse_order(data)
                .unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec())),
            ChancecoinMessageType::BTCPay => Self::parse_btcpay(data)
                .unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec())),
            ChancecoinMessageType::Roll => Self::parse_roll(data)
                .unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec())),
            ChancecoinMessageType::DiceBet => Self::parse_dice_bet(data)
                .unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec())),
            ChancecoinMessageType::PokerBet => Self::parse_poker_bet(data)
                .unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec())),
            ChancecoinMessageType::Cancel => Self::parse_cancel(data)
                .unwrap_or_else(|| ChancecoinMessageContent::Raw(data.to_vec())),
            ChancecoinMessageType::Unknown(_) => ChancecoinMessageContent::Raw(data.to_vec()),
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

    /// Get message summary
    pub fn summary(&self) -> String {
        match &self.content {
            ChancecoinMessageContent::Send { asset_id, amount } => {
                format!("Send: asset {} amount {} satoshis", asset_id, amount)
            }
            ChancecoinMessageContent::Order {
                give_id,
                give_amount,
                get_id,
                get_amount,
                expiration,
                ..
            } => {
                format!(
                    "Order: Give {} × {} for Get {} × {} (expires in {} blocks)",
                    give_amount, give_id, get_amount, get_id, expiration
                )
            }
            ChancecoinMessageContent::BTCPay { tx0_hash, tx1_hash } => {
                format!(
                    "BTCPay: {}..{} × {}..{}",
                    &tx0_hash[..8],
                    &tx0_hash[56..],
                    &tx1_hash[..8],
                    &tx1_hash[56..]
                )
            }
            ChancecoinMessageContent::Roll {
                roll, cha_amount, ..
            } => {
                if let Some(cha) = cha_amount {
                    format!("Roll: {:.6} (CHA amount: {})", roll, cha)
                } else {
                    format!("Roll: {:.6}", roll)
                }
            }
            ChancecoinMessageContent::DiceBet {
                bet,
                chance,
                payout,
            } => {
                format!(
                    "Dice Bet: {} satoshis, {}% chance, {}x payout",
                    bet, chance, payout
                )
            }
            ChancecoinMessageContent::PokerBet { bet, cards } => {
                format!("Poker Bet: {} satoshis, {} cards", bet, cards.len())
            }
            ChancecoinMessageContent::Cancel { offer_hash } => {
                format!("Cancel: {}..{}", &offer_hash[..8], &offer_hash[56..])
            }
            ChancecoinMessageContent::Raw(data) => {
                format!(
                    "{} ({} bytes data)",
                    self.message_type.description(),
                    data.len()
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dice_bet_parsing() {
        // Create dice bet message: CHANCECO + MessageID(40) + bet + chance + payout
        let mut data = Vec::new();
        data.extend_from_slice(b"CHANCECO"); // Signature
        data.extend_from_slice(&MESSAGE_ID_DICE.to_be_bytes()); // Message ID
        data.extend_from_slice(&1000u64.to_be_bytes()); // Bet amount
        data.extend_from_slice(&50.0f64.to_be_bytes()); // Chance
        data.extend_from_slice(&2.0f64.to_be_bytes()); // Payout

        let msg = ChancecoinMessage::new("test_txid".to_string(), data);
        assert!(msg.is_some());

        let msg = msg.unwrap();
        assert_eq!(msg.message_id, MESSAGE_ID_DICE);
        assert_eq!(msg.message_type, ChancecoinMessageType::DiceBet);

        match msg.content {
            ChancecoinMessageContent::DiceBet {
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

    #[test]
    fn test_poker_bet_parsing() {
        // Create poker bet message: CHANCECO + MessageID(41) + bet + 9 cards
        let mut data = Vec::new();
        data.extend_from_slice(b"CHANCECO"); // Signature
        data.extend_from_slice(&MESSAGE_ID_POKER.to_be_bytes()); // Message ID
        data.extend_from_slice(&2000u64.to_be_bytes()); // Bet amount

        // 9 cards (each 2 bytes)
        for i in 0..9 {
            data.extend_from_slice(&((i * 4) as u16).to_be_bytes());
        }

        let msg = ChancecoinMessage::new("test_txid".to_string(), data);
        assert!(msg.is_some());

        let msg = msg.unwrap();
        assert_eq!(msg.message_id, MESSAGE_ID_POKER);
        assert_eq!(msg.message_type, ChancecoinMessageType::PokerBet);

        match msg.content {
            ChancecoinMessageContent::PokerBet { bet, cards } => {
                assert_eq!(bet, 2000);
                assert_eq!(cards.len(), 9);
                assert_eq!(cards[0], 0);
                assert_eq!(cards[8], 32);
            }
            _ => panic!("Expected PokerBet content"),
        }
    }

    #[test]
    fn test_invalid_signature() {
        let data = b"WRONGSIG\x00\x00\x00\x0e".to_vec();
        let msg = ChancecoinMessage::new("test_txid".to_string(), data);
        assert!(msg.is_none());
    }

    #[test]
    fn test_message_type_description() {
        assert_eq!(
            ChancecoinMessageType::DiceBet.description(),
            "Chancecoin Dice Bet"
        );
        assert_eq!(
            ChancecoinMessageType::PokerBet.description(),
            "Chancecoin Poker Bet"
        );
    }

    #[test]
    fn test_message_type_from_id() {
        assert_eq!(
            ChancecoinMessageType::from_id(40),
            ChancecoinMessageType::DiceBet
        );
        assert_eq!(
            ChancecoinMessageType::from_id(41),
            ChancecoinMessageType::PokerBet
        );
        assert_eq!(
            ChancecoinMessageType::from_id(999),
            ChancecoinMessageType::Unknown(999)
        );
    }
}
