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
//! NOTE: Parsing logic has been moved to crate::decoder::chancecoin
//! to maintain separation of concerns (types vs business logic).
//!
//! References:
//! - https://github.com/chancecoin/chancecoinj/blob/master/src/Bet.java
//! - https://github.com/chancecoin/chancecoinj/blob/master/src/Blocks.java

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Unknown message type (message_id stored separately in ChancecoinMessage)
    Unknown,
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
            ChancecoinMessageType::Unknown => "Chancecoin Unknown",
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
            _ => ChancecoinMessageType::Unknown,
        }
    }
}

impl ChancecoinMessage {
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
