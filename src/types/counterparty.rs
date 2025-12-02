use super::ProtocolVariant;
use serde::{Deserialize, Serialize};

// Core protocol constants (Source: counterpartycore/lib/config.py)
pub const COUNTERPARTY_PREFIX: &[u8] = b"CNTRPRTY"; // 8-byte protocol identifier

/// Message type definitions from Counterparty Core codebase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

    // Multi-output data combination
    MultiOutput {
        primary_pattern: Box<MultisigPattern>,
        output_count: u32,
        output_indices: Vec<u32>,
        total_capacity: usize,
    },
}

// ===== COUNTERPARTY MESSAGE PARSING INFRASTRUCTURE =====
// NOTE: Parsing logic has been moved to crate::decoder::counterparty_parser
// This module contains only type definitions.

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
