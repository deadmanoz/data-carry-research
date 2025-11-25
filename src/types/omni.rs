//! Omni Layer Protocol Constants and Types
//!
//! This module defines all constants and types for the Omni Layer protocol,
//! including the mandatory Exodus address and its various representations.
//!
//! ## Exodus Address
//!
//! The Exodus address (`1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P`) is the foundation address
//! for the Omni Layer protocol. All Class B (P2MS-encoded) Omni transactions MUST
//! include an output to this address as a protocol marker.
//!
//! Two representations are provided:
//! - `EXODUS_ADDRESS`: Base58Check string (for display/comparison)
//! - `EXODUS_SCRIPT_PUBKEY`: Full 25-byte P2PKH script (for efficient validation)
//!
//! Use `is_exodus_script()` for fast script validation - it's a simple byte comparison.

use super::ProtocolVariant;
use serde::{Deserialize, Serialize};

// ============================================================================
// Exodus Address Constants (Omni Layer Protocol Marker)
// ============================================================================

/// Omni Layer Exodus address - mandatory for Class B (P2MS) transactions
///
/// This address must receive a dust output in all Omni Layer Class B transactions.
/// It serves as a protocol marker and fee destination.
///
/// Address: 1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P
pub const EXODUS_ADDRESS: &str = "1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P";

/// Exodus address script pubkey (P2PKH)
///
/// Full Bitcoin P2PKH script for the Exodus address.
/// Format: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
///
/// Use this for direct script comparison - most efficient method.
/// Hex: 76a914946cb2e08075bcbaf157e47bcb67eb2b2339d24288ac
pub const EXODUS_SCRIPT_PUBKEY: &[u8] = &[
    0x76, // OP_DUP
    0xa9, // OP_HASH160
    0x14, // 20 bytes
    0x94, 0x6c, 0xb2, 0xe0, 0x80, 0x75, 0xbc, 0xba, 0xf1, 0x57, 0xe4, 0x7b, 0xcb, 0x67, 0xeb, 0x2b,
    0x23, 0x39, 0xd2, 0x42, 0x88, // OP_EQUALVERIFY
    0xac, // OP_CHECKSIG
];

/// Helper function to check if a script pubkey is the Exodus address
///
/// This is the most efficient way to check for Exodus address in outputs.
/// Simply compares the entire script byte-for-byte against the known Exodus script.
///
/// # Example
/// ```ignore
/// if is_exodus_script(&output.script_pubkey.to_bytes()) {
///     println!("Found Exodus output!");
/// }
/// ```
pub fn is_exodus_script(script: &[u8]) -> bool {
    script == EXODUS_SCRIPT_PUBKEY
}

/// Omni Layer message types found in P2MS Class B transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OmniMessageType {
    // Transfer Types (most common in P2MS)
    SimpleSend = 0,      // Basic token transfer
    RestrictedSend = 2,  // Send with restrictions
    SendToOwners = 3,    // Distribute to all token holders
    SendAll = 4,         // Send all tokens of specified ecosystem
    SendNonFungible = 5, // NFT transfer

    // Trading/Exchange
    TradeOffer = 20,             // DEX trade offer
    AcceptOfferBTC = 22,         // Accept BTC trade offer
    MetaDEXTrade = 25,           // MetaDEX trading
    MetaDEXCancelPrice = 26,     // Cancel by price
    MetaDEXCancelPair = 27,      // Cancel trading pair
    MetaDEXCancelEcosystem = 28, // Cancel ecosystem trades

    // Property Management
    CreatePropertyFixed = 50,    // Fixed supply token
    CreatePropertyVariable = 51, // Variable supply token
    PromoteProperty = 52,        // Promote to main ecosystem
    CloseCrowdsale = 53,         // End crowdsale
    CreatePropertyManual = 54,   // Manually managed token
    GrantPropertyTokens = 55,    // Issue additional tokens
    RevokePropertyTokens = 56,   // Destroy tokens

    // Administrative
    ChangeIssuerAddress = 70,     // Transfer token control
    EnableFreezing = 71,          // Enable address freezing
    DisableFreezing = 72,         // Disable address freezing
    FreezePropertyTokens = 185,   // Freeze specific address
    UnfreezePropertyTokens = 186, // Unfreeze address

    // Other types that may appear in P2MS
    Notification = 31, // General notification
    AnyData = 200,     // Arbitrary data storage
}

impl OmniMessageType {
    /// Convert from u32 (from deobfuscated data)
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::SimpleSend),
            2 => Some(Self::RestrictedSend),
            3 => Some(Self::SendToOwners),
            4 => Some(Self::SendAll),
            5 => Some(Self::SendNonFungible),
            20 => Some(Self::TradeOffer),
            22 => Some(Self::AcceptOfferBTC),
            25 => Some(Self::MetaDEXTrade),
            26 => Some(Self::MetaDEXCancelPrice),
            27 => Some(Self::MetaDEXCancelPair),
            28 => Some(Self::MetaDEXCancelEcosystem),
            31 => Some(Self::Notification),
            50 => Some(Self::CreatePropertyFixed),
            51 => Some(Self::CreatePropertyVariable),
            52 => Some(Self::PromoteProperty),
            53 => Some(Self::CloseCrowdsale),
            54 => Some(Self::CreatePropertyManual),
            55 => Some(Self::GrantPropertyTokens),
            56 => Some(Self::RevokePropertyTokens),
            70 => Some(Self::ChangeIssuerAddress),
            71 => Some(Self::EnableFreezing),
            72 => Some(Self::DisableFreezing),
            185 => Some(Self::FreezePropertyTokens),
            186 => Some(Self::UnfreezePropertyTokens),
            200 => Some(Self::AnyData),
            _ => None,
        }
    }

    /// Map to protocol variant for classification
    pub fn get_variant(&self) -> ProtocolVariant {
        match self {
            // Asset Transfers - P2P value movement between parties
            Self::SimpleSend | Self::RestrictedSend | Self::SendAll | Self::SendNonFungible => {
                ProtocolVariant::OmniTransfer
            }

            // Dividend Distribution - Broadcast to all token holders
            Self::SendToOwners => ProtocolVariant::OmniDistribution,

            // Property Creation & Supply Expansion
            Self::CreatePropertyFixed
            | Self::CreatePropertyVariable
            | Self::PromoteProperty
            | Self::CreatePropertyManual
            | Self::GrantPropertyTokens => ProtocolVariant::OmniIssuance,

            // Token Destruction - Voluntary burning/revocation
            Self::RevokePropertyTokens => ProtocolVariant::OmniDestruction,

            // Decentralised Exchange Operations
            Self::TradeOffer
            | Self::AcceptOfferBTC
            | Self::MetaDEXTrade
            | Self::MetaDEXCancelPrice
            | Self::MetaDEXCancelPair
            | Self::MetaDEXCancelEcosystem => ProtocolVariant::OmniDEX,

            // Administrative Controls & Restrictions
            Self::CloseCrowdsale
            | Self::ChangeIssuerAddress
            | Self::EnableFreezing
            | Self::DisableFreezing
            | Self::FreezePropertyTokens
            | Self::UnfreezePropertyTokens => ProtocolVariant::OmniAdministration,

            // Utility Operations - Notifications & data storage
            Self::Notification | Self::AnyData => ProtocolVariant::OmniUtility,
        }
    }
}

/// Extracted and deobfuscated Omni P2MS data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniP2msData {
    pub raw_packets: Vec<OmniPacket>,
    pub deobfuscated_data: Vec<u8>,
    pub sender_address: String,
    pub message_type: OmniMessageType,
    pub payload: Vec<u8>,
    pub total_packets: u8,
}

/// Individual obfuscated packet from P2MS position 2 or 3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniPacket {
    pub vout: u32,
    pub position: u8, // 2 or 3 (P2MS position)
    pub sequence_number: u8,
    pub obfuscated_data: [u8; 31],
    pub deobfuscated_data: Option<[u8; 31]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test semantic variant mapping for edge cases to prevent future regressions
    #[test]
    fn test_get_variant_semantic_mappings() {
        // Transfer operations (basic P2P)
        assert_eq!(
            OmniMessageType::SimpleSend.get_variant(),
            ProtocolVariant::OmniTransfer
        );
        assert_eq!(
            OmniMessageType::SendAll.get_variant(),
            ProtocolVariant::OmniTransfer
        );

        // Distribution (broadcast to holders) - distinct from Transfer
        assert_eq!(
            OmniMessageType::SendToOwners.get_variant(),
            ProtocolVariant::OmniDistribution
        );

        // Issuance - including PromoteProperty (Type 52)
        assert_eq!(
            OmniMessageType::PromoteProperty.get_variant(),
            ProtocolVariant::OmniIssuance
        );
        assert_eq!(
            OmniMessageType::GrantPropertyTokens.get_variant(),
            ProtocolVariant::OmniIssuance
        );

        // Destruction - ONLY token burning (Type 56)
        assert_eq!(
            OmniMessageType::RevokePropertyTokens.get_variant(),
            ProtocolVariant::OmniDestruction
        );

        // Administration - freezing operations (NOT destruction)
        assert_eq!(
            OmniMessageType::EnableFreezing.get_variant(),
            ProtocolVariant::OmniAdministration
        );
        assert_eq!(
            OmniMessageType::FreezePropertyTokens.get_variant(),
            ProtocolVariant::OmniAdministration
        );
        assert_eq!(
            OmniMessageType::UnfreezePropertyTokens.get_variant(),
            ProtocolVariant::OmniAdministration
        );
        assert_eq!(
            OmniMessageType::CloseCrowdsale.get_variant(),
            ProtocolVariant::OmniAdministration
        );

        // DEX operations
        assert_eq!(
            OmniMessageType::TradeOffer.get_variant(),
            ProtocolVariant::OmniDEX
        );
        assert_eq!(
            OmniMessageType::MetaDEXTrade.get_variant(),
            ProtocolVariant::OmniDEX
        );

        // Utility - notifications and data (Type 31, 200)
        assert_eq!(
            OmniMessageType::Notification.get_variant(),
            ProtocolVariant::OmniUtility
        );
        assert_eq!(
            OmniMessageType::AnyData.get_variant(),
            ProtocolVariant::OmniUtility
        );
    }

    /// Verify all 25 message types map to exactly one variant
    #[test]
    fn test_all_message_types_mapped() {
        let all_types = vec![
            OmniMessageType::SimpleSend,
            OmniMessageType::RestrictedSend,
            OmniMessageType::SendToOwners,
            OmniMessageType::SendAll,
            OmniMessageType::SendNonFungible,
            OmniMessageType::TradeOffer,
            OmniMessageType::AcceptOfferBTC,
            OmniMessageType::MetaDEXTrade,
            OmniMessageType::MetaDEXCancelPrice,
            OmniMessageType::MetaDEXCancelPair,
            OmniMessageType::MetaDEXCancelEcosystem,
            OmniMessageType::Notification,
            OmniMessageType::CreatePropertyFixed,
            OmniMessageType::CreatePropertyVariable,
            OmniMessageType::PromoteProperty,
            OmniMessageType::CloseCrowdsale,
            OmniMessageType::CreatePropertyManual,
            OmniMessageType::GrantPropertyTokens,
            OmniMessageType::RevokePropertyTokens,
            OmniMessageType::ChangeIssuerAddress,
            OmniMessageType::EnableFreezing,
            OmniMessageType::DisableFreezing,
            OmniMessageType::FreezePropertyTokens,
            OmniMessageType::UnfreezePropertyTokens,
            OmniMessageType::AnyData,
        ];

        // Verify all types return a variant (no panics, no unmapped types)
        for msg_type in all_types {
            let _variant = msg_type.get_variant();
            // If this doesn't panic, the mapping exists
        }
    }
}
