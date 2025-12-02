//! DataStorage protocol type definitions
//!
//! Defines variants for generic data storage patterns detected in P2MS outputs
//! that don't match specific protocol signatures.

use super::ProtocolVariant;
use serde::{Deserialize, Serialize};

/// DataStorage variant types
///
/// These variants represent different patterns of data embedding
/// detected through structural analysis of P2MS outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataStorageVariant {
    /// Proof of Burn pattern
    ///
    /// All 0xFF burn patterns in pubkeys - provably unspendable.
    ProofOfBurn,

    /// File metadata storage
    ///
    /// Detected file sharing or metadata patterns (WikiLeaks-style).
    FileMetadata,

    /// Embedded data in pubkey coordinates
    ///
    /// Data embedded directly in pubkey X/Y coordinates.
    EmbeddedData,

    /// WikiLeaks Cablegate archive
    ///
    /// Specific historical artifact from April 2013.
    /// 132 transactions, heights 229991-230256.
    WikiLeaksCablegate,

    /// Bitcoin Whitepaper PDF
    ///
    /// The original Bitcoin whitepaper embedded at height 230009.
    /// Transaction: 54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713
    BitcoinWhitepaper,

    /// Null/zero byte data
    ///
    /// Null or zero byte padding patterns.
    NullData,

    /// Generic data storage
    ///
    /// Catch-all for other data storage patterns.
    Generic,
}

impl DataStorageVariant {
    /// Get the display name for this variant
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ProofOfBurn => "Proof of Burn",
            Self::FileMetadata => "File Metadata",
            Self::EmbeddedData => "Embedded Data",
            Self::WikiLeaksCablegate => "WikiLeaks Cablegate",
            Self::BitcoinWhitepaper => "Bitcoin Whitepaper",
            Self::NullData => "Null Data",
            Self::Generic => "Generic",
        }
    }
}

impl std::fmt::Display for DataStorageVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl From<DataStorageVariant> for ProtocolVariant {
    fn from(variant: DataStorageVariant) -> Self {
        match variant {
            DataStorageVariant::ProofOfBurn => ProtocolVariant::DataStorageProofOfBurn,
            DataStorageVariant::FileMetadata => ProtocolVariant::DataStorageFileMetadata,
            DataStorageVariant::EmbeddedData => ProtocolVariant::DataStorageEmbeddedData,
            DataStorageVariant::WikiLeaksCablegate => {
                ProtocolVariant::DataStorageWikiLeaksCablegate
            }
            DataStorageVariant::BitcoinWhitepaper => ProtocolVariant::DataStorageBitcoinWhitepaper,
            DataStorageVariant::NullData => ProtocolVariant::DataStorageNullData,
            DataStorageVariant::Generic => ProtocolVariant::DataStorageGeneric,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_display_names() {
        assert_eq!(
            DataStorageVariant::ProofOfBurn.display_name(),
            "Proof of Burn"
        );
        assert_eq!(
            DataStorageVariant::WikiLeaksCablegate.display_name(),
            "WikiLeaks Cablegate"
        );
        assert_eq!(
            DataStorageVariant::BitcoinWhitepaper.display_name(),
            "Bitcoin Whitepaper"
        );
        assert_eq!(DataStorageVariant::Generic.display_name(), "Generic");
    }

    #[test]
    fn test_variant_to_protocol_variant() {
        assert_eq!(
            ProtocolVariant::from(DataStorageVariant::ProofOfBurn),
            ProtocolVariant::DataStorageProofOfBurn
        );
        assert_eq!(
            ProtocolVariant::from(DataStorageVariant::WikiLeaksCablegate),
            ProtocolVariant::DataStorageWikiLeaksCablegate
        );
        assert_eq!(
            ProtocolVariant::from(DataStorageVariant::BitcoinWhitepaper),
            ProtocolVariant::DataStorageBitcoinWhitepaper
        );
        assert_eq!(
            ProtocolVariant::from(DataStorageVariant::Generic),
            ProtocolVariant::DataStorageGeneric
        );
    }
}
