//! LikelyDataStorage protocol type definitions
//!
//! Defines variants for P2MS outputs that exhibit data storage patterns
//! but don't match any specific protocol signature.

use super::ProtocolVariant;
use serde::{Deserialize, Serialize};

/// LikelyDataStorage variant types
///
/// These variants represent different heuristic patterns that suggest
/// data embedding rather than legitimate multisig usage.
///
/// Detection order (strictly enforced, mutually exclusive):
/// 1. InvalidECPoint (highest confidence - cryptographic proof)
/// 2. HighOutputCount (requires ALL valid EC points)
/// 3. DustAmount (requires ALL valid EC points)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LikelyDataStorageVariant {
    /// One or more pubkeys fail secp256k1 EC point validation
    ///
    /// Highest confidence indicator - legitimate multisig wallets would never
    /// generate keys that aren't on the secp256k1 curve.
    InvalidECPoint,

    /// 5+ P2MS outputs in a single transaction with ALL valid EC points
    ///
    /// Legitimate multisig typically uses 1-2 outputs; 5+ suggests batch data embedding.
    HighOutputCount,

    /// All P2MS outputs have dust-level amounts (≤1000 satoshis) with ALL valid EC points
    ///
    /// Data-carrying protocols use minimal amounts to reduce costs while still being
    /// accepted by the network (e.g., October 2024+ mystery protocol at 800 sats).
    DustAmount,
}

impl LikelyDataStorageVariant {
    /// Get the display name for this variant
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::InvalidECPoint => "Invalid EC Point",
            Self::HighOutputCount => "High Output Count",
            Self::DustAmount => "Dust Amount",
        }
    }
}

impl std::fmt::Display for LikelyDataStorageVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl From<LikelyDataStorageVariant> for ProtocolVariant {
    fn from(variant: LikelyDataStorageVariant) -> Self {
        match variant {
            LikelyDataStorageVariant::InvalidECPoint => {
                ProtocolVariant::LikelyDataStorageInvalidECPoint
            }
            LikelyDataStorageVariant::HighOutputCount => {
                ProtocolVariant::LikelyDataStorageHighOutputCount
            }
            LikelyDataStorageVariant::DustAmount => ProtocolVariant::LikelyDataStorageDustAmount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_display_names() {
        assert_eq!(
            LikelyDataStorageVariant::InvalidECPoint.display_name(),
            "Invalid EC Point"
        );
        assert_eq!(
            LikelyDataStorageVariant::HighOutputCount.display_name(),
            "High Output Count"
        );
        assert_eq!(
            LikelyDataStorageVariant::DustAmount.display_name(),
            "Dust Amount"
        );
    }

    #[test]
    fn test_variant_to_protocol_variant() {
        assert_eq!(
            ProtocolVariant::from(LikelyDataStorageVariant::InvalidECPoint),
            ProtocolVariant::LikelyDataStorageInvalidECPoint
        );
        assert_eq!(
            ProtocolVariant::from(LikelyDataStorageVariant::HighOutputCount),
            ProtocolVariant::LikelyDataStorageHighOutputCount
        );
        assert_eq!(
            ProtocolVariant::from(LikelyDataStorageVariant::DustAmount),
            ProtocolVariant::LikelyDataStorageDustAmount
        );
    }

    #[test]
    fn test_variant_display_trait() {
        assert_eq!(
            format!("{}", LikelyDataStorageVariant::InvalidECPoint),
            "Invalid EC Point"
        );
    }
}
