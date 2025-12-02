//! LikelyLegitimateMultisig protocol type definitions
//!
//! Defines variants for P2MS outputs that appear to be legitimate multisig
//! transactions rather than data storage.

use super::ProtocolVariant;
use serde::{Deserialize, Serialize};

/// LikelyLegitimateMultisig variant types
///
/// These variants represent different patterns of apparently legitimate
/// multisig usage after all data storage protocols have been ruled out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LikelyLegitimateVariant {
    /// Standard multisig with all valid, unique EC points
    ///
    /// All pubkeys pass secp256k1 validation and are unique.
    /// This is the expected pattern for legitimate multisig wallets.
    Standard,

    /// Valid EC points but with duplicate keys
    ///
    /// All pubkeys are valid EC points, but some keys are duplicated.
    /// This is unusual but still technically valid for multisig.
    DuplicateKeys,

    /// Mix of valid EC points and all-null pubkeys
    ///
    /// Contains valid EC points plus all-zero pubkeys (0x00...00).
    /// Spendable if M ≤ number of real keys.
    WithNullKey,
}

impl LikelyLegitimateVariant {
    /// Get the display name for this variant
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Standard => "Legitimate Multisig",
            Self::DuplicateKeys => "Legitimate Multisig (Duplicate Keys)",
            Self::WithNullKey => "Legitimate Multisig (Null-Padded)",
        }
    }
}

impl std::fmt::Display for LikelyLegitimateVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl From<LikelyLegitimateVariant> for ProtocolVariant {
    fn from(variant: LikelyLegitimateVariant) -> Self {
        match variant {
            LikelyLegitimateVariant::Standard => ProtocolVariant::LegitimateMultisig,
            LikelyLegitimateVariant::DuplicateKeys => ProtocolVariant::LegitimateMultisigDupeKeys,
            LikelyLegitimateVariant::WithNullKey => ProtocolVariant::LegitimateMultisigWithNullKey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_display_names() {
        assert_eq!(
            LikelyLegitimateVariant::Standard.display_name(),
            "Legitimate Multisig"
        );
        assert_eq!(
            LikelyLegitimateVariant::DuplicateKeys.display_name(),
            "Legitimate Multisig (Duplicate Keys)"
        );
        assert_eq!(
            LikelyLegitimateVariant::WithNullKey.display_name(),
            "Legitimate Multisig (Null-Padded)"
        );
    }

    #[test]
    fn test_variant_to_protocol_variant() {
        assert_eq!(
            ProtocolVariant::from(LikelyLegitimateVariant::Standard),
            ProtocolVariant::LegitimateMultisig
        );
        assert_eq!(
            ProtocolVariant::from(LikelyLegitimateVariant::DuplicateKeys),
            ProtocolVariant::LegitimateMultisigDupeKeys
        );
        assert_eq!(
            ProtocolVariant::from(LikelyLegitimateVariant::WithNullKey),
            ProtocolVariant::LegitimateMultisigWithNullKey
        );
    }
}
