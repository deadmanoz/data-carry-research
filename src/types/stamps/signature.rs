//! Bitcoin Stamps signature variant types
//!
//! The Bitcoin Stamps protocol uses "stamp:" or "stamps:" signatures (case-insensitive)
//! in ARC4-decrypted P2MS data. This module tracks all observed variants for population statistics.

use serde::{Deserialize, Serialize};

/// Bitcoin Stamps signature variants found in real transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampSignature {
    /// "stamp:" - lowercase singular (most common, canonical per protocol spec)
    StampLower,
    /// "STAMP:" - uppercase singular (used in Counterparty-embedded stamps)
    StampUpper,
    /// "stamps:" - lowercase plural (rare variant observed in wild)
    StampsLower,
    /// "STAMPS:" - uppercase plural (theoretical, for completeness)
    StampsUpper,
}

impl StampSignature {
    /// Get the byte string for this signature variant
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::StampLower => b"stamp:",
            Self::StampUpper => b"STAMP:",
            Self::StampsLower => b"stamps:",
            Self::StampsUpper => b"STAMPS:",
        }
    }

    /// Get the length of this signature in bytes
    pub const fn len(&self) -> usize {
        match self {
            Self::StampLower | Self::StampUpper => 6,
            Self::StampsLower | Self::StampsUpper => 7,
        }
    }

    /// Check if this signature is empty (always false for enum variants)
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Check if this is a plural variant
    pub const fn is_plural(&self) -> bool {
        matches!(self, Self::StampsLower | Self::StampsUpper)
    }

    /// Check if this is an uppercase variant
    pub const fn is_uppercase(&self) -> bool {
        matches!(self, Self::StampUpper | Self::StampsUpper)
    }

    /// All possible signature variants (ordered by likelihood: singular before plural, lower before upper)
    pub const ALL: [StampSignature; 4] = [
        Self::StampLower,  // Most common
        Self::StampUpper,  // Counterparty-embedded
        Self::StampsLower, // Rare
        Self::StampsUpper, // Theoretical
    ];
}

impl std::fmt::Display for StampSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", std::str::from_utf8(self.as_bytes()).unwrap())
    }
}

impl std::str::FromStr for StampSignature {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Literal tokens (for database storage)
            "stamp:" => Ok(Self::StampLower),
            "STAMP:" => Ok(Self::StampUpper),
            "stamps:" => Ok(Self::StampsLower),
            "STAMPS:" => Ok(Self::StampsUpper),
            // Enum names (for backfills/fixtures tolerance)
            "StampLower" => Ok(Self::StampLower),
            "StampUpper" => Ok(Self::StampUpper),
            "StampsLower" => Ok(Self::StampsLower),
            "StampsUpper" => Ok(Self::StampsUpper),
            _ => Err(format!("Unknown stamp signature: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stamp_signature_display_fromstr_roundtrip() {
        for variant in StampSignature::ALL {
            let display_str = variant.to_string();
            let parsed: StampSignature = display_str.parse().unwrap();
            assert_eq!(variant, parsed, "Failed round-trip for {:?}", variant);
        }
    }

    #[test]
    fn test_stamp_signature_display_outputs_literal() {
        assert_eq!(StampSignature::StampLower.to_string(), "stamp:");
        assert_eq!(StampSignature::StampUpper.to_string(), "STAMP:");
        assert_eq!(StampSignature::StampsLower.to_string(), "stamps:");
        assert_eq!(StampSignature::StampsUpper.to_string(), "STAMPS:");
    }

    #[test]
    fn test_stamp_signature_fromstr_literal_tokens() {
        assert_eq!("stamp:".parse(), Ok(StampSignature::StampLower));
        assert_eq!("STAMP:".parse(), Ok(StampSignature::StampUpper));
        assert_eq!("stamps:".parse(), Ok(StampSignature::StampsLower));
        assert_eq!("STAMPS:".parse(), Ok(StampSignature::StampsUpper));
    }

    #[test]
    fn test_stamp_signature_fromstr_enum_names() {
        assert_eq!("StampLower".parse(), Ok(StampSignature::StampLower));
        assert_eq!("StampUpper".parse(), Ok(StampSignature::StampUpper));
        assert_eq!("StampsLower".parse(), Ok(StampSignature::StampsLower));
        assert_eq!("StampsUpper".parse(), Ok(StampSignature::StampsUpper));
    }

    #[test]
    fn test_stamp_signature_fromstr_invalid() {
        let result: Result<StampSignature, _> = "invalid".parse();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown stamp signature"));
    }

    #[test]
    fn test_signature_variant_survives_database_roundtrip() {
        let variant = StampSignature::StampUpper;
        let signature_str = variant.to_string();

        let meta = serde_json::json!({
            "transport_protocol": "Counterparty",
            "stamp_signature_variant": signature_str.clone(),
            "outputs": [],
            "total_outputs": 2,
            "concatenated_data_size": 1024,
            "stamp_signature_offset": 42,
            "has_dual_signature": true,
            "encoding_format": "Counterparty embedded"
        })
        .to_string();

        let parsed: serde_json::Value = serde_json::from_str(&meta).unwrap();
        let extracted = parsed["stamp_signature_variant"].as_str().unwrap();

        assert_eq!(extracted, "STAMP:");

        let recovered: StampSignature = extracted.parse().unwrap();
        assert_eq!(variant, recovered);
    }

    #[test]
    fn test_signature_variant_roundtrip_all_variants() {
        for variant in StampSignature::ALL {
            let signature_str = variant.to_string();

            let meta = serde_json::json!({
                "transport_protocol": "Pure Bitcoin Stamps",
                "stamp_signature_variant": signature_str,
                "outputs": [],
            })
            .to_string();

            let parsed: serde_json::Value = serde_json::from_str(&meta).unwrap();
            let extracted = parsed["stamp_signature_variant"].as_str().unwrap();
            let recovered: StampSignature = extracted.parse().unwrap();

            assert_eq!(
                variant, recovered,
                "Failed database roundtrip for {:?}",
                variant
            );
        }
    }
}
