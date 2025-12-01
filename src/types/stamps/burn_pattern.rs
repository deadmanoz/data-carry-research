//! Bitcoin Stamps burn pattern types
//!
//! These correspond to the specific burn keys used in P2MS outputs.

use crate::types::burn_patterns::STAMPS_BURN_KEYS;
use serde::{Deserialize, Serialize};

/// Bitcoin Stamps burn pattern types
/// These correspond to the specific burn keys used in P2MS outputs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampsBurnPattern {
    /// 022222... pattern (most common)
    Stamps22,
    /// 033333... pattern
    Stamps33,
    /// 020202... alternating pattern
    Stamps0202,
    /// 030303... alternating pattern (two variants)
    Stamps0303,
}

#[allow(dead_code)]
impl StampsBurnPattern {
    /// Get the burn key hex string for this pattern
    pub fn burn_key(&self) -> &'static str {
        match self {
            StampsBurnPattern::Stamps22 => STAMPS_BURN_KEYS[0],
            StampsBurnPattern::Stamps33 => STAMPS_BURN_KEYS[1],
            StampsBurnPattern::Stamps0202 => STAMPS_BURN_KEYS[2],
            StampsBurnPattern::Stamps0303 => STAMPS_BURN_KEYS[3], // Default to first variant
        }
    }

    /// Check if a pubkey hex matches this burn pattern
    pub fn matches_pubkey(&self, pubkey_hex: &str) -> bool {
        match self {
            StampsBurnPattern::Stamps22 => pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[0]),
            StampsBurnPattern::Stamps33 => pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[1]),
            StampsBurnPattern::Stamps0202 => pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[2]),
            StampsBurnPattern::Stamps0303 => {
                pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[3])
                    || pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[4])
            }
        }
    }

    /// Parse a pubkey hex to determine the burn pattern type
    pub fn from_pubkey(pubkey_hex: &str) -> Option<Self> {
        [
            Self::Stamps22,
            Self::Stamps33,
            Self::Stamps0202,
            Self::Stamps0303,
        ]
        .into_iter()
        .find(|pattern| pattern.matches_pubkey(pubkey_hex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burn_pattern_matching() {
        let stamps22_key = "022222222222222222222222222222222222222222222222222222222222222222";
        assert_eq!(
            StampsBurnPattern::from_pubkey(stamps22_key),
            Some(StampsBurnPattern::Stamps22)
        );
        assert!(StampsBurnPattern::Stamps22.matches_pubkey(stamps22_key));
    }
}
