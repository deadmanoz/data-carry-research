//! Centralised burn pattern definitions for all protocols
//! This module provides a single source of truth for burn pattern detection

use serde::{Deserialize, Serialize};

/// Types of burn patterns detected across protocols
/// Only includes actual burn patterns (not protocol identifiers)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BurnPatternType {
    // Bitcoin Stamps patterns (4 types for 5 known keys)
    /// 022222... pattern (most common Stamps burn)
    Stamps22Pattern,
    /// 033333... pattern
    Stamps33Pattern,
    /// 020202... alternating pattern
    Stamps0202Pattern,
    /// 030303... alternating pattern (covers both 02 and 03 endings)
    Stamps0303Pattern,

    // DataStorage patterns
    /// All 0xFF pattern indicating proof-of-burn for data destruction
    ProofOfBurn,

    // Suspicious patterns
    /// Unknown pattern that looks like an intentional burn
    UnknownBurn,
}

/// Detected burn pattern with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnPattern {
    pub pattern_type: BurnPatternType,
    pub vout: u32,            // Which P2MS output contains this pattern
    pub pubkey_index: u8,     // Which pubkey within that output
    pub pattern_data: String, // The actual burn key hex
}

/// Bitcoin Stamps burn keys (5 distinct keys for 4 pattern types)
/// These are compressed pubkeys used as burn indicators in P2MS outputs
pub const STAMPS_BURN_KEYS: &[&str] = &[
    "022222222222222222222222222222222222222222222222222222222222222222",
    "033333333333333333333333333333333333333333333333333333333333333333",
    "020202020202020202020202020202020202020202020202020202020202020202",
    "030303030303030303030303030303030303030303030303030303030303030302", // variant 1
    "030303030303030303030303030303030303030303030303030303030303030303", // variant 2
];

/// DataStorage proof-of-burn pattern (all 0xFF for 32 bytes in hex = 64 chars)
pub const PROOF_OF_BURN_PATTERN: &str =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Check if a pubkey is a known Bitcoin Stamps burn key
pub fn is_stamps_burn_key(key: &str) -> bool {
    STAMPS_BURN_KEYS
        .iter()
        .any(|&burn_key| key.eq_ignore_ascii_case(burn_key))
}

/// Check if a pubkey is a proof-of-burn pattern (all 0xFF)
pub fn is_proof_of_burn_key(key: &str) -> bool {
    // Check both compressed (33 bytes = 66 hex chars) and uncompressed formats
    // Compressed: 02/03 prefix + 32 bytes of FF
    let compressed_02 = format!("02{}", PROOF_OF_BURN_PATTERN);
    let compressed_03 = format!("03{}", PROOF_OF_BURN_PATTERN);
    // Uncompressed: 04 prefix + 64 bytes of FF
    let uncompressed = format!("04{}{}", PROOF_OF_BURN_PATTERN, PROOF_OF_BURN_PATTERN);

    key.eq_ignore_ascii_case(&compressed_02)
        || key.eq_ignore_ascii_case(&compressed_03)
        || key.eq_ignore_ascii_case(&uncompressed)
        || key.eq_ignore_ascii_case(PROOF_OF_BURN_PATTERN)
}

/// Classify a Bitcoin Stamps burn pattern by its specific type
pub fn classify_stamps_burn(key: &str) -> Option<BurnPatternType> {
    let key_lower = key.to_lowercase();

    if key_lower == STAMPS_BURN_KEYS[0].to_lowercase() {
        Some(BurnPatternType::Stamps22Pattern)
    } else if key_lower == STAMPS_BURN_KEYS[1].to_lowercase() {
        Some(BurnPatternType::Stamps33Pattern)
    } else if key_lower == STAMPS_BURN_KEYS[2].to_lowercase() {
        Some(BurnPatternType::Stamps0202Pattern)
    } else if key_lower == STAMPS_BURN_KEYS[3].to_lowercase()
        || key_lower == STAMPS_BURN_KEYS[4].to_lowercase()
    {
        Some(BurnPatternType::Stamps0303Pattern)
    } else {
        None
    }
}

/// Classify any burn pattern type
pub fn classify_burn_pattern(key: &str) -> Option<BurnPatternType> {
    // Check for exact Stamps patterns first
    if let Some(stamps_type) = classify_stamps_burn(key) {
        return Some(stamps_type);
    }

    // Check for proof-of-burn pattern
    if is_proof_of_burn_key(key) {
        return Some(BurnPatternType::ProofOfBurn);
    }

    // Check for suspicious patterns
    if is_suspicious_pattern(key) {
        return Some(BurnPatternType::UnknownBurn);
    }

    None
}

/// Detect intentionally repetitive compressed pubkeys that suggest an unknown burn pattern.
///
/// This conservative heuristic only flags pubkeys that:
/// - Are exactly 66 hex characters long (compressed form) and start with 02/03
/// - Are not already recognised as Stamps or Proof-of-Burn patterns
/// - Use the same hex character for every position after the 02/03 prefix
///
/// Counterparty messages and other mixed-content payloads therefore avoid being misclassified.
fn is_suspicious_pattern(pubkey_hex: &str) -> bool {
    /// Compressed SEC256k1 public keys are 33 bytes / 66 hex characters and start with 02/03.
    const COMPRESSED_PUBKEY_HEX_LEN: usize = 66;

    if pubkey_hex.len() != COMPRESSED_PUBKEY_HEX_LEN {
        return false;
    }

    if !(pubkey_hex.starts_with("02") || pubkey_hex.starts_with("03")) {
        return false;
    }

    // Known protocol patterns are handled earlier in classification.
    if is_stamps_burn_key(pubkey_hex) || is_proof_of_burn_key(pubkey_hex) {
        return false;
    }

    let body = &pubkey_hex[2..];
    if body.is_empty() {
        return false;
    }

    let first_char = body.chars().next().unwrap().to_ascii_lowercase();
    body.chars().all(|c| c.to_ascii_lowercase() == first_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stamps_burn_key_detection() {
        assert!(is_stamps_burn_key(
            "022222222222222222222222222222222222222222222222222222222222222222"
        ));
        assert!(is_stamps_burn_key(
            "033333333333333333333333333333333333333333333333333333333333333333"
        ));
        assert!(is_stamps_burn_key(
            "020202020202020202020202020202020202020202020202020202020202020202"
        ));
        assert!(is_stamps_burn_key(
            "030303030303030303030303030303030303030303030303030303030303030302"
        ));
        assert!(is_stamps_burn_key(
            "030303030303030303030303030303030303030303030303030303030303030303"
        ));
        assert!(!is_stamps_burn_key(
            "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2"
        ));
    }

    #[test]
    fn test_proof_of_burn_detection() {
        assert!(is_proof_of_burn_key(
            "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        assert!(is_proof_of_burn_key(
            "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        assert!(is_proof_of_burn_key(
            "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
        assert!(!is_proof_of_burn_key(
            "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00"
        ));
    }

    #[test]
    fn test_stamps_burn_classification() {
        assert_eq!(
            classify_stamps_burn(
                "022222222222222222222222222222222222222222222222222222222222222222"
            ),
            Some(BurnPatternType::Stamps22Pattern)
        );
        assert_eq!(
            classify_stamps_burn(
                "033333333333333333333333333333333333333333333333333333333333333333"
            ),
            Some(BurnPatternType::Stamps33Pattern)
        );
        assert_eq!(
            classify_stamps_burn(
                "020202020202020202020202020202020202020202020202020202020202020202"
            ),
            Some(BurnPatternType::Stamps0202Pattern)
        );
        assert_eq!(
            classify_stamps_burn(
                "030303030303030303030303030303030303030303030303030303030303030302"
            ),
            Some(BurnPatternType::Stamps0303Pattern)
        );
        assert_eq!(
            classify_stamps_burn(
                "030303030303030303030303030303030303030303030303030303030303030303"
            ),
            Some(BurnPatternType::Stamps0303Pattern)
        );
        assert_eq!(
            classify_stamps_burn(
                "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2"
            ),
            None
        );
    }

    #[test]
    fn test_burn_pattern_classification() {
        // Stamps pattern
        let pattern = classify_burn_pattern(
            "022222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        assert_eq!(pattern, BurnPatternType::Stamps22Pattern);

        // Proof of burn
        let pattern = classify_burn_pattern(
            "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .unwrap();
        assert_eq!(pattern, BurnPatternType::ProofOfBurn);

        // Suspicious pattern
        let pattern = classify_burn_pattern(
            "020000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(pattern, BurnPatternType::UnknownBurn);

        // Normal key - no classification
        assert!(classify_burn_pattern(
            "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2"
        )
        .is_none());
    }

    #[test]
    fn test_suspicious_pattern_detection() {
        let all_zeros = format!("02{}", "0".repeat(64));
        assert!(is_suspicious_pattern(&all_zeros));

        let all_ones = format!("02{}", "1".repeat(64));
        assert!(is_suspicious_pattern(&all_ones));

        let all_fours = format!("03{}", "4".repeat(64));
        assert!(is_suspicious_pattern(&all_fours));

        let proof_of_burn = format!("02{}", "f".repeat(64));
        assert!(!is_suspicious_pattern(&proof_of_burn));

        assert!(!is_suspicious_pattern(
            "022222222222222222222222222222222222222222222222222222222222222222"
        ));
        assert!(!is_suspicious_pattern(
            "033333333333333333333333333333333333333333333333333333333333333333"
        ));

        let counterparty_message = format!("1{}", "0".repeat(65));
        assert!(!is_suspicious_pattern(&counterparty_message));

        assert!(!is_suspicious_pattern(
            "02b3622bf4017bdfe317c58aed5f4c753f206b7db896046fa7d774bbc4bf7f8dc2"
        ));
        assert!(!is_suspicious_pattern("short_key"));
    }
}
