//! Spendability analysis types for P2MS outputs
//!
//! This module defines types for analysing whether P2MS outputs are spendable
//! (can theoretically be unlocked) or permanently unspendable (UTXO bloat).

use std::fmt;
use std::str::FromStr;

/// Reason why a P2MS output is spendable or unspendable
///
/// This enum classifies the spendability based on the public key composition
/// within the P2MS script.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpendabilityReason {
    /// All public keys are known burn patterns (e.g., Bitcoin Stamps burn keys)
    ///
    /// **Result**: Unspendable - no valid keys for unlocking
    AllBurnKeys,

    /// Contains at least one real public key (valid EC point)
    ///
    /// **Result**: Spendable - can theoretically be unlocked with correct signatures
    ///
    /// Common in:
    /// - Counterparty (real pubkey for multisig unlock)
    /// - Omni Layer (sender pubkey included)
    ContainsRealPubkey,

    /// Has real pubkeys but not enough to meet M-of-N threshold
    ///
    /// **Result**: Unspendable - cannot gather M signatures when real_keys < M
    ///
    /// Example: 2-of-3 multisig with only 1 valid EC point + 2 null keys
    /// Cannot sign with 2 keys when only 1 real key exists.
    InsufficientRealKeys,

    /// All public keys are valid EC points on secp256k1 curve
    ///
    /// **Result**: Spendable - likely legitimate multisig
    ///
    /// Common in:
    /// - LikelyLegitimateMultisig (standard multisig wallets)
    AllValidECPoints,

    /// Mix of burn patterns and non-EC data keys (but no valid EC points)
    ///
    /// **Result**: Unspendable - no valid keys for unlocking
    MixedBurnAndData,

    /// All public keys are data (not burn patterns, not valid EC points)
    ///
    /// **Result**: Unspendable - keys are pure data, cannot sign
    AllDataKeys,
}

impl fmt::Display for SpendabilityReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SpendabilityReason::AllBurnKeys => "AllBurnKeys",
            SpendabilityReason::ContainsRealPubkey => "ContainsRealPubkey",
            SpendabilityReason::InsufficientRealKeys => "InsufficientRealKeys",
            SpendabilityReason::AllValidECPoints => "AllValidECPoints",
            SpendabilityReason::MixedBurnAndData => "MixedBurnAndData",
            SpendabilityReason::AllDataKeys => "AllDataKeys",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for SpendabilityReason {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AllBurnKeys" => Ok(SpendabilityReason::AllBurnKeys),
            "ContainsRealPubkey" => Ok(SpendabilityReason::ContainsRealPubkey),
            "InsufficientRealKeys" => Ok(SpendabilityReason::InsufficientRealKeys),
            "AllValidECPoints" => Ok(SpendabilityReason::AllValidECPoints),
            "MixedBurnAndData" => Ok(SpendabilityReason::MixedBurnAndData),
            "AllDataKeys" => Ok(SpendabilityReason::AllDataKeys),
            _ => Err(format!("Unknown spendability reason: {}", s)),
        }
    }
}

/// Result of spendability analysis for a P2MS output
///
/// This structure provides complete information about whether an output
/// can theoretically be spent and the composition of its public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendabilityResult {
    /// Whether this output can theoretically be spent
    ///
    /// - `true`: At least one valid EC point exists for signing
    /// - `false`: No valid keys, output is permanently unspendable
    pub is_spendable: bool,

    /// Reason explaining the spendability determination
    pub reason: SpendabilityReason,

    /// Number of real public keys (valid EC points)
    pub real_pubkey_count: u8,

    /// Number of known burn keys
    pub burn_key_count: u8,

    /// Number of data keys (not burn, not valid EC)
    pub data_key_count: u8,
}

impl SpendabilityResult {
    /// Create a new spendability result
    pub fn new(
        is_spendable: bool,
        reason: SpendabilityReason,
        real_pubkey_count: u8,
        burn_key_count: u8,
        data_key_count: u8,
    ) -> Self {
        Self {
            is_spendable,
            reason,
            real_pubkey_count,
            burn_key_count,
            data_key_count,
        }
    }

    /// Create result for unspendable output with all burn keys
    pub fn all_burn_keys(burn_count: u8) -> Self {
        Self {
            is_spendable: false,
            reason: SpendabilityReason::AllBurnKeys,
            real_pubkey_count: 0,
            burn_key_count: burn_count,
            data_key_count: 0,
        }
    }

    /// Create result for spendable output with real pubkeys
    pub fn contains_real_pubkey(real_count: u8, burn_count: u8, data_count: u8) -> Self {
        Self {
            is_spendable: true,
            reason: SpendabilityReason::ContainsRealPubkey,
            real_pubkey_count: real_count,
            burn_key_count: burn_count,
            data_key_count: data_count,
        }
    }

    /// Create result for unspendable output with insufficient real keys for M-of-N threshold
    pub fn insufficient_real_keys(real_count: u8, burn_count: u8, data_count: u8) -> Self {
        Self {
            is_spendable: false,
            reason: SpendabilityReason::InsufficientRealKeys,
            real_pubkey_count: real_count,
            burn_key_count: burn_count,
            data_key_count: data_count,
        }
    }

    /// Create result for spendable output with all valid EC points
    pub fn all_valid_ec_points(real_count: u8) -> Self {
        Self {
            is_spendable: true,
            reason: SpendabilityReason::AllValidECPoints,
            real_pubkey_count: real_count,
            burn_key_count: 0,
            data_key_count: 0,
        }
    }

    /// Create result for unspendable output with mixed burn and data keys
    pub fn mixed_burn_and_data(burn_count: u8, data_count: u8) -> Self {
        Self {
            is_spendable: false,
            reason: SpendabilityReason::MixedBurnAndData,
            real_pubkey_count: 0,
            burn_key_count: burn_count,
            data_key_count: data_count,
        }
    }

    /// Create result for unspendable output with all data keys
    pub fn all_data_keys(data_count: u8) -> Self {
        Self {
            is_spendable: false,
            reason: SpendabilityReason::AllDataKeys,
            real_pubkey_count: 0,
            burn_key_count: 0,
            data_key_count: data_count,
        }
    }

    /// Get total number of keys analysed
    pub fn total_keys(&self) -> u8 {
        self.real_pubkey_count + self.burn_key_count + self.data_key_count
    }

    /// Get a human-readable summary of the analysis
    pub fn summary(&self) -> String {
        format!(
            "{} (real: {}, burn: {}, data: {})",
            if self.is_spendable {
                "Spendable"
            } else {
                "Unspendable"
            },
            self.real_pubkey_count,
            self.burn_key_count,
            self.data_key_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spendability_reason_display() {
        assert_eq!(SpendabilityReason::AllBurnKeys.to_string(), "AllBurnKeys");
        assert_eq!(
            SpendabilityReason::ContainsRealPubkey.to_string(),
            "ContainsRealPubkey"
        );
        assert_eq!(
            SpendabilityReason::AllValidECPoints.to_string(),
            "AllValidECPoints"
        );
        assert_eq!(
            SpendabilityReason::MixedBurnAndData.to_string(),
            "MixedBurnAndData"
        );
        assert_eq!(SpendabilityReason::AllDataKeys.to_string(), "AllDataKeys");
    }

    #[test]
    fn test_spendability_reason_from_str() {
        assert_eq!(
            "AllBurnKeys".parse::<SpendabilityReason>().unwrap(),
            SpendabilityReason::AllBurnKeys
        );
        assert_eq!(
            "ContainsRealPubkey".parse::<SpendabilityReason>().unwrap(),
            SpendabilityReason::ContainsRealPubkey
        );
        assert_eq!(
            "AllValidECPoints".parse::<SpendabilityReason>().unwrap(),
            SpendabilityReason::AllValidECPoints
        );

        assert!("InvalidReason".parse::<SpendabilityReason>().is_err());
    }

    #[test]
    fn test_spendability_reason_roundtrip() {
        let reasons = vec![
            SpendabilityReason::AllBurnKeys,
            SpendabilityReason::ContainsRealPubkey,
            SpendabilityReason::AllValidECPoints,
            SpendabilityReason::MixedBurnAndData,
            SpendabilityReason::AllDataKeys,
        ];

        for reason in reasons {
            let s = reason.to_string();
            let parsed = s.parse::<SpendabilityReason>().unwrap();
            assert_eq!(reason, parsed);
        }
    }

    #[test]
    fn test_spendability_result_all_burn_keys() {
        let result = SpendabilityResult::all_burn_keys(3);
        assert!(!result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::AllBurnKeys);
        assert_eq!(result.real_pubkey_count, 0);
        assert_eq!(result.burn_key_count, 3);
        assert_eq!(result.data_key_count, 0);
        assert_eq!(result.total_keys(), 3);
    }

    #[test]
    fn test_spendability_result_contains_real_pubkey() {
        let result = SpendabilityResult::contains_real_pubkey(1, 2, 0);
        assert!(result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::ContainsRealPubkey);
        assert_eq!(result.real_pubkey_count, 1);
        assert_eq!(result.burn_key_count, 2);
        assert_eq!(result.data_key_count, 0);
        assert_eq!(result.total_keys(), 3);
    }

    #[test]
    fn test_spendability_result_all_valid_ec_points() {
        let result = SpendabilityResult::all_valid_ec_points(2);
        assert!(result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::AllValidECPoints);
        assert_eq!(result.real_pubkey_count, 2);
        assert_eq!(result.burn_key_count, 0);
        assert_eq!(result.data_key_count, 0);
        assert_eq!(result.total_keys(), 2);
    }

    #[test]
    fn test_spendability_result_summary() {
        let result = SpendabilityResult::contains_real_pubkey(1, 2, 0);
        let summary = result.summary();
        assert!(summary.contains("Spendable"));
        assert!(summary.contains("real: 1"));
        assert!(summary.contains("burn: 2"));
        assert!(summary.contains("data: 0"));
    }
}
