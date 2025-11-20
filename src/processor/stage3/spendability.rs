//! Spendability analysis for P2MS outputs
//!
//! This module analyses P2MS outputs to determine if they are spendable (can theoretically
//! be unlocked) or permanently unspendable (UTXO bloat). The analysis is based on the
//! composition of public keys within the multisig script.

use crate::analysis::pubkey_validator::validate_pubkeys;
use crate::types::burn_patterns::is_stamps_burn_key;
use crate::types::spendability::{SpendabilityReason, SpendabilityResult};
use crate::types::stamps::StampsTransport;
use crate::types::TransactionOutput;

/// Analyser for determining P2MS output spendability
pub struct SpendabilityAnalyser;

impl SpendabilityAnalyser {
    /// Analyse spendability for Bitcoin Stamps outputs
    ///
    /// ## Transport-Specific Behaviour
    ///
    /// - **Pure Bitcoin Stamps**: ALWAYS use burn keys → Always unspendable
    /// - **Counterparty Transport**: MAY use real keys → Check key composition:
    ///   - If burn keys present → Unspendable (even if real keys also present)
    ///   - If NO burn keys (only real keys) → Spendable
    ///
    /// # Arguments
    ///
    /// * `output` - The P2MS output to analyse
    /// * `transport` - Transport mechanism (Pure or Counterparty)
    ///
    /// # Returns
    ///
    /// SpendabilityResult with accurate key counts and appropriate reason
    ///
    /// # Key Precedence Rules
    ///
    /// **CRITICAL**: Burn key presence ALWAYS makes output unspendable,
    /// regardless of whether real signing keys are also present.
    pub fn analyse_stamps_output(
        output: &TransactionOutput,
        transport: StampsTransport,
    ) -> SpendabilityResult {
        // Extract pubkeys from multisig info
        let pubkeys = if let Some(info) = output.multisig_info() {
            info.pubkeys
        } else {
            // No multisig info, treat as unspendable
            return SpendabilityResult::all_burn_keys(0);
        };

        match transport {
            StampsTransport::Pure => {
                // Pure Stamps: ALWAYS use burn keys + data keys
                // Never have real signing keys
                let mut burn_count = 0u8;
                let mut data_count = 0u8;

                for pubkey in &pubkeys {
                    if is_stamps_burn_key(pubkey) {
                        burn_count += 1;
                    } else {
                        // Not a burn key = data key (Pure Stamps never use real keys)
                        data_count += 1;
                    }
                }

                // Pure Stamps are always unspendable
                if burn_count > 0 && data_count > 0 {
                    SpendabilityResult {
                        is_spendable: false,
                        reason: SpendabilityReason::MixedBurnAndData,
                        real_pubkey_count: 0, // Pure Stamps NEVER have real keys
                        burn_key_count: burn_count,
                        data_key_count: data_count,
                    }
                } else if burn_count > 0 {
                    SpendabilityResult {
                        is_spendable: false,
                        reason: SpendabilityReason::AllBurnKeys,
                        real_pubkey_count: 0,
                        burn_key_count: burn_count,
                        data_key_count: data_count,
                    }
                } else {
                    // All data keys (no burns) - shouldn't happen but handle it
                    SpendabilityResult {
                        is_spendable: false,
                        reason: SpendabilityReason::AllDataKeys,
                        real_pubkey_count: 0,
                        burn_key_count: 0,
                        data_key_count: data_count,
                    }
                }
            }
            StampsTransport::Counterparty => {
                // CP-transport: Check for burn keys FIRST
                // Burn key presence = UNSPENDABLE (even with real keys)
                // No burn keys = check EC points for spendability
                let mut burn_count = 0u8;
                let mut real_count = 0u8;
                let mut data_count = 0u8;

                for pubkey in &pubkeys {
                    if is_stamps_burn_key(pubkey) {
                        burn_count += 1;
                    } else {
                        // Validate EC point
                        let validation = validate_pubkeys(&[pubkey.clone()]);
                        if validation.all_valid_ec_points {
                            real_count += 1;
                        } else {
                            data_count += 1;
                        }
                    }
                }

                // CRITICAL: Burn key presence = UNSPENDABLE
                // (Even if real keys also present in the multisig)
                if burn_count > 0 {
                    // Has burn keys → unspendable
                    SpendabilityResult {
                        is_spendable: false,
                        reason: if real_count > 0 || data_count > 0 {
                            // Burn keys mixed with real or data keys
                            SpendabilityReason::MixedBurnAndData
                        } else {
                            // Only burn keys
                            SpendabilityReason::AllBurnKeys
                        },
                        real_pubkey_count: real_count,
                        burn_key_count: burn_count,
                        data_key_count: data_count,
                    }
                } else if real_count > 0 {
                    // No burn keys + has real keys → SPENDABLE
                    SpendabilityResult::contains_real_pubkey(real_count, 0, data_count)
                } else if data_count > 0 {
                    // No burn keys, no real keys, only data → unspendable
                    SpendabilityResult::all_data_keys(data_count)
                } else {
                    // Should never happen (empty pubkeys)
                    SpendabilityResult::all_data_keys(0)
                }
            }
        }
    }

    /// Analyse spendability for Counterparty outputs
    ///
    /// Counterparty outputs are ALWAYS spendable because they include:
    /// - A real public key for multisig unlock
    /// - Data keys for protocol encoding
    ///
    /// The real pubkey (typically first in 1-of-N) allows spending with the correct signature.
    ///
    /// # Returns
    /// Always returns spendable with `ContainsRealPubkey` reason
    pub fn analyse_counterparty_output(output: &TransactionOutput) -> SpendabilityResult {
        let pubkeys = if let Some(info) = output.multisig_info() {
            info.pubkeys
        } else {
            // No multisig info, default to spendable (conservative)
            return SpendabilityResult::contains_real_pubkey(1, 0, 0);
        };

        Self::analyse_pubkey_mix(&pubkeys, true)
    }

    /// Analyse spendability for Omni Layer outputs
    ///
    /// Omni Layer outputs are ALWAYS spendable because they include:
    /// - The sender's public key (required for protocol)
    /// - Data keys for obfuscated packet encoding
    ///
    /// The sender pubkey allows spending with the sender's signature.
    ///
    /// # Returns
    /// Always returns spendable with `ContainsRealPubkey` reason
    pub fn analyse_omni_output(output: &TransactionOutput) -> SpendabilityResult {
        let pubkeys = if let Some(info) = output.multisig_info() {
            info.pubkeys
        } else {
            // No multisig info, default to spendable (conservative)
            return SpendabilityResult::contains_real_pubkey(1, 0, 0);
        };

        Self::analyse_pubkey_mix(&pubkeys, true)
    }

    /// Analyse spendability for LikelyLegitimateMultisig outputs
    ///
    /// LikelyLegitimateMultisig outputs are typically spendable because:
    /// - All public keys are either valid EC points or null placeholders
    /// - Standard multisig wallet usage
    /// - Can be unlocked with correct M-of-N signatures
    ///
    /// # Special Case: Null-Padded Multisig
    /// Some outputs use null keys (all bytes = 0x00) as placeholders:
    /// - If real_keys >= required_sigs → Spendable
    /// - If real_keys < required_sigs → Unspendable (InsufficientRealKeys)
    ///
    /// # Returns
    /// Spendability result based on M-of-N threshold check
    pub fn analyse_legitimate_output(output: &TransactionOutput) -> SpendabilityResult {
        use crate::analysis::pubkey_validator::validate_pubkeys;

        let info = if let Some(info) = output.multisig_info() {
            info
        } else {
            // No multisig info, default to spendable
            return SpendabilityResult::all_valid_ec_points(0);
        };

        // Validate pubkeys to detect null keys
        let validation = validate_pubkeys(&info.pubkeys);

        // Real pubkey count = valid EC points (null keys are tracked separately now)
        let real_pubkey_count = validation.valid_keys as u8;
        let null_key_count = validation.null_key_count as u8;

        // Check M-of-N threshold for null-padded outputs
        if validation.null_key_count > 0 {
            // Null-padded multisig: check if we have enough real keys to meet M threshold
            if (real_pubkey_count as u32) < info.required_sigs {
                // Cannot gather M signatures when real_keys < M
                return SpendabilityResult::insufficient_real_keys(
                    real_pubkey_count,
                    0, // No burn keys in legitimate multisig
                    null_key_count,
                );
            }
        }

        // All checks passed - spendable with all valid EC points
        SpendabilityResult::all_valid_ec_points(real_pubkey_count)
    }

    /// Generic spendability analysis for unknown or mixed protocols
    ///
    /// This performs comprehensive analysis by:
    /// 1. Checking for burn key patterns
    /// 2. Validating EC points
    /// 3. Classifying remaining keys as data
    ///
    /// # Logic
    /// - If ANY valid EC point exists → Spendable (ContainsRealPubkey)
    /// - If ALL keys are burn patterns → Unspendable (AllBurnKeys)
    /// - If mix of burn + data (no EC) → Unspendable (MixedBurnAndData)
    /// - If ALL keys are data (no EC, no burn) → Unspendable (AllDataKeys)
    pub fn analyse_generic_output(output: &TransactionOutput) -> SpendabilityResult {
        let pubkeys = if let Some(info) = output.multisig_info() {
            info.pubkeys
        } else {
            // No multisig info, assume unspendable
            return SpendabilityResult::all_data_keys(0);
        };

        Self::analyse_pubkey_mix(&pubkeys, false)
    }

    /// Internal helper: Analyse the mix of pubkeys to determine spendability
    ///
    /// # Arguments
    /// * `pubkeys` - Vector of public key hex strings
    /// * `assume_has_real` - If true, assume at least one real key exists (Counterparty/Omni optimisation)
    ///
    /// # Returns
    /// SpendabilityResult with detailed key counts and reason
    fn analyse_pubkey_mix(pubkeys: &[String], assume_has_real: bool) -> SpendabilityResult {
        if pubkeys.is_empty() {
            return SpendabilityResult::all_data_keys(0);
        }

        // For Counterparty/Omni, we ASSUME there's a real key, but verify
        if assume_has_real {
            let mut real_count = 0u8;
            let mut burn_count = 0u8;
            let mut data_count = 0u8;

            for pubkey in pubkeys {
                if is_stamps_burn_key(pubkey) {
                    burn_count += 1;
                } else {
                    // Validate EC point
                    let validation = validate_pubkeys(&[pubkey.clone()]);
                    // Check for REAL EC points (null keys have valid_keys == 0)
                    if validation.all_valid_ec_points && validation.valid_keys > 0 {
                        real_count += 1;
                    } else if validation.null_key_count > 0 {
                        // Null keys are treated as data (placeholders, not real keys)
                        data_count += 1;
                    } else {
                        data_count += 1;
                    }
                }
            }

            // SAFETY: Never mark spendable without evidence of a real key
            // If assumption fails (real_count == 0), fall back to full analysis
            if real_count == 0 {
                // Fall through to full analysis below
            } else {
                // Have at least one real key - safe to mark spendable
                return SpendabilityResult::contains_real_pubkey(
                    real_count, burn_count, data_count,
                );
            }
        }

        // Full analysis for unknown/generic protocols
        let mut real_count = 0u8;
        let mut burn_count = 0u8;
        let mut data_count = 0u8;

        for pubkey in pubkeys {
            if is_stamps_burn_key(pubkey) {
                burn_count += 1;
            } else {
                // Validate EC point
                let validation = validate_pubkeys(&[pubkey.clone()]);
                // Check for REAL EC points (null keys have valid_keys == 0)
                if validation.all_valid_ec_points && validation.valid_keys > 0 {
                    real_count += 1;
                } else if validation.null_key_count > 0 {
                    // Null keys are treated as data (placeholders, not real keys)
                    data_count += 1;
                } else {
                    data_count += 1;
                }
            }
        }

        // Determine spendability based on key composition
        if real_count > 0 {
            // Has at least one valid EC point → Spendable
            SpendabilityResult::contains_real_pubkey(real_count, burn_count, data_count)
        } else if burn_count == pubkeys.len() as u8 {
            // All keys are burn patterns → Unspendable
            SpendabilityResult::all_burn_keys(burn_count)
        } else if burn_count > 0 && data_count > 0 {
            // Mix of burn and data keys → Unspendable
            SpendabilityResult::mixed_burn_and_data(burn_count, data_count)
        } else {
            // All keys are data → Unspendable
            SpendabilityResult::all_data_keys(data_count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::script_metadata::MultisigInfo;
    use crate::types::spendability::SpendabilityReason;
    use crate::types::stamps::StampsTransport;

    fn create_test_output(pubkeys: Vec<String>) -> TransactionOutput {
        let multisig_info = MultisigInfo {
            pubkeys: pubkeys.clone(),
            required_sigs: 1,
            total_pubkeys: pubkeys.len() as u32,
        };

        TransactionOutput {
            txid: "test_txid".to_string(),
            vout: 0,
            height: 100000,
            amount: 1000,
            script_hex: "test_script".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(multisig_info).unwrap(),
            address: None,
        }
    }

    #[test]
    fn test_stamps_always_unspendable() {
        let burn_key =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();
        let output = create_test_output(vec![burn_key.clone(), burn_key.clone(), burn_key]);

        let result = SpendabilityAnalyser::analyse_stamps_output(&output, StampsTransport::Pure);

        assert!(!result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::AllBurnKeys);
        assert_eq!(result.burn_key_count, 3);
        assert_eq!(result.real_pubkey_count, 0);
        assert_eq!(result.data_key_count, 0);
    }

    #[test]
    fn test_stamps_mixed_burn_and_data() {
        // Bitcoin Stamps with burn key + data keys
        let burn_key =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();
        let data_key = format!("03{}", "00".repeat(32)); // Invalid EC point = data key

        let output = create_test_output(vec![burn_key, data_key.clone(), data_key]);

        let result = SpendabilityAnalyser::analyse_stamps_output(&output, StampsTransport::Pure);

        assert!(!result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::MixedBurnAndData);
        assert_eq!(result.burn_key_count, 1);
        assert_eq!(result.data_key_count, 2);
        assert_eq!(result.real_pubkey_count, 0); // Stamps NEVER have real keys
    }

    #[test]
    fn test_stamps_all_data_keys() {
        // Bitcoin Stamps with only data keys (no burns) - shouldn't happen but handled
        let data_key = format!("03{}", "00".repeat(32)); // Invalid EC point = data key

        let output = create_test_output(vec![data_key.clone(), data_key.clone(), data_key]);

        let result = SpendabilityAnalyser::analyse_stamps_output(&output, StampsTransport::Pure);

        assert!(!result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::AllDataKeys);
        assert_eq!(result.burn_key_count, 0);
        assert_eq!(result.data_key_count, 3);
        assert_eq!(result.real_pubkey_count, 0); // Stamps NEVER have real keys
    }

    #[test]
    fn test_stamps_valid_ec_point_still_data() {
        // CRITICAL: Even if a non-burn key is a valid EC point, it's still a data key in Pure Stamps
        let burn_key =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();
        let valid_ec_key =
            "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc".to_string();

        let output = create_test_output(vec![burn_key, valid_ec_key.clone(), valid_ec_key]);

        let result = SpendabilityAnalyser::analyse_stamps_output(&output, StampsTransport::Pure);

        assert!(!result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::MixedBurnAndData);
        assert_eq!(result.burn_key_count, 1);
        assert_eq!(result.data_key_count, 2); // Valid EC points are STILL data keys in Pure Stamps
        assert_eq!(result.real_pubkey_count, 0); // Pure Stamps NEVER use real keys
    }

    // NEW TESTS: Counterparty-transported Bitcoin Stamps

    #[test]
    fn test_cp_transport_stamps_with_burn_keys_unspendable() {
        // CRITICAL: CP-transport Stamps with burn keys → UNSPENDABLE
        // (Even though real keys are also present)
        let burn_key =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();
        let real_key =
            "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc".to_string();

        let output = create_test_output(vec![real_key.clone(), real_key, burn_key]);

        let result =
            SpendabilityAnalyser::analyse_stamps_output(&output, StampsTransport::Counterparty);

        // CRITICAL ASSERTIONS: Burn key makes it unspendable
        assert!(
            !result.is_spendable,
            "CP-transport Stamps with burn key MUST be unspendable"
        );
        assert_eq!(result.burn_key_count, 1, "Should detect 1 burn key");
        assert_eq!(result.real_pubkey_count, 2, "Should detect 2 real keys");
        assert_eq!(result.data_key_count, 0, "No data keys");
        assert_eq!(
            result.reason,
            SpendabilityReason::MixedBurnAndData,
            "Burn + real = MixedBurnAndData"
        );
    }

    #[test]
    fn test_cp_transport_stamps_without_burn_keys_spendable() {
        // Theoretical: CP-transport Stamps with NO burn keys → SPENDABLE
        // This case doesn't exist in current production data but code must handle it
        let real_key =
            "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc".to_string();

        let output = create_test_output(vec![real_key.clone(), real_key.clone(), real_key]);

        let result =
            SpendabilityAnalyser::analyse_stamps_output(&output, StampsTransport::Counterparty);

        // WITHOUT burn keys → spendable
        assert!(
            result.is_spendable,
            "CP-transport Stamps WITHOUT burn keys should be spendable"
        );
        assert_eq!(result.burn_key_count, 0, "No burn keys");
        assert_eq!(result.real_pubkey_count, 3, "All 3 keys are real");
        assert_eq!(result.data_key_count, 0, "No data keys");
        assert_eq!(
            result.reason,
            SpendabilityReason::ContainsRealPubkey,
            "Real keys make it spendable"
        );
    }

    #[test]
    fn test_pure_stamps_always_unspendable_regardless() {
        // Pure Stamps: ALWAYS unspendable (always have burn keys)
        let burn_key =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();

        let output = create_test_output(vec![burn_key.clone(), burn_key.clone(), burn_key]);

        let result = SpendabilityAnalyser::analyse_stamps_output(&output, StampsTransport::Pure);

        assert!(!result.is_spendable);
        assert_eq!(result.burn_key_count, 3);
        assert_eq!(result.real_pubkey_count, 0); // Pure stamps NEVER have real keys
        assert_eq!(result.data_key_count, 0);
        assert_eq!(result.reason, SpendabilityReason::AllBurnKeys);
    }

    #[test]
    fn test_counterparty_always_spendable() {
        // Use a key that we KNOW is valid from pubkey_validator tests
        let real_key =
            "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc".to_string();
        // Use all zeros which we KNOW is invalid from test_generic_with_real_pubkey
        let data_key = format!("03{}", "00".repeat(32)); // Invalid EC point

        let output = create_test_output(vec![real_key, data_key.clone(), data_key]);

        let result = SpendabilityAnalyser::analyse_counterparty_output(&output);

        assert!(result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::ContainsRealPubkey);
        assert_eq!(result.real_pubkey_count, 1);
        assert_eq!(result.data_key_count, 2); // Now accurately counted
    }

    #[test]
    fn test_omni_always_spendable() {
        // Use a key that we KNOW is valid from pubkey_validator tests
        let sender_key =
            "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc".to_string();
        // Use all zeros which we KNOW is invalid from test_generic_with_real_pubkey
        let data_key = format!("03{}", "00".repeat(32));

        let output = create_test_output(vec![sender_key, data_key.clone(), data_key]);

        let result = SpendabilityAnalyser::analyse_omni_output(&output);

        assert!(result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::ContainsRealPubkey);
        assert_eq!(result.real_pubkey_count, 1);
        assert_eq!(result.data_key_count, 2); // Now accurately counted
    }

    #[test]
    fn test_legitimate_always_spendable() {
        // Use known-good keys from pubkey_validator tests
        let valid_key1 =
            "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc".to_string();
        let valid_key2 =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string();

        let output = create_test_output(vec![valid_key1, valid_key2]);

        let result = SpendabilityAnalyser::analyse_legitimate_output(&output);

        assert!(result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::AllValidECPoints);
        assert_eq!(result.real_pubkey_count, 2);
        assert_eq!(result.burn_key_count, 0);
        assert_eq!(result.data_key_count, 0);
    }

    #[test]
    fn test_generic_with_real_pubkey() {
        // Use a key that we KNOW is valid from pubkey_validator tests
        let real_key =
            "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc".to_string();
        // Create invalid EC point: all zeros except prefix
        let data_key = format!("03{}", "00".repeat(32));

        let output = create_test_output(vec![real_key, data_key]);

        let result = SpendabilityAnalyser::analyse_generic_output(&output);

        assert!(result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::ContainsRealPubkey);
        assert_eq!(result.real_pubkey_count, 1);
        assert_eq!(result.data_key_count, 1);
    }

    #[test]
    fn test_generic_all_burn_keys() {
        let burn_key =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();

        let output = create_test_output(vec![burn_key.clone(), burn_key.clone(), burn_key]);

        let result = SpendabilityAnalyser::analyse_generic_output(&output);

        assert!(!result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::AllBurnKeys);
        assert_eq!(result.burn_key_count, 3);
    }

    #[test]
    fn test_generic_mixed_burn_and_data() {
        let burn_key =
            "022222222222222222222222222222222222222222222222222222222222222222".to_string();
        // Create invalid EC point: all zeros except prefix
        let data_key = format!("03{}", "00".repeat(32));

        let output = create_test_output(vec![burn_key, data_key]);

        let result = SpendabilityAnalyser::analyse_generic_output(&output);

        assert!(!result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::MixedBurnAndData);
        assert_eq!(result.burn_key_count, 1);
        assert_eq!(result.data_key_count, 1);
    }

    #[test]
    fn test_generic_all_data_keys() {
        // Create invalid EC points: all zeros except prefix
        let data_key1 = format!("03{}", "00".repeat(32));
        let data_key2 = format!("02{}", "00".repeat(32));

        let output = create_test_output(vec![data_key1, data_key2]);

        let result = SpendabilityAnalyser::analyse_generic_output(&output);

        assert!(!result.is_spendable);
        assert_eq!(result.reason, SpendabilityReason::AllDataKeys);
        assert_eq!(result.data_key_count, 2);
    }
}
