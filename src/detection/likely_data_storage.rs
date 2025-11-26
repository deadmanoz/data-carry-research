//! Shared LikelyDataStorage detection logic
//!
//! This module provides unified protocol detection for LikelyDataStorage patterns that
//! can be used by both Stage 3 (classification) and Stage 4 (decoding).
//!
//! The detection logic is database-agnostic and operates purely on TransactionOutput data,
//! using full secp256k1 EC point validation to distinguish data storage from legitimate multisig.

use crate::types::TransactionOutput;
use tracing::warn;

/// Variant detected by LikelyDataStorage classification
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LikelyDataStorageVariant {
    /// ≥1 pubkey fails secp256k1 validation (highest confidence)
    InvalidECPoint,
    /// ≥5 P2MS outputs with ALL valid EC points
    HighOutputCount,
    /// ALL outputs ≤1000 sats with ALL valid EC points
    DustAmount,
}

/// Detection result with variant and human-readable details
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub variant: LikelyDataStorageVariant,
    pub details: String, // Format: matches Stage 3 exactly for consistency
}

/// Single, unified entry point for LikelyDataStorage detection
///
/// **Inputs**: Pre-filtered P2MS outputs only (script_type == "multisig").
/// Empty slice check is defensive (callers should filter first).
///
/// **Detection order** (strictly enforced, mutually exclusive):
/// 1. InvalidECPoint (highest confidence - cryptographic proof)
/// 2. HighOutputCount (requires ALL valid EC points)
/// 3. DustAmount (requires ALL valid EC points)
///
/// **Returns**: `Some(DetectionResult)` if a pattern is detected, `None` otherwise.
pub fn detect(outputs: &[TransactionOutput]) -> Option<DetectionResult> {
    // Defensive: outputs slice is already P2MS-filtered; empty check prevents panics
    if outputs.is_empty() {
        return None;
    }

    // Guard: verify all inputs are multisig to prevent silent misclassification
    let all_multisig = outputs.iter().all(|o| o.script_type == "multisig");
    if !all_multisig {
        warn!("LikelyDataStorage detect() called with non-multisig outputs - returning None");
        return None;
    }

    // Check 1: Invalid EC Points (PRIMARY - highest confidence)
    // Even a SINGLE invalid EC point strongly suggests data storage, as legitimate
    // multisig wallets would never generate keys that aren't on the secp256k1 curve.
    if let Some(details) = check_invalid_ec_points(outputs) {
        return Some(DetectionResult {
            variant: LikelyDataStorageVariant::InvalidECPoint,
            details,
        });
    }

    // Check 2: High Output Count (≥5 outputs with ALL valid EC points)
    // Legitimate multisig typically uses 1-2 outputs; 5+ suggests batch data embedding
    if outputs.len() >= 5 && check_all_valid_ec_points(outputs) {
        let details = format!("{} P2MS outputs with valid EC points", outputs.len());
        return Some(DetectionResult {
            variant: LikelyDataStorageVariant::HighOutputCount,
            details,
        });
    }

    // Check 3: Dust Amounts (ALL outputs ≤1000 sats with ALL valid EC points)
    // Data-carrying protocols use minimal amounts to reduce costs while still being
    // accepted by the network (e.g., October 2024+ mystery protocol at 800 sats)
    if let Some(details) = check_dust_amounts(outputs) {
        return Some(DetectionResult {
            variant: LikelyDataStorageVariant::DustAmount,
            details,
        });
    }

    None
}

// ============================================================================
// Helper Functions (Private - NOT pub)
// ============================================================================

/// Check if any pubkeys are invalid EC points (data embedding indicator)
///
/// Returns `Some(details)` if ≥1 invalid EC point found.
/// Uses full secp256k1 curve validation via shared aggregation helper.
///
/// **Catches**:
/// - Invalid prefixes (0xb6, 0x01, 0xe1 instead of 0x02/0x03/0x04)
/// - Valid prefixes but coordinates not on secp256k1 curve
/// - Malformed keys of wrong length
///
/// **Format**: `"<total_invalid>/<total_keys> pubkeys are invalid EC points<optional_examples>"`
fn check_invalid_ec_points(outputs: &[TransactionOutput]) -> Option<String> {
    use crate::analysis::aggregate_validation_for_outputs;

    let validation = aggregate_validation_for_outputs(outputs)?;

    // Trigger if ANY key is invalid (≥1 invalid EC point)
    if !validation.all_valid_ec_points {
        let total_invalid = validation.invalid_key_indices.len();
        let total_keys = validation.total_keys;

        // Collect error examples (first 3 for diagnostics)
        let error_examples: Vec<String> = validation
            .validation_errors
            .iter()
            .take(3)
            .cloned()
            .collect();

        let examples = if !error_examples.is_empty() {
            format!(": {}", error_examples.join("; "))
        } else {
            String::new()
        };

        Some(format!(
            "{}/{} pubkeys are invalid EC points{}",
            total_invalid, total_keys, examples
        ))
    } else {
        None
    }
}

/// Check if all pubkeys are valid EC points
///
/// Uses full secp256k1 curve validation via shared aggregation helper.
/// Returns `true` only if every single pubkey passes EC point validation.
fn check_all_valid_ec_points(outputs: &[TransactionOutput]) -> bool {
    use crate::analysis::aggregate_validation_for_outputs;

    if let Some(validation) = aggregate_validation_for_outputs(outputs) {
        // Return true only if ALL pubkeys are valid EC points
        validation.all_valid_ec_points
    } else {
        // If we can't validate (no extractable pubkeys), assume invalid
        false
    }
}

/// Check for dust-level amounts in P2MS outputs
///
/// Data-carrying protocols typically use minimal amounts (dust) to reduce costs
/// while still being accepted by the network. Legitimate multisig transactions
/// typically have meaningful amounts of BTC.
///
/// **Threshold**: `<= 1000` satoshis per P2MS output
///
/// Returns `Some(details)` if ALL outputs ≤1000 sats with ALL valid EC points.
///
/// **Format**: `"All <count> P2MS outputs have dust-level amounts (min: <min>, max: <max>, avg: <avg> sats)"`
fn check_dust_amounts(outputs: &[TransactionOutput]) -> Option<String> {
    const DUST_THRESHOLD: u64 = 1000; // satoshis

    // Check if ALL multisig outputs have dust-level amounts
    let all_dust = outputs.iter().all(|output| output.amount <= DUST_THRESHOLD);

    if !all_dust {
        return None; // Some multisig outputs have significant amounts, likely legitimate
    }

    // Also verify that pubkeys are valid EC points (not obvious data)
    // This prevents double-classification with InvalidECPoint variant
    if !check_all_valid_ec_points(outputs) {
        return None;
    }

    // Calculate statistics for the classification method
    let amounts: Vec<u64> = outputs.iter().map(|o| o.amount).collect();
    let min_amount = amounts.iter().min().unwrap_or(&0);
    let max_amount = amounts.iter().max().unwrap_or(&0);
    let avg_amount = if !amounts.is_empty() {
        amounts.iter().sum::<u64>() / amounts.len() as u64
    } else {
        0
    };

    Some(format!(
        "All {} P2MS outputs have dust-level amounts (min: {}, max: {}, avg: {} sats)",
        outputs.len(),
        min_amount,
        max_amount,
        avg_amount
    ))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: Create test output with specific pubkey and amount
    fn create_test_output(pubkey: &str, vout: u32, amount: u64) -> TransactionOutput {
        let script_hex = format!("5121{}51ae", pubkey);

        TransactionOutput {
            txid: "test_txid".to_string(),
            vout,
            height: 800000,
            amount,
            script_hex,
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: serde_json::json!({
                "required_sigs": 1,
                "total_pubkeys": 1,
                "pubkeys": [pubkey]
            }),
            address: None,
        }
    }

    #[test]
    fn test_invalid_ec_point_detection() {
        // Invalid EC point: 0xb6 prefix (not 0x02/0x03/0x04) + 32 bytes = 66 hex chars
        let invalid_pubkey = "b6".to_string() + &"00".repeat(32); // 66 chars total
        let outputs = vec![create_test_output(&invalid_pubkey, 0, 10000)];

        let result = detect(&outputs);
        assert!(result.is_some(), "Should detect InvalidECPoint");
        let result = result.unwrap();
        assert_eq!(result.variant, LikelyDataStorageVariant::InvalidECPoint);
        assert!(
            result.details.contains("invalid EC point"),
            "Details should mention invalid EC point"
        );
    }

    #[test]
    fn test_high_output_count_detection() {
        // 6 outputs with different VALID pubkeys (all valid EC points)
        let valid_pubkeys = [
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
        ];
        let outputs: Vec<_> = valid_pubkeys
            .iter()
            .enumerate()
            .map(|(i, pk)| create_test_output(pk, i as u32, 10000))
            .collect();

        let result = detect(&outputs);
        assert!(result.is_some(), "Should detect HighOutputCount");
        let result = result.unwrap();
        assert_eq!(result.variant, LikelyDataStorageVariant::HighOutputCount);
        assert!(
            result.details.contains("6 P2MS outputs"),
            "Details should mention 6 outputs"
        );
    }

    #[test]
    fn test_dust_amount_detection() {
        // 2 outputs with dust amounts (800 sats), valid EC points
        let valid_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let outputs = vec![
            create_test_output(valid_pubkey, 0, 800),
            create_test_output(valid_pubkey, 1, 800),
        ];

        let result = detect(&outputs);
        assert!(result.is_some(), "Should detect DustAmount");
        let result = result.unwrap();
        assert_eq!(result.variant, LikelyDataStorageVariant::DustAmount);
        assert!(
            result.details.contains("dust-level amounts"),
            "Details should mention dust-level amounts"
        );
        assert!(
            result.details.contains("avg: 800 sats"),
            "Details should show correct average"
        );
    }

    #[test]
    fn test_priority_ordering_invalid_wins() {
        // Create 6 outputs (triggers HighOutputCount threshold)
        // But ONE has invalid EC point (should trigger InvalidECPoint first)
        let invalid_pubkey = "b6".to_string() + &"00".repeat(32);
        let valid_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        let mut outputs = vec![create_test_output(&invalid_pubkey, 0, 10000)];
        for i in 1..6 {
            outputs.push(create_test_output(valid_pubkey, i, 10000));
        }

        let result = detect(&outputs);
        assert!(result.is_some());
        let result = result.unwrap();
        // InvalidECPoint should win (checked first, highest priority)
        assert_eq!(
            result.variant,
            LikelyDataStorageVariant::InvalidECPoint,
            "InvalidECPoint should have highest priority"
        );
    }

    #[test]
    fn test_no_detection_normal_transaction() {
        // 2 outputs, significant amounts (100,000 sats), valid EC points
        let valid_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let outputs = vec![
            create_test_output(valid_pubkey, 0, 100000),
            create_test_output(valid_pubkey, 1, 100000),
        ];

        let result = detect(&outputs);
        assert!(result.is_none(), "Should NOT detect any pattern");
    }

    #[test]
    fn test_repeated_pubkey_not_detected() {
        // REGRESSION TEST: Ensure RepeatedPubkey is NOT detected
        // 3 outputs using the SAME pubkey (old RepeatedPubkey logic would trigger)
        let valid_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let outputs = vec![
            create_test_output(valid_pubkey, 0, 10000),
            create_test_output(valid_pubkey, 1, 10000),
            create_test_output(valid_pubkey, 2, 10000),
        ];

        let result = detect(&outputs);
        // Should return None (not enough outputs for HighOutputCount, amounts not dust)
        // But should NEVER return RepeatedPubkey (that logic is removed)
        assert!(
            result.is_none(),
            "Should NOT detect RepeatedPubkey - logic removed"
        );
    }

    #[test]
    fn test_guard_non_multisig_inputs() {
        // Verify guard against non-multisig outputs
        let mut output = create_test_output(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            0,
            10000,
        );
        output.script_type = "p2pkh".to_string(); // NOT multisig

        let result = detect(&[output]);
        assert!(
            result.is_none(),
            "Guard should prevent classification of non-multisig"
        );
    }

    #[test]
    fn test_empty_slice_returns_none() {
        let result = detect(&[]);
        assert!(result.is_none(), "Empty slice should return None");
    }
}
