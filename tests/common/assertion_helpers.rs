//! Common Assertion Helpers for Protocol Tests
//!
//! This module provides reusable assertion functions to reduce code duplication
//! across protocol tests and ensure consistent error messages.

use data_carry_research::types::burn_patterns::BurnPatternType;
use data_carry_research::types::TransactionOutput;
use std::path::Path;

/// Assert that a fixture file exists, providing a standardised skip message if not
///
/// # Arguments
/// * `fixture_path` - Path to the fixture file
/// * `protocol_name` - Name of the protocol (for error messages)
///
/// # Returns
/// `true` if file exists, `false` if missing (test should skip)
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_fixture_exists;
///
/// if !assert_fixture_exists("tests/test_data/stamps/src20.json", "Bitcoin Stamps") {
///     return Ok(());  // Skip test
/// }
/// ```
pub fn assert_fixture_exists(fixture_path: &str, protocol_name: &str) -> bool {
    if !Path::new(fixture_path).exists() {
        println!(
            "⏭️  Skipping {} test - missing fixture: {}",
            protocol_name, fixture_path
        );
        false
    } else {
        true
    }
}

/// Assert that P2MS outputs vector is not empty
///
/// # Arguments
/// * `p2ms_outputs` - P2MS outputs to check
/// * `fixture_path` - Fixture path (for error message)
///
/// # Panics
/// Panics if P2MS outputs vector is empty
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_p2ms_outputs_not_empty;
///
/// let p2ms_outputs = load_p2ms_outputs_from_json(fixture_path, txid)?;
/// assert_p2ms_outputs_not_empty(&p2ms_outputs, fixture_path);
/// ```
pub fn assert_p2ms_outputs_not_empty(p2ms_outputs: &[TransactionOutput], fixture_path: &str) {
    assert!(
        !p2ms_outputs.is_empty(),
        "Fixture {} must contain at least one P2MS output",
        fixture_path
    );
}

/// Assert that OP_RETURN outputs vector is not empty
///
/// # Arguments
/// * `op_return_outputs` - OP_RETURN outputs to check
/// * `fixture_path` - Fixture path (for error message)
///
/// # Panics
/// Panics if OP_RETURN outputs vector is empty
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_op_return_outputs_not_empty;
///
/// let op_return_outputs = extract_op_returns(&json_value, txid)?;
/// assert_op_return_outputs_not_empty(&op_return_outputs, fixture_path);
/// ```
pub fn assert_op_return_outputs_not_empty(
    op_return_outputs: &[TransactionOutput],
    fixture_path: &str,
) {
    assert!(
        !op_return_outputs.is_empty(),
        "Fixture {} must contain at least one OP_RETURN output",
        fixture_path
    );
}

/// Assert that specific burn pattern types exist in outputs
///
/// # Arguments
/// * `outputs` - P2MS outputs to check
/// * `expected_patterns` - Expected burn pattern types
///
/// # Returns
/// `true` if all expected patterns found, `false` otherwise
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_burn_patterns_exist;
/// use data_carry_research::types::burn_patterns::BurnPatternType;
///
/// let has_stamps = assert_burn_patterns_exist(
///     &p2ms_outputs,
///     &[BurnPatternType::Stamps22Pattern, BurnPatternType::Stamps33Pattern]
/// );
/// assert!(has_stamps, "Expected Stamps burn patterns");
/// ```
pub fn assert_burn_patterns_exist(
    outputs: &[TransactionOutput],
    expected_patterns: &[BurnPatternType],
) -> bool {
    for output in outputs {
        if let Some(metadata) = output.metadata.as_object() {
            if let Some(burn_patterns) = metadata.get("burn_patterns").and_then(|v| v.as_array()) {
                for pattern_value in burn_patterns {
                    if let Some(pattern_type_str) = pattern_value.get("pattern_type") {
                        let pattern_type_str = pattern_type_str.as_str().unwrap_or("");
                        for expected_pattern in expected_patterns {
                            let expected_str = format!("{:?}", expected_pattern);
                            if pattern_type_str == expected_str {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Assert that a multisig output has expected M-of-N pattern
///
/// # Arguments
/// * `output` - Transaction output to check
/// * `required_sigs` - Expected number of required signatures
/// * `total_pubkeys` - Expected total number of public keys
///
/// # Returns
/// `true` if pattern matches, `false` otherwise
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_multisig_pattern;
///
/// // Verify Counterparty 1-of-3 pattern
/// assert!(assert_multisig_pattern(&output, 1, 3), "Expected 1-of-3 multisig");
///
/// // Verify Omni Layer 1-of-2 pattern
/// assert!(assert_multisig_pattern(&output, 1, 2), "Expected 1-of-2 multisig");
/// ```
pub fn assert_multisig_pattern(
    output: &TransactionOutput,
    required_sigs: u32,
    total_pubkeys: u32,
) -> bool {
    if let Some(info) = output.multisig_info() {
        info.required_sigs == required_sigs && info.total_pubkeys == total_pubkeys
    } else {
        false
    }
}

/// Assert that output has valid EC point public keys (secp256k1 curve)
///
/// # Arguments
/// * `output` - Transaction output to check
///
/// # Returns
/// `true` if all public keys are valid EC points, `false` otherwise
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_valid_ec_points;
///
/// assert!(assert_valid_ec_points(&output), "Expected valid EC points");
/// ```
pub fn assert_valid_ec_points(output: &TransactionOutput) -> bool {
    use bitcoin::secp256k1::PublicKey;

    if let Some(info) = output.multisig_info() {
        info.pubkeys.iter().all(|pubkey| {
            if let Ok(bytes) = hex::decode(pubkey) {
                // Validate using secp256k1 library (same as pubkey_validator.rs)
                PublicKey::from_slice(&bytes).is_ok()
            } else {
                false
            }
        })
    } else {
        false
    }
}

/// Assert that outputs contain a specific script pattern (hex substring)
///
/// # Arguments
/// * `outputs` - Outputs to search
/// * `hex_pattern` - Hex pattern to find (case-insensitive)
///
/// # Returns
/// `true` if pattern found in any output, `false` otherwise
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_script_contains_hex;
///
/// // Check for CNTRPRTY signature
/// assert!(
///     assert_script_contains_hex(&p2ms_outputs, "434e545250525459"),
///     "Expected CNTRPRTY signature in script"
/// );
/// ```
pub fn assert_script_contains_hex(outputs: &[TransactionOutput], hex_pattern: &str) -> bool {
    let pattern_lower = hex_pattern.to_lowercase();
    outputs
        .iter()
        .any(|output| output.script_hex.to_lowercase().contains(&pattern_lower))
}

/// Assert that a minimum number of outputs exist
///
/// # Arguments
/// * `outputs` - Outputs to count
/// * `min_count` - Minimum expected count
/// * `output_type` - Type of outputs (for error message)
///
/// # Panics
/// Panics if output count is below minimum
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_min_output_count;
///
/// assert_min_output_count(&p2ms_outputs, 2, "P2MS");
/// ```
pub fn assert_min_output_count(outputs: &[TransactionOutput], min_count: usize, output_type: &str) {
    assert!(
        outputs.len() >= min_count,
        "Expected at least {} {} outputs, found {}",
        min_count,
        output_type,
        outputs.len()
    );
}

/// Assert that all outputs have the expected script type
///
/// # Arguments
/// * `outputs` - Outputs to check
/// * `expected_type` - Expected script type (e.g., "multisig", "op_return")
///
/// # Returns
/// `true` if all outputs match, `false` otherwise
///
/// # Example
/// ```rust,ignore
/// use crate::common::assertion_helpers::assert_all_script_type;
///
/// assert!(
///     assert_all_script_type(&p2ms_outputs, "multisig"),
///     "All outputs should be multisig"
/// );
/// ```
pub fn assert_all_script_type(outputs: &[TransactionOutput], expected_type: &str) -> bool {
    outputs
        .iter()
        .all(|output| output.script_type == expected_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_output(script_hex: &str, script_type: &str) -> TransactionOutput {
        TransactionOutput {
            txid: "test".to_string(),
            vout: 0,
            height: 0,
            amount: 546,
            script_hex: script_hex.to_string(),
            script_type: script_type.to_string(),
            is_coinbase: false,
            script_size: script_hex.len() / 2,
            metadata: serde_json::json!({
                "pubkeys": [
                    "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc",
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                ],
                "required_sigs": 1,
                "total_pubkeys": 2
            }),
            address: None,
        }
    }

    #[test]
    fn test_assert_fixture_exists_missing() {
        assert!(!assert_fixture_exists(
            "tests/test_data/nonexistent.json",
            "Test"
        ));
    }

    #[test]
    fn test_assert_fixture_exists_present() {
        // This test assumes Cargo.toml exists (safe assumption)
        assert!(assert_fixture_exists("Cargo.toml", "Test"));
    }

    #[test]
    #[should_panic(expected = "must contain at least one P2MS output")]
    fn test_assert_p2ms_outputs_not_empty_fails() {
        assert_p2ms_outputs_not_empty(&[], "test_fixture.json");
    }

    #[test]
    fn test_assert_p2ms_outputs_not_empty_succeeds() {
        let output = create_test_output("5221deadbeef21aebeef52ae", "multisig");
        assert_p2ms_outputs_not_empty(&[output], "test_fixture.json");
    }

    #[test]
    fn test_assert_multisig_pattern() {
        let output = create_test_output("5221deadbeef21aebeef52ae", "multisig");
        assert!(assert_multisig_pattern(&output, 1, 2));
        assert!(!assert_multisig_pattern(&output, 2, 3));
    }

    #[test]
    fn test_assert_script_contains_hex() {
        let output = create_test_output("5221434e545250525459deadbeef52ae", "multisig");
        assert!(assert_script_contains_hex(&[output], "434e545250525459"));
        assert!(!assert_script_contains_hex(&[], "434e545250525459"));
    }

    #[test]
    fn test_assert_all_script_type() {
        let output1 = create_test_output("5221deadbeef21aebeef52ae", "multisig");
        let output2 = create_test_output("5221cafebabe21aebeef52ae", "multisig");
        let output3 = create_test_output("6a04deadbeef", "op_return");

        assert!(assert_all_script_type(
            &[output1.clone(), output2],
            "multisig"
        ));
        assert!(!assert_all_script_type(&[output1, output3], "multisig"));
    }

    #[test]
    #[should_panic(expected = "Expected at least 2 P2MS outputs")]
    fn test_assert_min_output_count_fails() {
        let output = create_test_output("5221deadbeef21aebeef52ae", "multisig");
        assert_min_output_count(&[output], 2, "P2MS");
    }

    #[test]
    fn test_assert_min_output_count_succeeds() {
        let output1 = create_test_output("5221deadbeef21aebeef52ae", "multisig");
        let output2 = create_test_output("5221cafebabe21aebeef52ae", "multisig");
        assert_min_output_count(&[output1, output2], 2, "P2MS");
    }
}
