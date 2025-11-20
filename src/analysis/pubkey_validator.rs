//! Public key validation for P2MS outputs
//!
//! This module validates whether public keys in P2MS scripts are valid secp256k1 EC points.
//! Invalid points indicate data-carrying usage (not legitimate cryptographic keys).

use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Result of validating public keys in a P2MS output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubkeyValidationResult {
    /// True if all public keys are valid EC points on secp256k1 curve
    pub all_valid_ec_points: bool,

    /// True if the same public key appears multiple times (likely wallet error)
    pub has_duplicate_keys: bool,

    /// Number of duplicate keys found
    pub duplicate_count: usize,

    /// Indices of invalid public keys (0-based)
    pub invalid_key_indices: Vec<usize>,

    /// Human-readable validation errors
    pub validation_errors: Vec<String>,

    /// Total number of public keys validated
    pub total_keys: usize,

    /// Number of valid keys
    pub valid_keys: usize,

    /// Number of null keys (all bytes = 0x00)
    pub null_key_count: usize,

    /// Indices of null keys (0-based)
    pub null_key_indices: Vec<usize>,
}

impl PubkeyValidationResult {
    /// Create a new validation result
    pub fn new(total_keys: usize) -> Self {
        Self {
            all_valid_ec_points: true,
            has_duplicate_keys: false,
            duplicate_count: 0,
            invalid_key_indices: Vec::new(),
            validation_errors: Vec::new(),
            total_keys,
            valid_keys: 0,
            null_key_count: 0,
            null_key_indices: Vec::new(),
        }
    }

    /// Add an invalid key at the given index
    pub fn add_invalid_key(&mut self, index: usize, error: String) {
        self.all_valid_ec_points = false;
        self.invalid_key_indices.push(index);
        self.validation_errors
            .push(format!("Key {}: {}", index, error));
    }

    /// Mark that duplicates were found
    pub fn mark_duplicates(&mut self, count: usize) {
        self.has_duplicate_keys = true;
        self.duplicate_count = count;
    }

    /// Mark a null key at the given index
    pub fn add_null_key(&mut self, index: usize) {
        self.null_key_count += 1;
        self.null_key_indices.push(index);
    }

    /// Get a human-readable summary
    pub fn summary(&self) -> String {
        if self.all_valid_ec_points {
            if self.null_key_count > 0 {
                format!(
                    "{} real EC points + {} null keys (null-padded multisig)",
                    self.valid_keys, self.null_key_count
                )
            } else if self.has_duplicate_keys {
                format!(
                    "All {} keys valid EC points, {} duplicates found (likely wallet error)",
                    self.total_keys, self.duplicate_count
                )
            } else {
                format!(
                    "All {} keys valid EC points, standard multisig",
                    self.total_keys
                )
            }
        } else {
            format!(
                "{}/{} keys invalid EC points - definite data-carrying",
                self.invalid_key_indices.len(),
                self.total_keys
            )
        }
    }
}

/// Check if a pubkey is ALL-null (every byte = 0x00)
///
/// Null pubkeys appear in some 1-of-2 multisig outputs as placeholders.
/// They are not valid EC points but make the output spendable if M ≤ real_keys.
fn is_null_pubkey(pubkey_bytes: &[u8]) -> bool {
    if pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65 {
        return false; // Invalid length - not a proper pubkey
    }
    pubkey_bytes.iter().all(|&b| b == 0x00)
}

/// Validate a list of public key hex strings
///
/// Returns a validation result indicating whether all keys are valid EC points,
/// whether any duplicates were detected, and whether any null keys were found.
pub fn validate_pubkeys(pubkey_hexes: &[String]) -> PubkeyValidationResult {
    let mut result = PubkeyValidationResult::new(pubkey_hexes.len());
    let mut seen_keys = HashSet::new();
    let mut duplicate_count = 0;

    for (index, pubkey_hex) in pubkey_hexes.iter().enumerate() {
        // Check for duplicates
        if !seen_keys.insert(pubkey_hex.clone()) {
            duplicate_count += 1;
        }

        // Decode hex
        let pubkey_bytes = match hex::decode(pubkey_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                result.add_invalid_key(index, format!("Invalid hex: {}", e));
                continue;
            }
        };

        // Check if this is a null key BEFORE EC validation
        if is_null_pubkey(&pubkey_bytes) {
            result.add_null_key(index);
            // Null keys are NOT counted in valid_keys - they're tracked separately
            // This ensures spendability analysis correctly distinguishes real EC points from nulls
            continue;
        }

        // Validate EC point using secp256k1 library
        match PublicKey::from_slice(&pubkey_bytes) {
            Ok(_pubkey) => {
                // Valid EC point on secp256k1 curve
                result.valid_keys += 1;
            }
            Err(e) => {
                // Invalid EC point - definitely data-carrying
                result.add_invalid_key(
                    index,
                    format!(
                        "Not a valid EC point: {} (bytes: {})",
                        e,
                        pubkey_bytes.len()
                    ),
                );
            }
        }
    }

    // Mark duplicates if found
    if duplicate_count > 0 {
        result.mark_duplicates(duplicate_count);
    }

    result
}

/// Validate public keys from a P2MS metadata JSON object
///
/// Extracts the "pubkeys" array from metadata and validates each key.
pub fn validate_from_metadata(metadata: &serde_json::Value) -> Option<PubkeyValidationResult> {
    let pubkeys = metadata.get("pubkeys")?.as_array()?;

    let pubkey_hexes: Vec<String> = pubkeys
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    if pubkey_hexes.is_empty() {
        return None;
    }

    Some(validate_pubkeys(&pubkey_hexes))
}

/// Aggregate validation results across multiple P2MS outputs
///
/// This helper consolidates validation from multiple outputs into a single result,
/// useful for transaction-level classification decisions.
///
/// # Arguments
/// * `outputs` - Slice of TransactionOutput structures to validate
///
/// # Returns
/// Aggregated validation result, or None if no outputs have extractable pubkeys
///
/// # Example
/// ```no_run
/// use data_carry_research::analysis::aggregate_validation_for_outputs;
/// use data_carry_research::types::TransactionOutput;
///
/// let outputs: Vec<TransactionOutput> = vec![/* ... */];
/// if let Some(validation) = aggregate_validation_for_outputs(&outputs) {
///     if validation.all_valid_ec_points {
///         println!("All keys are valid EC points");
///     }
/// }
/// ```
pub fn aggregate_validation_for_outputs(
    outputs: &[crate::types::TransactionOutput],
) -> Option<PubkeyValidationResult> {
    let mut all_valid = true;
    let mut has_any_duplicates = false;
    let mut total_valid = 0;
    let mut total_invalid = 0;
    let mut total_duplicate_count = 0;
    let mut total_null_count = 0;
    let mut all_errors = Vec::new();
    let mut all_invalid_indices = Vec::new();
    let mut all_null_indices = Vec::new();

    for output in outputs {
        if let Some(validation) = validate_from_metadata(&output.metadata) {
            if !validation.all_valid_ec_points {
                all_valid = false;
                total_invalid += validation.invalid_key_indices.len();
                all_errors.extend(validation.validation_errors);
                all_invalid_indices.extend(validation.invalid_key_indices);
            } else {
                total_valid += validation.valid_keys;
            }

            if validation.has_duplicate_keys {
                has_any_duplicates = true;
                total_duplicate_count += validation.duplicate_count;
            }

            if validation.null_key_count > 0 {
                total_null_count += validation.null_key_count;
                all_null_indices.extend(validation.null_key_indices);
            }
        }
    }

    if total_valid > 0 || total_invalid > 0 {
        Some(PubkeyValidationResult {
            all_valid_ec_points: all_valid,
            has_duplicate_keys: has_any_duplicates,
            duplicate_count: total_duplicate_count,
            invalid_key_indices: all_invalid_indices,
            validation_errors: all_errors,
            total_keys: total_valid + total_invalid,
            valid_keys: total_valid,
            null_key_count: total_null_count,
            null_key_indices: all_null_indices,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_uncompressed_pubkey() {
        // Valid uncompressed public key (65 bytes, 0x04 prefix)
        let pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5".to_string();

        let result = validate_pubkeys(&[pubkey]);

        assert!(result.all_valid_ec_points);
        assert_eq!(result.valid_keys, 1);
        assert!(!result.has_duplicate_keys);
        assert!(result.invalid_key_indices.is_empty());
    }

    #[test]
    fn test_valid_compressed_pubkey() {
        // Valid compressed public key (33 bytes, 0x02 prefix)
        let pubkey =
            "02a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbc".to_string();

        let result = validate_pubkeys(&[pubkey]);

        assert!(result.all_valid_ec_points);
        assert_eq!(result.valid_keys, 1);
        assert!(!result.has_duplicate_keys);
    }

    #[test]
    fn test_duplicate_keys() {
        let pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5".to_string();

        // Same key twice
        let result = validate_pubkeys(&[pubkey.clone(), pubkey]);

        assert!(result.all_valid_ec_points); // Both are valid
        assert!(result.has_duplicate_keys); // But they're duplicates
        assert_eq!(result.duplicate_count, 1);
        assert_eq!(result.valid_keys, 2);
    }

    #[test]
    fn test_invalid_hex() {
        let invalid_hex = "not_hex_at_all".to_string();

        let result = validate_pubkeys(&[invalid_hex]);

        assert!(!result.all_valid_ec_points);
        assert_eq!(result.valid_keys, 0);
        assert_eq!(result.invalid_key_indices, vec![0]);
        assert!(!result.validation_errors.is_empty());
    }

    #[test]
    fn test_invalid_ec_point() {
        // 33 bytes but not a valid EC point
        let invalid_point = format!("03{}", "00".repeat(32));

        let result = validate_pubkeys(&[invalid_point]);

        assert!(!result.all_valid_ec_points);
        assert_eq!(result.valid_keys, 0);
        assert_eq!(result.invalid_key_indices, vec![0]);
    }

    #[test]
    fn test_mixed_valid_invalid() {
        let valid = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5".to_string();
        let invalid = "03".to_string() + &"00".repeat(32);

        let result = validate_pubkeys(&[valid, invalid]);

        assert!(!result.all_valid_ec_points);
        assert_eq!(result.valid_keys, 1);
        assert_eq!(result.invalid_key_indices, vec![1]);
    }

    #[test]
    fn test_summary_all_valid() {
        let pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5".to_string();
        let result = validate_pubkeys(&[pubkey.clone(), pubkey.clone() + "00"]);

        let summary = result.summary();
        assert!(summary.contains("valid EC points"));
    }

    #[test]
    fn test_summary_with_duplicates() {
        let pubkey = "04a39b9e4fbd213ef24bb9be69de4a118dd0644082e47c01fd9159d38637b83fbcdc115a5d6e970586a012d1cfe3e3a8b1a3d04e763bdc5a071c0e827c0bd834a5".to_string();
        let result = validate_pubkeys(&[pubkey.clone(), pubkey]);

        let summary = result.summary();
        assert!(summary.contains("duplicates"));
        assert!(summary.contains("wallet error"));
    }
}
