//! Shared multisig pattern matching utilities for protocol identification
//!
//! This module consolidates common patterns for matching M-of-N multisig configurations
//! across multiple protocols (Counterparty, OP_RETURN signalled, ASCII identifier protocols).
//!
//! ## Common Matching Patterns
//!
//! - **Exact match**: Check if output matches M-of-N (e.g., 1-of-2, 2-of-3)
//! - **Pattern search**: Find all outputs matching a specific M-of-N pattern
//! - **Pattern exists**: Check if any output has a specific M-of-N pattern

use crate::types::TransactionOutput;

/// Utility for matching multisig patterns in transaction outputs
pub struct MultisigPatternMatcher;

impl MultisigPatternMatcher {
    /// Check if a single output matches an M-of-N multisig pattern
    ///
    /// Validates that:
    /// - Output has multisig metadata
    /// - Required signatures matches `m`
    /// - Total pubkeys matches `n`
    /// - Pubkey count matches `n` (ensures all pubkeys are present)
    ///
    /// # Arguments
    /// * `output` - Transaction output to check
    /// * `m` - Required signatures (M in M-of-N)
    /// * `n` - Total pubkeys (N in M-of-N)
    ///
    /// # Returns
    /// * `true` if output matches M-of-N pattern, `false` otherwise
    ///
    /// # Examples
    /// ```ignore
    /// // Check for 1-of-2 multisig pattern
    /// if MultisigPatternMatcher::matches(&output, 1, 2) {
    ///     // Process 1-of-2 multisig
    /// }
    ///
    /// // Check for 2-of-3 multisig pattern
    /// if MultisigPatternMatcher::matches(&output, 2, 3) {
    ///     // Process 2-of-3 multisig
    /// }
    /// ```
    pub fn matches(output: &TransactionOutput, m: u32, n: u32) -> bool {
        if let Some(info) = output.multisig_info() {
            info.required_sigs == m && info.total_pubkeys == n && info.pubkeys.len() == n as usize
        } else {
            false
        }
    }

    /// Find all outputs matching an M-of-N multisig pattern
    ///
    /// Returns a vector of references to outputs that match the specified M-of-N pattern.
    /// Useful when you need to collect and process all matching outputs.
    ///
    /// # Arguments
    /// * `outputs` - Slice of transaction outputs to search
    /// * `m` - Required signatures (M in M-of-N)
    /// * `n` - Total pubkeys (N in M-of-N)
    ///
    /// # Returns
    /// * Vector of references to outputs matching the M-of-N pattern
    ///
    /// # Examples
    /// ```ignore
    /// // Find all 1-of-3 multisig outputs
    /// let one_of_three = MultisigPatternMatcher::find_matching(&outputs, 1, 3);
    /// for output in one_of_three {
    ///     // Process each 1-of-3 output
    /// }
    /// ```
    pub fn find_matching(outputs: &[TransactionOutput], m: u32, n: u32) -> Vec<&TransactionOutput> {
        outputs
            .iter()
            .filter(|output| Self::matches(output, m, n))
            .collect()
    }

    /// Check if any output has an M-of-N multisig pattern
    ///
    /// Efficient check without collecting results. Returns `true` as soon as
    /// a matching output is found.
    ///
    /// # Arguments
    /// * `outputs` - Slice of transaction outputs to search
    /// * `m` - Required signatures (M in M-of-N)
    /// * `n` - Total pubkeys (N in M-of-N)
    ///
    /// # Returns
    /// * `true` if at least one output matches M-of-N pattern, `false` otherwise
    ///
    /// # Examples
    /// ```ignore
    /// // Check if transaction has any 2-of-2 multisig outputs
    /// if MultisigPatternMatcher::has_pattern(&outputs, 2, 2) {
    ///     // Transaction contains at least one 2-of-2 multisig
    /// }
    /// ```
    pub fn has_pattern(outputs: &[TransactionOutput], m: u32, n: u32) -> bool {
        outputs.iter().any(|output| Self::matches(output, m, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::script_metadata::MultisigInfo;
    use crate::types::TransactionOutput;

    fn create_test_output(m: u32, n: u32, pubkeys: Vec<String>) -> TransactionOutput {
        let metadata_value = serde_json::to_value(MultisigInfo {
            required_sigs: m,
            total_pubkeys: n,
            pubkeys,
        })
        .unwrap();

        TransactionOutput {
            txid: "test_txid".to_string(),
            vout: 0,
            height: 100000,
            amount: 546,
            script_hex: "test_script".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 10,
            metadata: metadata_value,
            address: None,
        }
    }

    #[test]
    fn test_matches_1of2() {
        let output = create_test_output(1, 2, vec!["pubkey1".to_string(), "pubkey2".to_string()]);
        assert!(MultisigPatternMatcher::matches(&output, 1, 2));
        assert!(!MultisigPatternMatcher::matches(&output, 2, 2));
        assert!(!MultisigPatternMatcher::matches(&output, 1, 3));
    }

    #[test]
    fn test_matches_2of3() {
        let output = create_test_output(
            2,
            3,
            vec![
                "pubkey1".to_string(),
                "pubkey2".to_string(),
                "pubkey3".to_string(),
            ],
        );
        assert!(MultisigPatternMatcher::matches(&output, 2, 3));
        assert!(!MultisigPatternMatcher::matches(&output, 1, 3));
        assert!(!MultisigPatternMatcher::matches(&output, 2, 2));
    }

    #[test]
    fn test_matches_fails_when_pubkey_count_mismatch() {
        // Create 1-of-2 but only provide 1 pubkey (invalid)
        let output = create_test_output(1, 2, vec!["pubkey1".to_string()]);
        assert!(!MultisigPatternMatcher::matches(&output, 1, 2));
    }

    #[test]
    fn test_find_matching() {
        let outputs = vec![
            create_test_output(1, 2, vec!["pk1".to_string(), "pk2".to_string()]),
            create_test_output(2, 2, vec!["pk1".to_string(), "pk2".to_string()]),
            create_test_output(1, 2, vec!["pk3".to_string(), "pk4".to_string()]),
            create_test_output(
                1,
                3,
                vec!["pk1".to_string(), "pk2".to_string(), "pk3".to_string()],
            ),
        ];

        let one_of_two = MultisigPatternMatcher::find_matching(&outputs, 1, 2);
        assert_eq!(one_of_two.len(), 2);

        let two_of_two = MultisigPatternMatcher::find_matching(&outputs, 2, 2);
        assert_eq!(two_of_two.len(), 1);

        let one_of_three = MultisigPatternMatcher::find_matching(&outputs, 1, 3);
        assert_eq!(one_of_three.len(), 1);

        let three_of_three = MultisigPatternMatcher::find_matching(&outputs, 3, 3);
        assert_eq!(three_of_three.len(), 0);
    }

    #[test]
    fn test_has_pattern() {
        let outputs = vec![
            create_test_output(1, 2, vec!["pk1".to_string(), "pk2".to_string()]),
            create_test_output(2, 2, vec!["pk1".to_string(), "pk2".to_string()]),
        ];

        assert!(MultisigPatternMatcher::has_pattern(&outputs, 1, 2));
        assert!(MultisigPatternMatcher::has_pattern(&outputs, 2, 2));
        assert!(!MultisigPatternMatcher::has_pattern(&outputs, 1, 3));
        assert!(!MultisigPatternMatcher::has_pattern(&outputs, 3, 3));
    }

    #[test]
    fn test_has_pattern_empty_outputs() {
        let outputs: Vec<TransactionOutput> = vec![];
        assert!(!MultisigPatternMatcher::has_pattern(&outputs, 1, 2));
    }

    #[test]
    fn test_find_matching_empty_outputs() {
        let outputs: Vec<TransactionOutput> = vec![];
        let result = MultisigPatternMatcher::find_matching(&outputs, 1, 2);
        assert_eq!(result.len(), 0);
    }
}
