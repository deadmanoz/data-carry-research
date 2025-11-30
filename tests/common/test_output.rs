//! Test Output Formatting Utilities
//!
//! Consolidated formatting utilities for protocol classification tests.
//! Provides standardised header, footer, and output formatting across all protocol tests.

use data_carry_research::types::TransactionOutput;

/// Test output formatter with standardised box drawing and formatting
pub struct TestOutputFormatter;

impl TestOutputFormatter {
    /// Create standardised test header with box drawing
    ///
    /// # Arguments
    /// * `protocol_name` - Protocol name (e.g., "Bitcoin Stamps", "Counterparty", "Omni Layer")
    /// * `test_name` - Specific test name (e.g., "stamps_src20_deploy")
    /// * `txid` - Transaction ID (will be truncated to first 12 chars for display)
    ///
    /// # Example
    /// ```
    /// let header = TestOutputFormatter::format_test_header(
    ///     "Bitcoin Stamps",
    ///     "stamps_src20_deploy",
    ///     "0d5a0c9f4e29646d2dbafab12aaad8465f9e2dc637697ef83899f9d7086cc56b"
    /// );
    /// ```
    pub fn format_test_header(protocol_name: &str, test_name: &str, txid: &str) -> String {
        let txid_display = if txid.len() >= 12 { &txid[..12] } else { txid };

        format!(
            "\n╔══════════════════════════════════════════════════════════════\n\
             ║ {} Test: {}\n\
             ╠══════════════════════════════════════════════════════════════\n\
             ║ Transaction: {}...\n\
             ╟──────────────────────────────────────────────────────────────\n",
            protocol_name, test_name, txid_display
        )
    }

    /// Create standardised test header with additional context line
    ///
    /// # Arguments
    /// * `protocol_name` - Protocol name
    /// * `test_name` - Specific test name
    /// * `txid` - Transaction ID
    /// * `context` - Additional context (e.g., "First Input TXID: abcd...")
    pub fn format_test_header_with_context(
        protocol_name: &str,
        test_name: &str,
        txid: &str,
        context: &str,
    ) -> String {
        let txid_display = if txid.len() >= 12 { &txid[..12] } else { txid };

        format!(
            "\n╔══════════════════════════════════════════════════════════════\n\
             ║ {} Test: {}\n\
             ╠══════════════════════════════════════════════════════════════\n\
             ║ Transaction: {}...\n\
             ║ {}\n\
             ╟──────────────────────────────────────────────────────────────\n",
            protocol_name, test_name, txid_display, context
        )
    }

    /// Create test header without transaction ID (for synthetic tests)
    ///
    /// Use this for tests that don't have a real transaction ID, such as
    /// synthetic pattern tests that verify classification logic directly.
    ///
    /// # Arguments
    /// * `protocol_name` - Protocol name (e.g., "DataStorage")
    /// * `test_name` - Specific test name (e.g., "datastorage_compressed")
    pub fn format_test_header_simple(protocol_name: &str, test_name: &str) -> String {
        format!(
            "\n╔══════════════════════════════════════════════════════════════\n\
             ║ {} Test: {}\n\
             ╟──────────────────────────────────────────────────────────────\n",
            protocol_name, test_name
        )
    }

    /// Create standardised test footer with classification results
    ///
    /// # Arguments
    /// * `classification` - Classification result (e.g., "BitcoinStamps", "Counterparty")
    /// * `method` - Classification method (e.g., "P2MS + ARC4 decryption")
    ///
    /// # Example
    /// ```
    /// let footer = TestOutputFormatter::format_test_footer(
    ///     "BitcoinStamps",
    ///     "P2MS + ARC4 decryption + stamp: signature"
    /// );
    /// ```
    pub fn format_test_footer(classification: &str, method: &str) -> String {
        format!(
            "║\n\
             ║ Classification: ✅ {}\n\
             ║   Method: {}\n\
             ╚══════════════════════════════════════════════════════════════\n",
            classification, method
        )
    }

    /// Create test footer with additional message type information
    ///
    /// # Arguments
    /// * `classification` - Classification result
    /// * `method` - Classification method
    /// * `message_type` - Protocol-specific message type (e.g., "Type 0 (Send)")
    pub fn format_test_footer_with_type(
        classification: &str,
        method: &str,
        message_type: &str,
    ) -> String {
        format!(
            "║\n\
             ║ Classification: ✅ {}\n\
             ║   Method: {}\n\
             ║   Message Type: {}\n\
             ╚══════════════════════════════════════════════════════════════\n",
            classification, method, message_type
        )
    }

    /// Format P2MS output details for display
    ///
    /// # Arguments
    /// * `output` - Transaction output to format
    /// * `index` - Output index (0-based)
    ///
    /// # Returns
    /// Formatted string with output details including vout, multisig pattern, and amount
    pub fn format_p2ms_output(output: &TransactionOutput, index: usize) -> String {
        let mut result = format!("║ Output #{} (vout: {}):\n", index, output.vout);

        // Extract multisig info
        if let Some(info) = output.multisig_info() {
            result.push_str(&format!(
                "║   Pattern: {}-of-{} multisig\n",
                info.required_sigs, info.total_pubkeys
            ));
        } else {
            result.push_str("║   Pattern: P2MS multisig\n");
        }

        result.push_str(&format!("║   Amount: {} satoshis\n", output.amount));

        // Show pubkey count
        if let Some(info) = output.multisig_info() {
            result.push_str(&format!("║   Contains {} pubkeys\n", info.pubkeys.len()));
        }

        result.push_str("║\n");
        result
    }

    /// Format detailed P2MS output analysis with pubkey details
    ///
    /// # Arguments
    /// * `output` - Transaction output to analyse
    /// * `index` - Output index (0-based)
    /// * `pubkey_annotations` - Optional annotations for each pubkey (e.g., "(data)", "(source)")
    pub fn format_p2ms_output_detailed(
        output: &TransactionOutput,
        index: usize,
        pubkey_annotations: Option<Vec<String>>,
    ) -> String {
        let mut result = format!("║ Output #{} (vout: {}):\n", index, output.vout);

        // Extract multisig info
        if let Some(info) = output.multisig_info() {
            result.push_str(&format!(
                "║   Pattern: {}-of-{} multisig\n",
                info.required_sigs, info.total_pubkeys
            ));

            result.push_str(&format!("║   Amount: {} satoshis\n", output.amount));

            // Show each pubkey with annotation
            for (i, pubkey) in info.pubkeys.iter().enumerate() {
                let pubkey_display = if pubkey.len() > 16 {
                    format!("{}...", &pubkey[..16])
                } else {
                    pubkey.clone()
                };

                let annotation = if let Some(ref annotations) = pubkey_annotations {
                    annotations.get(i).map(|s| s.as_str()).unwrap_or("")
                } else {
                    ""
                };

                result.push_str(&format!(
                    "║   Pubkey {}: {} {}\n",
                    i + 1,
                    pubkey_display,
                    annotation
                ));
            }
        } else {
            result.push_str("║   Pattern: P2MS multisig (no metadata)\n");
            result.push_str(&format!("║   Amount: {} satoshis\n", output.amount));
        }

        result.push_str("║\n");
        result
    }

    /// Format pubkey analysis section
    ///
    /// # Arguments
    /// * `pubkeys` - List of pubkey hex strings
    /// * `title` - Section title (default: "Pubkey Analysis")
    pub fn format_pubkey_analysis(pubkeys: &[String], title: Option<&str>) -> String {
        let mut output = String::new();
        output.push_str(&format!("║ {}:\n", title.unwrap_or("Pubkey Analysis")));

        for (i, pubkey) in pubkeys.iter().enumerate() {
            let preview = if pubkey.len() > 16 {
                format!("{}...", &pubkey[..16])
            } else {
                pubkey.clone()
            };
            output.push_str(&format!("║   Pubkey {}: {}\n", i + 1, preview));
        }

        output.push_str("║\n");
        output
    }

    /// Format a data section with title and key-value pairs
    ///
    /// # Arguments
    /// * `title` - Section title
    /// * `data` - Key-value pairs to display
    ///
    /// # Example
    /// ```
    /// let data = vec![
    ///     ("Sender", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    ///     ("Sequence", "1"),
    ///     ("Data Length", "31 bytes"),
    /// ];
    /// let output = TestOutputFormatter::format_data_section("Deobfuscation", &data);
    /// ```
    pub fn format_data_section(title: &str, data: &[(&str, &str)]) -> String {
        let mut output = format!("║ {}:\n", title);

        for (key, value) in data {
            output.push_str(&format!("║   {}: {}\n", key, value));
        }

        output.push_str("║\n");
        output
    }

    /// Format a simple divider line
    pub fn format_divider() -> String {
        "║\n".to_string()
    }

    /// Format a section separator
    pub fn format_section_separator() -> String {
        "╟──────────────────────────────────────────────────────────────\n".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_test_header() {
        let header = TestOutputFormatter::format_test_header(
            "Bitcoin Stamps",
            "stamps_src20_deploy",
            "0d5a0c9f4e29646d2dbafab12aaad8465f9e2dc637697ef83899f9d7086cc56b",
        );

        assert!(header.contains("Bitcoin Stamps Test"));
        assert!(header.contains("stamps_src20_deploy"));
        assert!(header.contains("0d5a0c9f4e29"));
    }

    #[test]
    fn test_format_test_footer() {
        let footer =
            TestOutputFormatter::format_test_footer("BitcoinStamps", "P2MS + ARC4 decryption");

        assert!(footer.contains("✅ BitcoinStamps"));
        assert!(footer.contains("P2MS + ARC4 decryption"));
    }

    #[test]
    fn test_format_data_section() {
        let data = vec![("Key1", "Value1"), ("Key2", "Value2")];
        let output = TestOutputFormatter::format_data_section("Test Section", &data);

        assert!(output.contains("Test Section:"));
        assert!(output.contains("Key1: Value1"));
        assert!(output.contains("Key2: Value2"));
    }
}
