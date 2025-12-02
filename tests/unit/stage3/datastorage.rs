//! Stage 3 Data Storage Protocol Classification Tests
//!
//! This test suite validates the Data Storage protocol classification functionality
//! in the Bitcoin P2MS Data-Carrying Protocol Analyser. Data Storage protocols
//! use specific burn patterns (proof-of-burn) to store arbitrary data on-chain.
//!
//! ## Test Coverage
//!
//! ### Burn Patterns Tested:
//! - **Proof-of-Burn (Compressed)**: 0x03 + all 0xFF bytes
//! - **Proof-of-Burn (Uncompressed)**: 0x04 + all 0xFF bytes
//! - **Invalid Patterns**: Ensuring non-burn patterns are not classified
//!
//! ### Protocol Variants:
//! - **DataStorageProofOfBurn**: Standard proof-of-burn pattern recognition
//!
//! These tests use synthetic burn patterns to verify classification logic
//! without requiring real Bitcoin transaction data.

use data_carry_research::processor::stage3::datastorage::DataStorageClassifier;
use data_carry_research::processor::stage3::ProtocolSpecificClassifier;
use data_carry_research::shared::datastorage_helpers::{detect_binary_signature, is_burn_pattern};
use data_carry_research::types::{
    EnrichedTransaction, ProtocolType, ProtocolVariant, TransactionOutput,
};
use serial_test::serial;

// Import standardised test utilities
use crate::common::fixtures;
use crate::common::protocol_test_base::setup_protocol_test;
use crate::common::test_output::TestOutputFormatter;

/// Data Storage protocol test data creation
mod test_data {
    use super::*;

    /// Display pubkey analysis for DataStorage patterns
    /// Uses production helpers: is_burn_pattern() and detect_binary_signature()
    pub fn display_pubkey_analysis(pubkeys: &[String]) -> String {
        let mut output = String::new();
        output.push_str("║ Pubkey Analysis:\n");

        for (i, pubkey) in pubkeys.iter().enumerate() {
            let hex_data = hex::decode(pubkey).unwrap_or_default();
            let preview = if pubkey.len() > 20 {
                format!("{}...", &pubkey[..20])
            } else {
                pubkey.clone()
            };

            // Detect patterns using production helpers
            if is_burn_pattern(&hex_data, Some(pubkey)) {
                output.push_str(&format!(
                    "║   Pubkey {}: {} [Proof-of-Burn: 0x{}]\n",
                    i + 1,
                    preview,
                    &pubkey[..4]
                ));
            } else if let Some(format) = detect_binary_signature(&hex_data) {
                output.push_str(&format!(
                    "║   Pubkey {}: {} [Format: {}]\n",
                    i + 1,
                    preview,
                    format
                ));
            } else {
                output.push_str(&format!("║   Pubkey {}: {} [Data]\n", i + 1, preview));
            }
        }
        output.push_str("║\n");
        output
    }

    /// Display concatenated data analysis
    pub fn display_concatenated_data_analysis(pubkeys: &[String]) -> String {
        let mut output = String::new();
        output.push_str("║ Data Concatenation Analysis:\n");

        // Concatenate all pubkey data
        let mut combined_data = Vec::new();
        for pubkey in pubkeys {
            if let Ok(data) = hex::decode(pubkey) {
                combined_data.extend_from_slice(&data);
            }
        }

        output.push_str(&format!(
            "║   Total data: {} bytes from {} output(s)\n",
            combined_data.len(),
            pubkeys.len()
        ));

        // Check for formats using production helper
        if let Some(format) = detect_binary_signature(&combined_data) {
            output.push_str(&format!("║   Detected format: {} (at offset 0)\n", format));
        }

        // Check for TAR at offset 257
        if combined_data.len() > 262 && &combined_data[257..262] == b"ustar" {
            output.push_str("║   Detected format: TAR (at offset 257)\n");
        }

        output.push_str("║\n");
        output
    }

    /// Extract concatenated data from pubkeys (for verification)
    pub fn extract_concatenated_data(pubkeys: &[String]) -> Vec<u8> {
        let mut combined_data = Vec::new();
        for pubkey in pubkeys {
            if let Ok(data) = hex::decode(pubkey) {
                combined_data.extend_from_slice(&data);
            }
        }
        combined_data
    }

    /// Verify extracted data matches reference file byte-for-byte
    ///
    /// The blockchain data includes an 8-byte header (4-byte length + 4-byte CRC32).
    /// Reference Python files are the raw scripts without this header.
    /// This function handles both formats:
    /// - If reference is .py file: compare against extracted_data[8..] (skip header)
    /// - If reference is .bin file: compare against full extracted_data (with header)
    pub fn verify_against_reference(
        extracted_data: &[u8],
        reference_path: &str,
    ) -> anyhow::Result<()> {
        use std::fs;

        let reference_data = fs::read(reference_path).map_err(|e| {
            anyhow::anyhow!("Failed to read reference file '{}': {}", reference_path, e)
        })?;

        println!("║");
        println!("║ Reference Verification:");
        println!("║   Reference file: {}", reference_path);
        println!("║   Reference size: {} bytes", reference_data.len());
        println!(
            "║   Blockchain data: {} bytes (8-byte header + script)",
            extracted_data.len()
        );

        // Determine comparison mode based on file extension
        let data_to_compare = if reference_path.ends_with(".py") {
            // Python file: skip 8-byte header from blockchain data
            if extracted_data.len() < 8 {
                anyhow::bail!(
                    "Extracted data too short ({} bytes), expected at least 8-byte header",
                    extracted_data.len()
                );
            }
            println!("║   Comparing: Python script (skip 8-byte header)");
            &extracted_data[8..]
        } else {
            // Binary file: compare full data including header
            println!("║   Comparing: Full blockchain data (with header)");
            extracted_data
        };

        println!("║   Comparison size: {} bytes", data_to_compare.len());

        if data_to_compare.len() != reference_data.len() {
            anyhow::bail!(
                "Size mismatch: comparison data {} bytes but reference has {} bytes",
                data_to_compare.len(),
                reference_data.len()
            );
        }

        // Byte-by-byte comparison
        for (i, (extracted_byte, reference_byte)) in data_to_compare
            .iter()
            .zip(reference_data.iter())
            .enumerate()
        {
            if extracted_byte != reference_byte {
                anyhow::bail!(
                    "Byte mismatch at offset {}: extracted=0x{:02x} reference=0x{:02x}",
                    i,
                    extracted_byte,
                    reference_byte
                );
            }
        }

        println!("║   ✅ Byte-for-byte match verified");
        println!("║");

        Ok(())
    }

    /// Create a test transaction with specific pubkey patterns for burn testing
    pub fn create_transaction_with_pubkeys(
        txid: &str,

        pubkeys: Vec<String>,
    ) -> EnrichedTransaction {
        let mut tx = fixtures::create_test_enriched_transaction(txid);

        // Override p2ms_outputs with test pubkeys
        tx.outputs = vec![{
            use data_carry_research::types::script_metadata::MultisigInfo;
            let info = MultisigInfo {
                pubkeys: pubkeys.clone(),
                required_sigs: 1,
                total_pubkeys: pubkeys.len() as u32,
            };
            TransactionOutput {
                txid: txid.to_string(),
                vout: 0,
                height: 0,
                amount: 1000,
                script_hex: "mock_script".to_string(),
                script_type: "multisig".to_string(),
                is_coinbase: false,
                script_size: 100,
                metadata: serde_json::to_value(info).unwrap(),
                address: None,
            }
        }];

        tx
    }

    /// Create a compressed proof-of-burn transaction (0x03 + all 0xFF)
    pub fn create_compressed_burn_transaction(txid: &str) -> EnrichedTransaction {
        create_transaction_with_pubkeys(
            txid,
            vec!["03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()],
        )
    }

    /// Create an uncompressed proof-of-burn transaction (0x04 + all 0xFF)
    pub fn create_uncompressed_burn_transaction(txid: &str) -> EnrichedTransaction {
        create_transaction_with_pubkeys(
            txid,
            // Uncompressed key: 0x04 (1 byte) + 32 bytes X + 32 bytes Y = 65 bytes = 130 hex chars
            vec!["04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()],
        )
    }

    /// Create a non-burn transaction (normal pubkey)
    pub fn create_normal_transaction(txid: &str) -> EnrichedTransaction {
        create_transaction_with_pubkeys(
            txid,
            vec!["0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string()],
        )
    }
}

/// Basic Data Storage protocol classification tests
mod basic_classification {
    use super::*;
    use anyhow::Result;

    #[test]
    #[serial]
    fn test_datastorage_compressed_proof_of_burn() -> Result<()> {
        let test_name = "datastorage_compressed";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Display test header
        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // Test compressed proof-of-burn pattern (0x03 + all 0xFF)
        let burn_tx = test_data::create_compressed_burn_transaction("compressed_burn");

        println!("║ P2MS Outputs: {}", burn_tx.outputs.len());
        println!("║");

        // Display pubkey analysis
        for output in &burn_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&burn_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "Expected classification result for compressed burn"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageProofOfBurn)
        );
        assert!(classification
            .classification_details
            .additional_metadata
            .is_some());

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_uncompressed_proof_of_burn() -> Result<()> {
        let test_name = "datastorage_uncompressed";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Display test header
        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // Test uncompressed proof-of-burn pattern (0x04 + all 0xFF)
        let burn_tx = test_data::create_uncompressed_burn_transaction("uncompressed_burn");

        println!("║ P2MS Outputs: {}", burn_tx.outputs.len());
        println!("║");

        // Display pubkey analysis
        for output in &burn_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&burn_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "Expected classification result for uncompressed burn"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageProofOfBurn)
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_normal_pubkey_not_classified() -> Result<()> {
        let test_name = "datastorage_normal";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Display test header
        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // Test normal pubkey (should not be classified as data storage)
        let normal_tx = test_data::create_normal_transaction("normal_tx");

        println!("║ P2MS Outputs: {}", normal_tx.outputs.len());
        println!("║");

        // Display pubkey analysis
        for output in &normal_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&normal_tx, test_db.database_mut());
        assert!(
            result.is_none(),
            "Normal pubkey should not be classified as data storage"
        );

        println!("║ ✅ Result: Not classified (expected behaviour)");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        Ok(())
    }
}

/// Edge case tests for Data Storage protocol
mod edge_cases {
    use super::*;
    use anyhow::Result;

    #[test]
    #[serial]
    fn test_datastorage_partial_burn_pattern_not_classified() -> Result<()> {
        let test_name = "datastorage_partial";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Display test header
        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // Test partial burn pattern (not all 0xFF)
        let partial_burn_tx = test_data::create_transaction_with_pubkeys(
            "partial_burn",
            vec!["03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00".to_string()],
        );

        println!("║ P2MS Outputs: {}", partial_burn_tx.outputs.len());
        println!("║");

        for output in &partial_burn_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&partial_burn_tx, test_db.database_mut());
        assert!(
            result.is_none(),
            "Partial burn pattern should not be classified"
        );

        println!("║ ✅ Result: Not classified (expected - incomplete pattern)");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_wrong_prefix_not_classified() -> Result<()> {
        let test_name = "datastorage_wrong_prefix";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // Test wrong prefix (0x01 is invalid for compressed keys, should be 0x02/0x03)
        let wrong_prefix_tx = test_data::create_transaction_with_pubkeys(
            "wrong_prefix",
            vec!["01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()],
        );

        println!("║ P2MS Outputs: {}", wrong_prefix_tx.outputs.len());
        println!("║");

        for output in &wrong_prefix_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&wrong_prefix_tx, test_db.database_mut());
        assert!(result.is_none(), "Wrong prefix should not be classified");

        println!("║ ✅ Result: Not classified (expected - invalid prefix)");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_empty_pubkeys_not_classified() -> Result<()> {
        let test_name = "datastorage_empty";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // Test transaction with no pubkeys
        let empty_tx = test_data::create_transaction_with_pubkeys("empty_tx", vec![]);

        println!("║ P2MS Outputs: {}", empty_tx.outputs.len());
        println!("║ No pubkeys to analyse");
        println!("║");

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&empty_tx, test_db.database_mut());
        assert!(result.is_none(), "Empty pubkeys should not be classified");

        println!("║ ✅ Result: Not classified (expected - no pubkeys)");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        Ok(())
    }
}

/// Archive format detection tests
mod archive_formats {
    use super::*;
    use anyhow::Result;

    #[test]
    #[serial]
    fn test_datastorage_gzip_detection() -> Result<()> {
        let test_name = "datastorage_gzip";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // GZIP magic: 0x1f 0x8b 0x08 (DEFLATE)
        let gzip_header = hex::encode([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Pad to 33 bytes (compressed pubkey length)
        let gzip_pubkey = format!("{}{}", gzip_header, "00".repeat(25));

        let gzip_tx = test_data::create_transaction_with_pubkeys("gzip_tx", vec![gzip_pubkey]);

        println!("║ P2MS Outputs: {}", gzip_tx.outputs.len());
        println!("║");

        for output in &gzip_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&gzip_tx, test_db.database_mut());
        assert!(result.is_some(), "GZIP signature should be detected");

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );
        assert!(classification
            .classification_details
            .classification_method
            .contains("GZIP"));

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_zlib_moderate_compression() -> Result<()> {
        let test_name = "datastorage_zlib";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // ZLIB moderate compression: 0x78 0x5e
        // CMF/FLG checksum: (0x78 * 256 + 0x5e) % 31 = 30750 % 31 = 0 ✓
        let zlib_header = hex::encode([0x78, 0x5e]);
        let zlib_pubkey = format!("{}{}", zlib_header, "00".repeat(31));

        let zlib_tx = test_data::create_transaction_with_pubkeys("zlib_tx", vec![zlib_pubkey]);

        println!("║ P2MS Outputs: {}", zlib_tx.outputs.len());
        println!("║");

        for output in &zlib_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&zlib_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "ZLIB moderate compression (0x78 0x5e) should be detected"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );
        assert!(classification
            .classification_details
            .classification_method
            .contains("ZLIB"));

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_bzip2_detection() -> Result<()> {
        let test_name = "datastorage_bzip2";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // BZIP2 magic: BZh9 (0x42 0x5a 0x68 0x39)
        let bzip2_header = hex::encode([0x42, 0x5a, 0x68, 0x39]);
        let bzip2_pubkey = format!("{}{}", bzip2_header, "00".repeat(29));

        let bzip2_tx = test_data::create_transaction_with_pubkeys("bzip2_tx", vec![bzip2_pubkey]);

        println!("║ P2MS Outputs: {}", bzip2_tx.outputs.len());
        println!("║");

        for output in &bzip2_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&bzip2_tx, test_db.database_mut());
        assert!(result.is_some(), "BZIP2 signature should be detected");

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );
        assert!(classification
            .classification_details
            .classification_method
            .contains("BZIP2"));

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_tar_detection_concatenated() -> Result<()> {
        let test_name = "datastorage_tar";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // TAR requires magic "ustar\0" or "ustar  " at offset 257
        // Real data-embedding transactions use RAW DATA chunks (not valid ECDSA pubkeys)
        // Each chunk = 65 bytes (no prefix, just raw data like Linpyro transaction)
        let tar_magic = b"ustar\0";
        let mut pubkeys = Vec::new();

        // First 3 chunks: padding (195 bytes total, bytes 0-194)
        for i in 0..3 {
            let chunk = vec![i as u8; 65];
            pubkeys.push(hex::encode(&chunk));
        }

        // 4th chunk: padding + tar magic start
        // Chunk 4 is bytes 195-259 (65 bytes)
        // Tar magic should start at byte 257 (offset 257 in concatenated data)
        // Offset within chunk 4: 257 - 195 = 62
        let mut chunk_4 = vec![0xCC; 62]; // Padding (bytes 195-256)
        chunk_4.extend_from_slice(&tar_magic[..3]); // "ust" (bytes 257-259, only 3 bytes fit)
        pubkeys.push(hex::encode(&chunk_4));

        // 5th chunk: continue tar magic + padding
        // Chunk 5 is bytes 260-324
        let mut chunk_5 = vec![];
        chunk_5.extend_from_slice(&tar_magic[3..]); // "ar\0" (bytes 260-262)
        chunk_5.extend_from_slice(&[0xDD; 62]); // Padding (bytes 263-324)
        pubkeys.push(hex::encode(&chunk_5));

        let tar_tx = test_data::create_transaction_with_pubkeys("tar_tx", pubkeys.clone());

        println!("║ P2MS Outputs: {}", tar_tx.outputs.len());
        println!("║");

        // Show concatenation analysis for TAR (the magic is split across outputs)
        print!(
            "{}",
            test_data::display_concatenated_data_analysis(&pubkeys)
        );

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&tar_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "TAR signature at offset 257 should be detected after concatenation"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );
        assert!(
            classification
                .classification_details
                .classification_method
                .contains("TAR"),
            "Classification method should mention TAR, got: {}",
            classification.classification_details.classification_method
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_png_detection() -> Result<()> {
        let test_name = "datastorage_png";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // PNG magic: 89 50 4E 47 0D 0A 1A 0A
        let png_header = hex::encode([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        let png_pubkey = format!("{}{}", png_header, "00".repeat(25));

        let png_tx = test_data::create_transaction_with_pubkeys("png_tx", vec![png_pubkey]);

        println!("║ P2MS Outputs: {}", png_tx.outputs.len());
        println!("║");

        for output in &png_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&png_tx, test_db.database_mut());
        assert!(result.is_some(), "PNG signature should be detected");

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );
        assert!(classification
            .classification_details
            .classification_method
            .contains("PNG"));

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_datastorage_pdf_detection() -> Result<()> {
        let test_name = "datastorage_pdf";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // PDF magic: %PDF (0x25 0x50 0x44 0x46)
        let pdf_header = hex::encode(b"%PDF");
        let pdf_pubkey = format!("{}{}", pdf_header, "00".repeat(29));

        let pdf_tx = test_data::create_transaction_with_pubkeys("pdf_tx", vec![pdf_pubkey]);

        println!("║ P2MS Outputs: {}", pdf_tx.outputs.len());
        println!("║");

        for output in &pdf_tx.outputs {
            if let Some(info) = output.multisig_info() {
                print!("{}", test_data::display_pubkey_analysis(&info.pubkeys));
            }
        }

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&pdf_tx, test_db.database_mut());
        assert!(result.is_some(), "PDF signature should be detected");

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );
        assert!(classification
            .classification_details
            .classification_method
            .contains("PDF"));

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }
}

/// Real-world transaction tests using actual blockchain data
mod real_transactions {
    use super::*;
    use crate::common::protocol_test_base::load_p2ms_outputs_from_json;
    use anyhow::Result;

    #[test]
    #[serial]
    fn test_linpyro_transaction_1() -> Result<()> {
        let test_name = "linpyro_tx1";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Load real Linpyro transaction 3344647bc080...
        let txid = "3344647bc0801d3c4f5ca9a33106e6e4ed34754a1d7833e7bbcdc9094db347b0";

        print!(
            "{}",
            TestOutputFormatter::format_test_header("DataStorage", test_name, txid)
        );

        let p2ms_outputs =
            load_p2ms_outputs_from_json("tests/test_data/datastorage/3344647bc080.json", txid)?;

        println!("║ TXID: {}...", &txid[..32]);
        println!("║ Block Height: 230009");
        println!("║ P2MS Outputs: {}", p2ms_outputs.len());
        println!("║");

        // Collect all pubkeys for analysis
        let all_pubkeys: Vec<String> = p2ms_outputs
            .iter()
            .flat_map(|o| {
                o.multisig_info()
                    .map(|i| i.pubkeys.clone())
                    .unwrap_or_default()
            })
            .collect();

        print!(
            "{}",
            test_data::display_concatenated_data_analysis(&all_pubkeys)
        );

        // Create EnrichedTransaction
        let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
        enriched_tx.outputs = p2ms_outputs.clone();
        enriched_tx.p2ms_outputs_count = p2ms_outputs.len();

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&enriched_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "Linpyro transaction 1 (3344647bc080...) should be classified as DataStorage"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );

        // Should detect GZIP compression (Linpyro is gzipped tar)
        assert!(
            classification
                .classification_details
                .classification_method
                .contains("GZIP"),
            "Should detect GZIP compression, got: {}",
            classification.classification_details.classification_method
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_linpyro_transaction_2() -> Result<()> {
        let test_name = "linpyro_tx2";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Load real Linpyro transaction d246f58b59be...
        let txid = "d246f58b59be6595df03c404a6497177564c7b2bf5396596641e59d268b1b40d";

        print!(
            "{}",
            TestOutputFormatter::format_test_header("DataStorage", test_name, txid)
        );

        let p2ms_outputs =
            load_p2ms_outputs_from_json("tests/test_data/datastorage/d246f58b59be.json", txid)?;

        println!("║ TXID: {}...", &txid[..32]);
        println!("║ Block Height: 230009");
        println!("║ P2MS Outputs: {}", p2ms_outputs.len());
        println!("║");

        let all_pubkeys: Vec<String> = p2ms_outputs
            .iter()
            .flat_map(|o| {
                o.multisig_info()
                    .map(|i| i.pubkeys.clone())
                    .unwrap_or_default()
            })
            .collect();

        print!(
            "{}",
            test_data::display_concatenated_data_analysis(&all_pubkeys)
        );

        // Create EnrichedTransaction
        let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
        enriched_tx.outputs = p2ms_outputs.clone();
        enriched_tx.p2ms_outputs_count = p2ms_outputs.len();

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&enriched_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "Linpyro transaction 2 (d246f58b59be...) should be classified as DataStorage"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );

        // Should detect GZIP compression
        assert!(
            classification
                .classification_details
                .classification_method
                .contains("GZIP"),
            "Should detect GZIP compression, got: {}",
            classification.classification_details.classification_method
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_wikileaks_python_script_1() -> Result<()> {
        let test_name = "wikileaks_python_1";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Load first WikiLeaks Python script transaction 6c53cd98...
        // This contains a File downloader script (#!/usr/bin/python3)
        let txid = "6c53cd987119ef797d5adccd76241247988a0a5ef783572a9972e7371c5fb0cc";

        print!(
            "{}",
            TestOutputFormatter::format_test_header("DataStorage", test_name, txid)
        );

        let p2ms_outputs = load_p2ms_outputs_from_json(
            "tests/test_data/datastorage/wikileaks_python_6c53cd98.json",
            txid,
        )?;

        println!("║ TXID: {}...", &txid[..32]);
        println!("║ Block Height: 230009");
        println!("║ P2MS Outputs: {}", p2ms_outputs.len());
        println!("║ Content: Python script (#!/usr/bin/python3)");
        println!("║");

        let all_pubkeys: Vec<String> = p2ms_outputs
            .iter()
            .flat_map(|o| {
                o.multisig_info()
                    .map(|i| i.pubkeys.clone())
                    .unwrap_or_default()
            })
            .collect();

        print!(
            "{}",
            test_data::display_concatenated_data_analysis(&all_pubkeys)
        );

        // Extract and verify data matches blockchain reference
        // Blockchain data includes 8-byte header; reference .py is just the script
        let extracted_data = test_data::extract_concatenated_data(&all_pubkeys);
        test_data::verify_against_reference(
            &extracted_data,
            "tests/test_data/datastorage/wikileaks_downloader_blockchain.py",
        )?;

        // Create EnrichedTransaction
        let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
        enriched_tx.outputs = p2ms_outputs.clone();
        enriched_tx.p2ms_outputs_count = p2ms_outputs.len();

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&enriched_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "WikiLeaks Python script 1 (6c53cd98...) should be classified as DataStorage"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);

        // FIXED: Correctly detects as embedded data (Python script) despite containing git:// URL
        // Text content detection now takes priority over incidental URL references
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );

        // Should mention embedded text data
        assert!(
            classification
                .classification_details
                .classification_method
                .contains("Text data"),
            "Should detect embedded text data, got: {}",
            classification.classification_details.classification_method
        );

        // Content type should be text/x-python (from ContentType::detect)
        assert_eq!(
            classification.classification_details.content_type,
            Some("text/x-python".to_string()),
            "Content type should be text/x-python for Python script"
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_wikileaks_python_script_2() -> Result<()> {
        let test_name = "wikileaks_python_2";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Load second WikiLeaks Python script transaction 4b72a223...
        // This contains a File insertion tool script
        let txid = "4b72a223007eab8a951d43edc171befeabc7b5dca4213770c88e09ba5b936e17";

        print!(
            "{}",
            TestOutputFormatter::format_test_header("DataStorage", test_name, txid)
        );

        let p2ms_outputs = load_p2ms_outputs_from_json(
            "tests/test_data/datastorage/wikileaks_python_4b72a223.json",
            txid,
        )?;

        println!("║ TXID: {}...", &txid[..32]);
        println!("║ Block Height: 230009");
        println!("║ P2MS Outputs: {}", p2ms_outputs.len());
        println!("║ Content: Python script (file insertion tool)");
        println!("║");

        let all_pubkeys: Vec<String> = p2ms_outputs
            .iter()
            .flat_map(|o| {
                o.multisig_info()
                    .map(|i| i.pubkeys.clone())
                    .unwrap_or_default()
            })
            .collect();

        print!(
            "{}",
            test_data::display_concatenated_data_analysis(&all_pubkeys)
        );

        // Extract and verify data matches blockchain reference
        // Blockchain data includes 8-byte header; reference .py is just the script
        let extracted_data = test_data::extract_concatenated_data(&all_pubkeys);
        test_data::verify_against_reference(
            &extracted_data,
            "tests/test_data/datastorage/wikileaks_uploader_blockchain.py",
        )?;

        // Create EnrichedTransaction
        let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
        enriched_tx.outputs = p2ms_outputs.clone();
        enriched_tx.p2ms_outputs_count = p2ms_outputs.len();

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&enriched_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "WikiLeaks Python script 2 (4b72a223...) should be classified as DataStorage"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);

        // FIXED: Correctly detects as embedded data (Python script) despite containing git:// URL
        // Text content detection now takes priority over incidental URL references
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData)
        );

        // Should mention embedded text data
        assert!(
            classification
                .classification_details
                .classification_method
                .contains("Text data"),
            "Should detect embedded text data, got: {}",
            classification.classification_details.classification_method
        );

        // Content type should be text/x-python (from ContentType::detect)
        assert_eq!(
            classification.classification_details.content_type,
            Some("text/x-python".to_string()),
            "Content type should be text/x-python for Python script"
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_null_data_classification() -> Result<()> {
        let test_name = "datastorage_null";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Load real transaction with all-zero pubkey data
        // TXID: 9cf7c3fcf15ec0427a98623abe1fa752ad10c1615670c0dbe0a11516f277540e
        let txid = "9cf7c3fcf15ec0427a98623abe1fa752ad10c1615670c0dbe0a11516f277540e";

        print!(
            "{}",
            TestOutputFormatter::format_test_header("DataStorage", test_name, txid)
        );

        let p2ms_outputs = load_p2ms_outputs_from_json(
            "tests/test_data/datastorage/nulldata_9cf7c3fc.json",
            txid,
        )?;

        println!("║ TXID: {}...", &txid[..32]);
        println!("║ Block Height: 420336");
        println!("║ P2MS Outputs: {}", p2ms_outputs.len());
        println!("║ Content: All-zero pubkey (33 bytes of 0x00)");
        println!("║");

        let all_pubkeys: Vec<String> = p2ms_outputs
            .iter()
            .flat_map(|o| {
                o.multisig_info()
                    .map(|i| i.pubkeys.clone())
                    .unwrap_or_default()
            })
            .collect();

        print!("{}", test_data::display_pubkey_analysis(&all_pubkeys));

        // Create EnrichedTransaction
        let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
        enriched_tx.outputs = p2ms_outputs.clone();
        enriched_tx.p2ms_outputs_count = p2ms_outputs.len();

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&enriched_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "Null data transaction (9cf7c3fc...) should be classified as DataStorage"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageNullData),
            "All-zero data should be classified as DataStorageNullData"
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_url_embedding_classification() -> Result<()> {
        let test_name = "datastorage_url";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Load real transaction with URL embedded in pubkeys
        // TXID: 0716406f435e576bea06a9de51b3756594f59c8c7272f9c41b63a90442348d07
        // Contains: midasrezerv.com/reports/amst-iss-00001.zip
        let txid = "0716406f435e576bea06a9de51b3756594f59c8c7272f9c41b63a90442348d07";

        print!(
            "{}",
            TestOutputFormatter::format_test_header("DataStorage", test_name, txid)
        );

        let p2ms_outputs =
            load_p2ms_outputs_from_json("tests/test_data/datastorage/url_embedding.json", txid)?;

        println!("║ TXID: {}...", &txid[..32]);
        println!("║ Block Height: 350000");
        println!("║ P2MS Outputs: {}", p2ms_outputs.len());
        println!("║ Content: URL embedded across pubkeys");
        println!("║  midasrezerv.com/reports/amst-iss-00001.zip");
        println!("║");

        let all_pubkeys: Vec<String> = p2ms_outputs
            .iter()
            .flat_map(|o| {
                o.multisig_info()
                    .map(|i| i.pubkeys.clone())
                    .unwrap_or_default()
            })
            .collect();

        print!(
            "{}",
            test_data::display_concatenated_data_analysis(&all_pubkeys)
        );

        // Create EnrichedTransaction
        let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
        enriched_tx.outputs = p2ms_outputs.clone();
        enriched_tx.p2ms_outputs_count = p2ms_outputs.len();

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&enriched_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "URL embedding transaction (0716406f...) should be classified as DataStorage"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageFileMetadata),
            "URL/file reference should be classified as DataStorageFileMetadata (file metadata has higher priority than generic text)"
        );

        // Should mention file metadata (URLs have semantic meaning beyond just being text)
        assert!(
            classification
                .classification_details
                .classification_method
                .contains("File metadata"),
            "Should detect file metadata, got: {}",
            classification.classification_details.classification_method
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn test_ascii_personal_message_classification() -> Result<()> {
        let test_name = "datastorage_ascii_message";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        // Load real transaction with ASCII personal message in P2MS pubkey
        // TXID: 4a3574cd6053c14f6858555b942da16d1f6594aa1750e515c1f6be77e7f686e4
        // Contains: {"":"Hello People! How are you? By: Fedor."}
        // This is TX #4 from the Unknown analysis - should be classified by DataStorage
        let txid = "4a3574cd6053c14f6858555b942da16d1f6594aa1750e515c1f6be77e7f686e4";

        print!(
            "{}",
            TestOutputFormatter::format_test_header("DataStorage", test_name, txid)
        );

        let p2ms_outputs = load_p2ms_outputs_from_json(
            "tests/test_data/datastorage/ascii_message_4a3574cd.json",
            txid,
        )?;

        println!("║ TXID: {}...", &txid[..32]);
        println!("║ Block Height: 299533");
        println!("║ P2MS Outputs: {}", p2ms_outputs.len());
        println!("║ Content: ASCII message in P2MS pubkey");
        println!("║  \"Hello People! How are you? By: Fedor.\"");
        println!("║");

        let all_pubkeys: Vec<String> = p2ms_outputs
            .iter()
            .flat_map(|o| {
                o.multisig_info()
                    .map(|i| i.pubkeys.clone())
                    .unwrap_or_default()
            })
            .collect();

        print!("{}", test_data::display_pubkey_analysis(&all_pubkeys));

        // Verify the ASCII content is present (69.2% printable ASCII)
        let concatenated = test_data::extract_concatenated_data(&all_pubkeys);
        let text = String::from_utf8_lossy(&concatenated);
        assert!(
            text.contains("Hello People"),
            "Should contain the ASCII message"
        );

        // Create EnrichedTransaction
        let mut enriched_tx = fixtures::create_test_enriched_transaction(txid);
        enriched_tx.outputs = p2ms_outputs.clone();
        enriched_tx.p2ms_outputs_count = p2ms_outputs.len();

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&enriched_tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "ASCII personal message transaction (4a3574cd...) should be classified as DataStorage"
        );

        let (classification, _output_classifications) = result.unwrap();
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData),
            "ASCII message should be classified as DataStorageEmbeddedData"
        );

        // Should mention embedded text data
        assert!(
            classification
                .classification_details
                .classification_method
                .contains("Text data"),
            "Should detect embedded text data, got: {}",
            classification.classification_details.classification_method
        );

        // Content type: Mixed binary/text data with 0xFF padding gets classified as octet-stream
        assert_eq!(
            classification.classification_details.content_type,
            Some("application/octet-stream".to_string()),
            "Content type should be application/octet-stream (mixed binary/text with 0xFF padding)"
        );

        print!(
            "{}",
            TestOutputFormatter::format_test_footer("DataStorage", "Pattern-based detection")
        );

        Ok(())
    }
}

/// Bitcoin Whitepaper detection tests (TXID-based artifact detection)
mod bitcoin_whitepaper {
    use super::*;
    use anyhow::Result;

    /// The Bitcoin Whitepaper TXID (must match the constant in datastorage.rs)
    const BITCOIN_WHITEPAPER_TXID: &str =
        "54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713";

    #[test]
    #[serial]
    fn test_bitcoin_whitepaper_txid_detection() -> Result<()> {
        let test_name = "bitcoin_whitepaper";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // Create a minimal transaction with the whitepaper TXID
        // The classifier detects by TXID alone, so we only need basic structure
        let mut tx = fixtures::create_test_enriched_transaction(BITCOIN_WHITEPAPER_TXID);
        tx.height = 230_009; // Historical height of the whitepaper

        // Add a synthetic P2MS output (classifier requires at least one for output classifications)
        tx.outputs = vec![{
            use data_carry_research::types::script_metadata::MultisigInfo;
            let info = MultisigInfo {
                pubkeys: vec![
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                        .to_string(),
                ],
                required_sigs: 1,
                total_pubkeys: 1,
            };
            TransactionOutput {
                txid: BITCOIN_WHITEPAPER_TXID.to_string(),
                vout: 0,
                height: 230_009,
                amount: 1000,
                script_hex: "mock_script".to_string(),
                script_type: "multisig".to_string(),
                is_coinbase: false,
                script_size: 100,
                metadata: serde_json::to_value(info).unwrap(),
                address: None,
            }
        }];
        tx.p2ms_outputs_count = 1;

        println!("║ TXID: {}", BITCOIN_WHITEPAPER_TXID);
        println!("║ Block Height: 230,009");
        println!("║ Detection Method: Hardcoded TXID match");
        println!("║");

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "Bitcoin Whitepaper TXID should be detected"
        );

        let (classification, output_classifications) = result.unwrap();

        // Verify transaction-level classification
        assert_eq!(
            classification.protocol,
            ProtocolType::DataStorage,
            "Protocol should be DataStorage"
        );
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageBitcoinWhitepaper),
            "Variant should be DataStorageBitcoinWhitepaper"
        );

        // Verify content type is PDF
        assert_eq!(
            classification.classification_details.content_type,
            Some("application/pdf".to_string()),
            "Content type should be application/pdf for the Bitcoin Whitepaper"
        );

        // Verify classification method mentions known artifact
        assert!(
            classification
                .classification_details
                .classification_method
                .contains("Known historical artifact"),
            "Classification method should mention known artifact detection"
        );

        // Verify output-level classification also has correct content type
        assert!(!output_classifications.is_empty());
        for output_class in &output_classifications {
            assert_eq!(
                output_class.details.content_type,
                Some("application/pdf".to_string()),
                "Output content type should also be application/pdf"
            );
        }

        println!("║ ✅ Protocol: DataStorage");
        println!("║ ✅ Variant: Bitcoin Whitepaper");
        println!("║ ✅ Content-Type: application/pdf");
        println!("║ ✅ Detection: Known historical artifact (TXID match)");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        Ok(())
    }

    #[test]
    #[serial]
    fn test_non_whitepaper_txid_not_matched() -> Result<()> {
        let test_name = "non_whitepaper";
        let (mut test_db, _config) = setup_protocol_test(test_name)?;
        let classifier = DataStorageClassifier;

        print!(
            "{}",
            TestOutputFormatter::format_test_header_simple("DataStorage", test_name)
        );

        // Create a transaction with a different TXID that has PDF-like content
        // This should NOT be classified as Bitcoin Whitepaper (TXID doesn't match)
        let fake_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // PDF magic bytes: %PDF
        let pdf_header = hex::encode(b"%PDF-1.4");
        let pdf_pubkey = format!("{}{}", pdf_header, "00".repeat(25));

        let tx = test_data::create_transaction_with_pubkeys(fake_txid, vec![pdf_pubkey]);

        println!("║ TXID: {} (NOT whitepaper)", fake_txid);
        println!("║ Content: PDF magic bytes in pubkey");
        println!("║ Expected: Should be DataStorageEmbeddedData (NOT BitcoinWhitepaper)");
        println!("║");

        println!("║ Running DataStorage Classification...");
        println!("║");

        let result = classifier.classify(&tx, test_db.database_mut());
        assert!(
            result.is_some(),
            "PDF content should still be detected as DataStorage"
        );

        let (classification, _) = result.unwrap();

        // Should be detected as EmbeddedData, NOT BitcoinWhitepaper
        assert_eq!(classification.protocol, ProtocolType::DataStorage);
        assert_eq!(
            classification.variant,
            Some(ProtocolVariant::DataStorageEmbeddedData),
            "Non-whitepaper TXID should be classified as EmbeddedData, not BitcoinWhitepaper"
        );

        // Should NOT be application/pdf (generic PDF detection uses different logic)
        // The generic PDF detection uses ContentType::detect which may or may not return PDF

        println!("║ ✅ Protocol: DataStorage");
        println!("║ ✅ Variant: EmbeddedData (NOT BitcoinWhitepaper)");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        Ok(())
    }
}
