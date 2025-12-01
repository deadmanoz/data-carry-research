//! Stage 3 Bitcoin Stamps Protocol Classification Tests
//!
//! This test suite validates the Bitcoin Stamps protocol classification functionality
//! in the Bitcoin P2MS Data-Carrying Protocol Analyser. Bitcoin Stamps use specific
//! burn patterns and P2MS encoding to embed digital art and files in the Bitcoin blockchain.
//!
//! ## Test Coverage
//!
//! ### Transaction Patterns:
//! - **Key-Burn Pattern Recognition**: Stamps22, Stamps33, and alternating patterns
//! - **P2MS Encoding**: 1-of-2 and 1-of-3 multisig patterns for data storage
//! - **SRC-20 Tokens**: Bitcoin Stamps token transactions
//!
//! ### Burn Patterns Tested:
//! - **Stamps22**: 022222... (most common pattern)
//! - **Stamps33**: 033333... (alternative pattern)
//! - **Alternating**: 020202... and 030303... patterns
//!
//! ### Real Bitcoin Transactions:
//! All tests use authentic Bitcoin mainnet transaction data from JSON fixtures,
//! ensuring validation against real-world Bitcoin Stamps protocol usage.

use data_carry_research::types::burn_patterns::{classify_stamps_burn, BurnPatternType};
use std::path::Path;

// Import standardised test utilities
use crate::common::fixture_registry::{self, ProtocolFixture};
use crate::common::protocol_test_base::{load_p2ms_outputs_from_json, ProtocolTestBuilder};

/// Run a stamps test using the unified ProtocolTestBuilder
async fn run_stamps_fixture_test(fixture: &'static ProtocolFixture) {
    // Bitcoin Stamps requires inputs for ARC4 key derivation (first input TXID)
    // NOTE: Burn patterns NOT required for Stage 3 classification.
    // Stage 3 classifies via cryptographic signature detection ("stamp:" prefix).
    let result = ProtocolTestBuilder::from_fixture(fixture)
        .with_inputs()
        .execute()
        .await;

    if let Err(e) = result {
        panic!("Bitcoin Stamps test failed: {}", e);
    }
}

/// SRC-20 Token transaction tests
mod src20_tokens {
    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_src20_deploy() {
        run_stamps_fixture_test(&fixture_registry::stamps::SRC20_DEPLOY).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_src20_mint() {
        run_stamps_fixture_test(&fixture_registry::stamps::SRC20_MINT).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_src20_transfer() {
        run_stamps_fixture_test(&fixture_registry::stamps::SRC20_TRANSFER).await;
    }
}

/// Image and data encoding tests
mod image_encoding {
    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_classic_image() {
        run_stamps_fixture_test(&fixture_registry::stamps::CLASSIC_4D89D7).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_recent_multisig_format() {
        run_stamps_fixture_test(&fixture_registry::stamps::RECENT_C8C383).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_original_image_format() {
        run_stamps_fixture_test(&fixture_registry::stamps::ORIGINAL_IMAGE).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_historical_f35382() {
        run_stamps_fixture_test(&fixture_registry::stamps::CLASSIC_F35382).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_arc4_decoding_with_structure_verification() {
        // Test ARC4 decoding with detailed Counterparty structure verification
        use data_carry_research::crypto::arc4;
        use data_carry_research::types::stamps::validation;

        let txid = "54fdeda90c4573f8a93fa45251a3c6214bcc79aa8549728dfb08ffe3e7dd3d81";
        let fixture_path = "tests/test_data/stamps/54fdeda90c4573f8a93fa45251a3c6214bcc79aa8549728dfb08ffe3e7dd3d81.json";

        println!("\n╔══════════════════════════════════════════════════════════════");
        println!("║ Testing ARC4 Decoding with Structure Verification           ");
        println!("╠══════════════════════════════════════════════════════════════");
        println!("║ TXID: {}...", &txid[..12]);
        println!("╟──────────────────────────────────────────────────────────────");

        if !Path::new(fixture_path).exists() {
            println!("⚠️  Test skipped: missing fixture {}", fixture_path);
            return;
        }

        // Load P2MS outputs
        let p2ms_outputs = load_p2ms_outputs_from_json(fixture_path, txid)
            .expect("Failed to load P2MS outputs from JSON");
        println!("║ Loaded {} P2MS outputs", p2ms_outputs.len());
        assert!(!p2ms_outputs.is_empty());

        // Get first input TXID for ARC4 key
        let first_input_txid = "3b2b5e1de60ba341b8ba85e35b09800edb118dc7bee246d54b11420f01aabac5";
        let arc4_key = arc4::prepare_key_from_txid(first_input_txid)
            .expect("Failed to prepare ARC4 key from first input txid");
        println!("║ ARC4 key prepared: {} bytes", arc4_key.len());
        assert_eq!(arc4_key.len(), 32);

        // Process with production code
        let stamps_result = validation::process_multioutput_stamps(&p2ms_outputs, &arc4_key)
            .expect("Production ARC4 decoding should succeed");

        println!("║ Production decoding results:");
        println!("║   Valid outputs: {}", stamps_result.valid_outputs.len());
        println!("║   Decoded bytes: {}", stamps_result.decrypted_data.len());
        println!("║   STAMP offset: {}", stamps_result.stamp_signature_offset);

        // Verify Counterparty structure
        let data = &stamps_result.decrypted_data;
        assert!(
            data.len() >= 29,
            "Should have minimum Counterparty structure"
        );

        // Check Counterparty signature
        assert_eq!(&data[0..8], b"CNTRPRTY", "Should have CNTRPRTY signature");
        println!("║ ✅ Valid CNTRPRTY signature");

        // Check message type (20 = Issuance)
        assert_eq!(data[8], 20, "Should be message type 20 (Issuance)");
        println!("║ ✅ Message type 20 (Issuance)");

        // Verify asset ID
        if data.len() >= 17 {
            let asset_id = u64::from_be_bytes([
                data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
            ]);
            println!("║ ✅ Asset ID: 0x{:016x}", asset_id);
        }

        // Verify stamp signature
        let (detected_offset, detected_variant) =
            validation::find_stamp_signature(data).expect("Should find stamp signature");
        assert_eq!(detected_offset, stamps_result.stamp_signature_offset);
        assert_eq!(detected_variant, stamps_result.stamp_signature_variant);
        println!(
            "║ ✅ Stamp signature {:?} at offset {}",
            detected_variant, detected_offset
        );

        println!("╚══════════════════════════════════════════════════════════════");
    }
}

/// Burn pattern detection tests
mod burn_patterns {
    use super::*;

    #[test]
    fn test_stamps22_burn_pattern_detection() {
        // Test Stamps22 pattern (022222...)
        let stamps22_key = "022222222222222222222222222222222222222222222222222222222222222222";

        if let Some(pattern_type) = classify_stamps_burn(stamps22_key) {
            assert_eq!(pattern_type, BurnPatternType::Stamps22Pattern);
        } else {
            panic!("Failed to detect Stamps22 burn pattern");
        }
    }

    #[test]
    fn test_stamps33_burn_pattern_detection() {
        // Test Stamps33 pattern (033333...)
        let stamps33_key = "033333333333333333333333333333333333333333333333333333333333333333";

        if let Some(pattern_type) = classify_stamps_burn(stamps33_key) {
            assert_eq!(pattern_type, BurnPatternType::Stamps33Pattern);
        } else {
            panic!("Failed to detect Stamps33 burn pattern");
        }
    }

    #[test]
    fn test_stamps_alternating_patterns() {
        // Test alternating patterns
        let stamps_0202 = "020202020202020202020202020202020202020202020202020202020202020202";
        let stamps_0303 = "030303030303030303030303030303030303030303030303030303030303030303";

        if let Some(pattern_type) = classify_stamps_burn(stamps_0202) {
            assert_eq!(pattern_type, BurnPatternType::Stamps0202Pattern);
        } else {
            panic!("Failed to detect Stamps0202 burn pattern");
        }

        if let Some(pattern_type) = classify_stamps_burn(stamps_0303) {
            assert_eq!(pattern_type, BurnPatternType::Stamps0303Pattern);
        } else {
            panic!("Failed to detect Stamps0303 burn pattern");
        }
    }

    #[test]
    fn test_non_stamps_pattern_not_detected() {
        // Test that normal pubkeys are not detected as Stamps burn patterns
        let normal_key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

        assert!(
            classify_stamps_burn(normal_key).is_none(),
            "Normal pubkey should not be detected as Stamps burn pattern"
        );
    }
}

/// Edge case and validation tests
mod edge_cases {
    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_transfer_conflict() {
        run_stamps_fixture_test(&fixture_registry::stamps::TRANSFER_934DC3).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_stamps_malformed_src20() {
        run_stamps_fixture_test(&fixture_registry::stamps::MALFORMED_E2AA45).await;
    }
}

#[cfg(test)]
mod variant_classification {
    use data_carry_research::types::content_detection::ImageFormat;
    use data_carry_research::types::stamps::validation::{
        check_zlib_at_offsets, detect_stamps_variant_with_content,
    };
    use data_carry_research::types::stamps::StampsVariant;

    /// Helper function that mirrors real signature structure
    fn add_stamp_signature(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(b"stamp:"); // Use hardcoded "stamp:" signature
        result.extend_from_slice(data);
        result
    }

    #[test]
    fn test_html_variant_detection() {
        // Complete HTML with paired tags
        let html = b"<!DOCTYPE html><html><head><title>Snake</title></head><body><script>game();</script></body></html>";
        let with_signature = add_stamp_signature(html);
        let (variant, content_type, _) = detect_stamps_variant_with_content(&with_signature);
        assert_eq!(variant, Some(StampsVariant::HTML));
        assert_eq!(content_type, Some("text/html"));
    }

    #[test]
    fn test_html_json_false_positive() {
        // JSON containing HTML tags should remain JSON (SRC-20)
        let json = br#"{"p":"src-20","tick":"STAMP","html":"<script>alert('test')</script>"}"#;
        let with_signature = add_stamp_signature(json);
        let (variant, content_type, _) = detect_stamps_variant_with_content(&with_signature);
        assert_eq!(variant, Some(StampsVariant::SRC20));
        assert_eq!(content_type, Some("application/json"));
    }

    #[test]
    fn test_gzip_detection() {
        // GZIP with minimal deflate block
        let gzip_data = &[
            0x1F, 0x8B, 0x08, 0x00, // Magic + deflate
            0x00, 0x00, 0x00, 0x00, // Timestamp
            0x00, 0x03, // Extra flags + OS
            0x03, 0x00, // Minimal deflate block
        ];
        let with_signature = add_stamp_signature(gzip_data);
        let (variant, content_type, _) = detect_stamps_variant_with_content(&with_signature);
        assert_eq!(variant, Some(StampsVariant::Compressed));
        assert_eq!(content_type, Some("application/gzip"));
    }

    #[test]
    fn test_invalid_zlib_checksum() {
        // 0x78 0x9B fails checksum: (0x78 * 256 + 0x9B) % 31 = 29 (not 0)
        let invalid_zlib = &[0x78, 0x9B, 0x01, 0x02]; // Invalid header + data
        let with_signature = add_stamp_signature(invalid_zlib);
        let (variant, _, _) = detect_stamps_variant_with_content(&with_signature);
        assert_ne!(variant, Some(StampsVariant::Compressed));
    }

    #[test]
    fn test_compressed_zlib_offsets() {
        // Test offset 0
        let zlib_offset_0 = &[0x78, 0x9C, 0x03, 0x00]; // Valid header + data
        assert!(check_zlib_at_offsets(zlib_offset_0, &[0, 5, 7]));

        // Test offset 5
        let mut zlib_offset_5 = vec![0; 10];
        zlib_offset_5[5] = 0x78;
        zlib_offset_5[6] = 0x9C;
        assert!(check_zlib_at_offsets(&zlib_offset_5, &[0, 5, 7]));

        // Test offset 7
        let mut zlib_offset_7 = vec![0; 12];
        zlib_offset_7[7] = 0x78;
        zlib_offset_7[8] = 0x9C;
        assert!(check_zlib_at_offsets(&zlib_offset_7, &[0, 5, 7]));
    }

    #[test]
    fn test_svg_is_classic() {
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><circle cx=\"50\" cy=\"50\" r=\"40\"/></svg>";
        let with_signature = add_stamp_signature(svg);
        let (variant, content_type, image_format) =
            detect_stamps_variant_with_content(&with_signature);
        assert_eq!(variant, Some(StampsVariant::Classic));
        assert_eq!(content_type, Some("image/svg+xml"));
        assert_eq!(image_format, Some(ImageFormat::Svg));
    }

    #[test]
    fn test_compression_priority() {
        // Compressed JSON should be Compressed, not SRC20
        let compressed_json = &[
            0x78, 0x9C, // ZLIB header
            0x03, 0x00, 0x00, 0x00, // Minimal compressed data
        ];
        let with_signature = add_stamp_signature(compressed_json);
        let (variant, content_type, _) = detect_stamps_variant_with_content(&with_signature);
        assert_eq!(variant, Some(StampsVariant::Compressed));
        assert_eq!(content_type, Some("application/zlib"));
    }

    #[test]
    fn test_truncated_payload_safety() {
        // Test that truncated payloads don't panic
        let truncated = b"stamp:"; // Signature only, no data
        let (variant, _, _) = detect_stamps_variant_with_content(truncated);
        assert_eq!(variant, Some(StampsVariant::Unknown));

        // Short payload - per consolidation plan, ANY non-empty data becomes Data
        let short = b"stamp:\x00\x10"; // 2 bytes of data (even if nonsensical)
        let (variant, content_type, _) = detect_stamps_variant_with_content(short);
        assert_eq!(variant, Some(StampsVariant::Data));
        assert_eq!(content_type, Some("application/octet-stream"));
    }

    /// Regression test for issue where Counterparty-embedded stamps were misclassified.
    ///
    /// Bug: Latin-1 to UTF-8 conversion was missing for Counterparty-embedded stamps,
    /// causing base64 decode to fail and stamps to be classified as Data instead of
    /// their actual type (SRC20, Classic, etc.).
    ///
    /// Fixed in: extract_stamps_payload() with proper Latin-1 conversion for offset > 2
    #[test]
    fn test_counterparty_embedded_src20_regression() {
        use base64::{engine::general_purpose, Engine};

        // Simulate Counterparty-embedded format: [CNTRPRTY prefix][stamp:][base64 SRC-20]
        // Stamp signature at offset > 2 indicates Counterparty transport
        let src20_json = r#"{"p":"src-20","op":"transfer","tick":"STEVE","amt":"100000000"}"#;
        let base64_data = general_purpose::STANDARD.encode(src20_json.as_bytes());

        // Counterparty-embedded: 8 bytes CNTRPRTY + 4 bytes message type + stamp:base64
        let mut counterparty_embedded: Vec<u8> = Vec::new();
        counterparty_embedded.extend_from_slice(b"CNTRPRTY"); // 8 bytes - Counterparty prefix
        counterparty_embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x1F]); // 4 bytes - message type
        counterparty_embedded.extend_from_slice(b"stamp:"); // 6 bytes - stamp signature
        counterparty_embedded.extend_from_slice(base64_data.as_bytes()); // base64 SRC-20

        // Stamp signature should be found at offset 12 (8 + 4)
        let (variant, content_type, _) = detect_stamps_variant_with_content(&counterparty_embedded);

        // Should detect SRC-20, NOT Data
        assert_eq!(
            variant,
            Some(StampsVariant::SRC20),
            "Counterparty-embedded SRC-20 should be detected as SRC20, not {:?}",
            variant
        );
        assert_eq!(
            content_type,
            Some("application/json"),
            "SRC-20 should have application/json content type"
        );
    }

    /// Test that Pure stamps (offset 0) still work correctly
    #[test]
    fn test_pure_stamps_offset_0_src20() {
        use base64::{engine::general_purpose, Engine};

        let src20_json = r#"{"p":"src-20","op":"mint","tick":"TEST","amt":"1000"}"#;
        let base64_data = general_purpose::STANDARD.encode(src20_json.as_bytes());

        // Pure stamps at offset 0: [stamp:][base64]
        let mut pure_stamps: Vec<u8> = Vec::new();
        pure_stamps.extend_from_slice(b"stamp:");
        pure_stamps.extend_from_slice(base64_data.as_bytes());

        let (variant, content_type, _) = detect_stamps_variant_with_content(&pure_stamps);

        assert_eq!(variant, Some(StampsVariant::SRC20));
        assert_eq!(content_type, Some("application/json"));
    }

    /// Test that SRC-20 with hyphenless "src20" protocol field is detected
    /// (This was another bug found during investigation)
    #[test]
    fn test_src20_without_hyphen() {
        use base64::{engine::general_purpose, Engine};

        // Some stamps use "src20" instead of "src-20"
        let src20_json = r#"{"p":"src20","op":"mint","tick":"KAREN","amt":"100000"}"#;
        let base64_data = general_purpose::STANDARD.encode(src20_json.as_bytes());

        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(b"stamp:");
        payload.extend_from_slice(base64_data.as_bytes());

        let (variant, content_type, _) = detect_stamps_variant_with_content(&payload);

        // Should still detect as SRC20 even without hyphen
        assert_eq!(
            variant,
            Some(StampsVariant::SRC20),
            "SRC-20 with 'src20' (no hyphen) should be detected as SRC20"
        );
        assert_eq!(content_type, Some("application/json"));
    }

    /// Regression test for Counterparty-embedded stamps with data URI prefix.
    ///
    /// Bug: When Counterparty-embedded stamps contained data URI prefixes like
    /// "data:image/png;base64,", the prefix was NOT stripped before base64 character
    /// filtering, causing "dataimagepngbase64" to be prepended to the actual data.
    ///
    /// Fixed in: extract_stamps_payload() now calls strip_data_uri_prefix_str()
    /// BEFORE base64 character filtering for Counterparty-embedded stamps.
    #[test]
    fn test_counterparty_embedded_with_data_uri_prefix() {
        use base64::{engine::general_purpose, Engine};

        // Create actual PNG data (minimal valid header)
        let png_header = [
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
            b'I', b'H', b'D', b'R', // IHDR chunk type
            0x00, 0x00, 0x00, 0x01, // Width: 1
            0x00, 0x00, 0x00, 0x01, // Height: 1
            0x08, 0x02, // Bit depth 8, RGB
            0x00, 0x00, 0x00, // Compression, filter, interlace
            0x90, 0x77, 0x53, 0xDE, // CRC
        ];
        let base64_png = general_purpose::STANDARD.encode(png_header);

        // Counterparty-embedded with data URI prefix
        // Format: [CNTRPRTY][msg_type][stamp:data:image/png;base64,<base64_data>]
        let mut counterparty_embedded: Vec<u8> = Vec::new();
        counterparty_embedded.extend_from_slice(b"CNTRPRTY");
        counterparty_embedded.extend_from_slice(&[0x00, 0x00, 0x00, 0x1F]); // Message type
        counterparty_embedded.extend_from_slice(b"stamp:");
        counterparty_embedded.extend_from_slice(b"data:image/png;base64,");
        counterparty_embedded.extend_from_slice(base64_png.as_bytes());

        let (variant, content_type, image_format) =
            detect_stamps_variant_with_content(&counterparty_embedded);

        // Should detect as Classic (PNG image), NOT Data
        assert_eq!(
            variant,
            Some(StampsVariant::Classic),
            "Counterparty-embedded PNG with data URI prefix should be Classic, not {:?}",
            variant
        );
        assert_eq!(
            content_type,
            Some("image/png"),
            "PNG should have image/png content type"
        );
        assert_eq!(
            image_format,
            Some(ImageFormat::Png),
            "Should detect PNG image format"
        );
    }
}
