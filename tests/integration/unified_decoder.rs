/// Unified tests for the decode-txid command
///
/// Tests both Bitcoin Stamps and Counterparty protocol decoding using real Bitcoin transactions.
/// These tests require a running Bitcoin Core node with txindex=1.
///
/// ## Important Note on Bitcoin Stamps Test Coverage
///
/// **P2MS Encoding Requirement**: The decoder specifically detects P2MS (Pay-to-Multisig) outputs.
/// Bitcoin Stamps that use SegWit encoding (witness_v0_keyhash, witness_v0_scripthash) cannot be
/// detected by the current implementation.
///
/// - `572be558f1260117c134c1d4a770a443a713c778c4afdfe4139a8da15cb5d5ef` (SegWit)
/// - `8730c7f8940706be7de6c28466b348703c8ddd48bf9a409a483265b7ded07d8e` (SegWit)
///
/// These transactions exist in test data but cannot be tested with the current P2MS-focused decoder.
// Integration tests access common module through the parent path
use crate::common::rpc_helpers::create_test_rpc_config;
use data_carry_research::decoder::ProtocolDecoder;
use data_carry_research::decoder::{BitcoinStampsData, DecodedData};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tempfile::TempDir;
use tokio;

/// Test configuration - requires running Bitcoin Core
// RPC configuration now imported from common::rpc_helpers

/// Bitcoin Stamps test TXIDs - Images
const BITCOIN_STAMPS_IMAGE_TXID: &str =
    "54fdeda90c4573f8a93fa45251a3c6214bcc79aa8549728dfb08ffe3e7dd3d81";
const STAMPS_ORIGINAL_IMAGE_TXID: &str =
    "3368bd06d79cc3a66a01d55cf81112e92affcb64022d7f1c78fafcad824ea426";
const STAMPS_CLASSIC_4D89D7_TXID: &str =
    "4d89d7f69ee77c3ddda041f94270b4112d002fc67b88008f29710fadfb486da8";
const STAMPS_CLASSIC_F35382_TXID: &str =
    "f353823cdc63ee24fe2167ca14d3bb9b6a54dd063b53382c0cd42f05d7262808";
const STAMPS_RECENT_C8C383_TXID: &str =
    "c8c3831f6354831f1f14ee8f979c2b114d883c85653aae1c2d286ad351dfc30c";
const STAMPS_IMAGE_359AEF_TXID: &str =
    "359aefd7bf0bbd8398ee5c8c0f206799b78b158578f0f98e1e06bf58e70008dc";
const STAMPS_IMAGE_50AEB7_TXID: &str =
    "50aeb77245a9483a5b077e4e7506c331dc2f628c22046e7d2b4c6ad6c6236ae1";
const STAMPS_IMAGE_582A46_TXID: &str =
    "582a46f2077fe53ec3d1b7cb49c9f962294d6dc261256413ba5968190f171a3f";
const STAMPS_IMAGE_5E7D66_TXID: &str =
    "5e7d66b0b1d3bc28d8ed9211262592d44b601f148686a93cc372fc7e5a3bab71";
const STAMPS_IMAGE_C129CC_TXID: &str =
    "c129cc8f13760fce63a42257dbe5dcdd0aad798f858f6b08968c7834c7a1bcc7";

/// Bitcoin Stamps test TXIDs - SRC-20
const BITCOIN_STAMPS_SRC20_TXID: &str =
    "eb96a65e4a332f2c84cb847268f614c037e038d2c386eb08d49271966c1b0000";

/// Bitcoin Stamps test TXIDs - SRC-101
const BITCOIN_STAMPS_SRC101_TXID: &str =
    "77fb147b72a551cf1e2f0b37dccf9982a1c25623a7fe8b4d5efaac566cf63fed";

/// Bitcoin Stamps test TXIDs - Special cases
const STAMPS_MULTI_OUTPUT_TXID: &str =
    "95dca4dc27e50e7b26174a0ded7af3b26527def625670d058ae09200eeb3d735";

/// Working Counterparty test TXIDs
const COUNTERPARTY_ISSUANCE_TXID: &str =
    "e5e9f6a63ede5315994cf2d8a5f8fe760f1f37f6261e5fbb1263bed54114768a";
const COUNTERPARTY_SEND_TXID: &str =
    "da3ed1efda82824cb24ea081ef2a8f532a7dd9cd1ebc5efa873498c3958c864e";
const COUNTERPARTY_BROADCAST_TXID: &str =
    "21c2cd5b369c2e7a350bf92ad43c31e5abb0aa85ccba11368b08f9f4abb8e0af";
const COUNTERPARTY_OLGA_LOCK_TXID: &str =
    "34da6ecf10c66ed659054aa6c71900c807875cb57b96abea4cee4f7a831ed690";
const COUNTERPARTY_SALVATION_TXID: &str =
    "541e640fbb527c35e0ee32d724efa4a5506c4c52acfba1ebc3b45949780c08a8";
const COUNTERPARTY_TYPE0_TXID: &str =
    "585f50f12288cd9044705483672fbbddb71dff8198b390b40ab3de30db0a88dd";
const COUNTERPARTY_TYPE30_TXID: &str =
    "627ae48d6b4cffb2ea734be1016dedef4cee3f8ffefaea5602dd58c696de6b74";

/// Additional Counterparty test TXIDs
const COUNTERPARTY_SUBASSET_TXID: &str =
    "793566ef1644a14c2658aed6b3c2df41bc519941f121f9cff82825f48911e451";
const COUNTERPARTY_MODERN_1OF3_TXID: &str =
    "a63ee2b1e64d98784ba39c9e6738bc923fd88a808d618dd833254978247d66ea";

/// Bitcoin Stamps with Counterparty transport (Type 20 issuance with STAMP: signature)
const STAMPS_COUNTERPARTY_TRANSPORT_TXID: &str =
    "31a96a3bd86600b4af3c81bc960b15e89e506f855e93fbbda6f701963b1936ac";

/// DataStorage test TXIDs - Bitcoin Whitepaper (embedded PDF)
const DATASTORAGE_BITCOIN_WHITEPAPER_TXID: &str =
    "54e48e5f5c656b26c3bca14a8c95aa583d07ebe84dde3b7dd4a78f4e4186e713";

/// Omni Layer test TXIDs
const OMNI_MULTI_PACKET_TXID: &str =
    "153091863886921ab8bf6a7cc17ea99610795522f48b1824d2e417954e466281";
const OMNI_PROPERTY_FIXED_TXID: &str =
    "725ba706446baa48a2416ab2ffc229c56600d59f31b782ac6c5c82868e1ad97f";
const OMNI_VARIABLE_PROPERTY_TXID: &str =
    "b01d1594a7e2083ebcd428706045df003f290c4dc7bd6d77c93df9fcca68232f";
const OMNI_MANUAL_PROPERTY_TXID: &str =
    "73914fb386c19f09181ac01cb3680eaee01268ef0781dff9f25d5c069b5334f0";
const OMNI_SEND_TO_OWNERS_TXID: &str =
    "0937f162eda99e5aeeab550b26ea7cdd1322a3281fe1721b6ae9c8eb0eab374d";
const OMNI_GRANT_TOKENS_TXID: &str =
    "1caf0432ef165b19d5b5d726dc7fd1461390283c15bade2c9683fd712099e53b";
const OMNI_REVOKE_TOKENS_TXID: &str =
    "7429731487105e72ab915a77e677a59d08e6be43b4e8daab58906058382ffbce";
const OMNI_DEX_OFFER_TXID: &str =
    "9a017721f168c0a733d7a8495ffbab102c5c56ac3907f57382dc10a18357b004";
const OMNI_DEX_ACCEPT_TXID: &str =
    "3d7742608f3df0436c7d482465b092344c083105fb4d8f5f7745494074ec1d3b";
const OMNI_CROWDSALE_CREATION_TXID: &str =
    "eda3d2bbb8125397f4d4909ea25d845dc451e8a3206035bf0d736bb3ece5d758";
const OMNI_CROWDSALE_PARTICIPATION_TXID: &str =
    "c1ff92f278432d6e14e08ab60f2dceab4d8b4396b4d7e62b5b10e88e840b39d4";
const OMNI_CLOSE_CROWDSALE_TXID: &str =
    "b8864525a2eef4f76a58f33a4af50dc24461445e1a420e21bcc99a1901740e79";

/// Helper to create RPC config
// RPC config creation now uses common::rpc_helpers::create_test_rpc_config()

/// Helper to create decoder with temp directory
async fn create_test_decoder() -> anyhow::Result<(ProtocolDecoder, TempDir)> {
    let temp_dir = TempDir::new()?;
    let output_dir = temp_dir.path().to_path_buf();
    let rpc_config = create_test_rpc_config();

    let decoder = ProtocolDecoder::new(rpc_config, output_dir).await?;
    Ok((decoder, temp_dir))
}

/// Helper to create decoder with project directory (for manual verification)
async fn create_test_decoder_with_project_dir() -> anyhow::Result<ProtocolDecoder> {
    let output_dir = std::path::PathBuf::from("output_data");
    let rpc_config = create_test_rpc_config();

    let decoder = ProtocolDecoder::new(rpc_config, output_dir).await?;
    Ok(decoder)
}

/// Helper to skip test if RPC not available
fn skip_if_rpc_unavailable(e: anyhow::Error, test_name: &str) {
    eprintln!(
        "⚠️  Skipping {} - Bitcoin RPC not available: {}",
        test_name, e
    );
}

// =============================================================================
// BITCOIN STAMPS TESTS
// =============================================================================

#[tokio::test]
async fn test_decode_bitcoin_stamps_image_54fdeda9() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_bitcoin_stamps_image_54fdeda9");
            return Ok(());
        }
    };

    println!("🔍 Testing Bitcoin Stamps image decoding");
    println!("Transaction: {}", BITCOIN_STAMPS_IMAGE_TXID);

    let result = decoder.decode_txid(BITCOIN_STAMPS_IMAGE_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Image(decoded_image),
            ..
        }) => {
            println!("✅ Successfully decoded image:");
            println!("   Format: {:?}", decoded_image.format);
            println!("   Size: {} bytes", decoded_image.size_bytes);
            println!("   File: {:?}", decoded_image.file_path);

            // Validate the decoded image
            assert_eq!(decoded_image.txid, BITCOIN_STAMPS_IMAGE_TXID);
            assert!(
                decoded_image.size_bytes > 0,
                "Image should have non-zero size"
            );
            assert!(decoded_image.file_path.exists(), "Image file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
            assert!(
                decoded_image.file_path.starts_with(&expected_dir),
                "Image should be in bitcoin_stamps/images directory"
            );

            println!("✅ Image validation passed");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Json(_),
            ..
        }) => {
            panic!("❌ Expected image data, got JSON");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Html(_),
            ..
        }) => {
            panic!("❌ Expected image data, got HTML");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Compressed(_),
            ..
        }) => {
            panic!("❌ Expected image data, got compressed data");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Data(_),
            ..
        }) => {
            panic!("❌ Expected image data, got generic data");
        }
        Some(DecodedData::Counterparty { .. }) => {
            panic!("❌ Expected Bitcoin Stamps image data, got Counterparty");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_bitcoin_stamps_src101_77fb147b() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_bitcoin_stamps_src101_77fb147b");
            return Ok(());
        }
    };

    println!("🔍 Testing Bitcoin Stamps JSON decoding (SRC-101)");
    println!("Transaction: {}", BITCOIN_STAMPS_SRC101_TXID);

    let result = decoder.decode_txid(BITCOIN_STAMPS_SRC101_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Json(decoded_json),
            ..
        }) => {
            println!("✅ Successfully decoded JSON:");
            println!("   Type: {:?}", decoded_json.json_type);
            println!("   Size: {} bytes", decoded_json.size_bytes);
            println!("   File: {:?}", decoded_json.file_path);

            // Validate the decoded JSON
            assert_eq!(decoded_json.txid, BITCOIN_STAMPS_SRC101_TXID);
            assert!(
                decoded_json.size_bytes > 0,
                "JSON should have non-zero size"
            );
            assert!(decoded_json.file_path.exists(), "JSON file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
            assert!(
                decoded_json.file_path.starts_with(&expected_dir),
                "JSON should be in bitcoin_stamps/json directory"
            );

            // Validate JSON content structure
            let json_obj = decoded_json
                .parsed_data
                .as_object()
                .expect("JSON should be an object");

            assert_eq!(
                json_obj.get("p").and_then(|v| v.as_str()),
                Some("src-101"),
                "Should be SRC-101 protocol"
            );
            assert_eq!(
                json_obj.get("op").and_then(|v| v.as_str()),
                Some("deploy"),
                "Should be deploy operation"
            );
            assert!(json_obj.contains_key("name"), "Should have name field");

            println!("✅ JSON validation passed");
            println!("   Protocol: {}", json_obj.get("p").unwrap());
            println!("   Operation: {}", json_obj.get("op").unwrap());
            if let Some(name) = json_obj.get("name") {
                println!("   Name: {}", name);
            }
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Image(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got Image");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Html(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got HTML");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Compressed(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got compressed data");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Data(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got generic data");
        }
        Some(DecodedData::Counterparty { .. }) => {
            panic!("❌ Expected Bitcoin Stamps JSON data, got Counterparty");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_bitcoin_stamps_src20_eb96a65e() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_bitcoin_stamps_src20_eb96a65e");
            return Ok(());
        }
    };

    println!("🔍 Testing Bitcoin Stamps JSON decoding (SRC-20)");
    println!("Transaction: {}", BITCOIN_STAMPS_SRC20_TXID);

    let result = decoder.decode_txid(BITCOIN_STAMPS_SRC20_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Json(decoded_json),
            ..
        }) => {
            println!("✅ Successfully decoded JSON:");
            println!("   Type: {:?}", decoded_json.json_type);
            println!("   Size: {} bytes", decoded_json.size_bytes);
            println!("   File: {:?}", decoded_json.file_path);

            // Validate the decoded JSON
            assert_eq!(decoded_json.txid, BITCOIN_STAMPS_SRC20_TXID);
            assert!(
                decoded_json.size_bytes > 0,
                "JSON should have non-zero size"
            );
            assert!(decoded_json.file_path.exists(), "JSON file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
            assert!(
                decoded_json.file_path.starts_with(&expected_dir),
                "JSON should be in bitcoin_stamps/json directory"
            );

            // Validate JSON content structure for SRC-20
            let json_obj = decoded_json
                .parsed_data
                .as_object()
                .expect("JSON should be an object");

            assert_eq!(
                json_obj.get("p").and_then(|v| v.as_str()),
                Some("src-20"),
                "Should be SRC-20 protocol"
            );
            assert_eq!(
                json_obj.get("op").and_then(|v| v.as_str()),
                Some("transfer"),
                "Should be transfer operation"
            );
            assert!(json_obj.contains_key("tick"), "Should have tick field");
            assert!(json_obj.contains_key("amt"), "Should have amt field");

            println!("✅ JSON validation passed");
            println!("   Protocol: {}", json_obj.get("p").unwrap());
            println!("   Operation: {}", json_obj.get("op").unwrap());
            if let Some(tick) = json_obj.get("tick") {
                println!("   Tick: {}", tick);
            }
            if let Some(amt) = json_obj.get("amt") {
                println!("   Amount: {}", amt);
            }
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Image(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got Image");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Html(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got HTML");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Compressed(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got compressed data");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Data(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got generic data");
        }
        Some(DecodedData::Counterparty { .. }) => {
            panic!("❌ Expected Bitcoin Stamps JSON data, got Counterparty");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_bitcoin_stamps_image_c129cc() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_bitcoin_stamps_image_c129cc");
            return Ok(());
        }
    };

    println!(
        "🔍 Testing Bitcoin Stamps SRC-20 JSON decoding (Counterparty-embedded, missing padding)"
    );
    println!("Transaction: {}", STAMPS_IMAGE_C129CC_TXID);

    let result = decoder.decode_txid(STAMPS_IMAGE_C129CC_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Json(decoded_json),
            ..
        }) => {
            println!("✅ Successfully decoded JSON:");
            println!("   Type: {:?}", decoded_json.json_type);
            println!("   Size: {} bytes", decoded_json.size_bytes);
            println!("   File: {:?}", decoded_json.file_path);

            // Validate the decoded JSON
            assert_eq!(decoded_json.txid, STAMPS_IMAGE_C129CC_TXID);
            assert!(
                decoded_json.size_bytes > 0,
                "JSON should have non-zero size"
            );
            assert!(decoded_json.file_path.exists(), "JSON file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
            assert!(
                decoded_json.file_path.starts_with(&expected_dir),
                "JSON should be in bitcoin_stamps/json directory"
            );

            // Validate JSON content structure for SRC-20
            let json_obj = decoded_json
                .parsed_data
                .as_object()
                .expect("JSON should be an object");

            assert_eq!(
                json_obj.get("p").and_then(|v| v.as_str()),
                Some("src-20"),
                "Should be SRC-20 protocol"
            );
            assert_eq!(
                json_obj.get("op").and_then(|v| v.as_str()),
                Some("mint"),
                "Should be mint operation"
            );
            assert_eq!(
                json_obj.get("tick").and_then(|v| v.as_str()),
                Some("PIZZA"),
                "Should be PIZZA tick"
            );
            assert_eq!(
                json_obj.get("amt").and_then(|v| v.as_str()),
                Some("11111"),
                "Should be amount 11111"
            );

            println!("✅ JSON validation passed");
            println!("   Protocol: {}", json_obj.get("p").unwrap());
            println!("   Operation: {}", json_obj.get("op").unwrap());
            println!("   Tick: {}", json_obj.get("tick").unwrap());
            println!("   Amount: {}", json_obj.get("amt").unwrap());
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Image(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got Image");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Html(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got HTML");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Compressed(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got compressed data");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Data(_),
            ..
        }) => {
            panic!("❌ Expected JSON data, got generic data");
        }
        Some(DecodedData::Counterparty { .. }) => {
            panic!("❌ Expected Bitcoin Stamps JSON data, got Counterparty");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_bitcoin_stamps_multi_output_95dca4() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_bitcoin_stamps_multi_output_95dca4");
            return Ok(());
        }
    };

    println!(
        "🔍 Testing Bitcoin Stamps HTML content decoding (multi-output, Counterparty-embedded)"
    );
    println!("Transaction: {}", STAMPS_MULTI_OUTPUT_TXID);

    let result = decoder.decode_txid(STAMPS_MULTI_OUTPUT_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Html(decoded_html),
            ..
        }) => {
            println!("✅ Successfully decoded HTML data:");
            println!("   Size: {} bytes", decoded_html.size_bytes);
            println!("   HTML file: {:?}", decoded_html.file_path);

            // Validate the HTML data
            assert_eq!(decoded_html.txid, STAMPS_MULTI_OUTPUT_TXID);
            assert!(
                decoded_html.size_bytes > 0,
                "HTML data should have non-zero size"
            );
            assert!(
                decoded_html.file_path.exists(),
                "HTML file should exist"
            );

            // Check that HTML file is in the correct directory
            let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
            assert!(
                decoded_html.file_path.starts_with(&expected_dir),
                "HTML file should be in bitcoin_stamps/html directory"
            );

            // Validate HTML file extension
            assert!(
                decoded_html.file_path.extension().map_or(false, |e| e == "html"),
                "File should have .html extension"
            );

            // Read and validate HTML content
            let html_content = std::fs::read_to_string(&decoded_html.file_path)?;
            assert!(html_content.contains("<html"), "Should contain HTML tag");
            assert!(
                html_content.contains("background"),
                "Should contain background style"
            );
            assert_eq!(
                html_content.len(),
                decoded_html.size_bytes,
                "File size should match size_bytes"
            );

            println!("✅ HTML validation passed");
            println!("   HTML file: {:?}", decoded_html.file_path);
            println!("   HTML size: {} bytes", html_content.len());
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Image(_),
            ..
        }) => {
            panic!("❌ Expected HTML data, got Image");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Json(_),
            ..
        }) => {
            panic!("❌ Expected HTML data, got JSON");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Compressed(_),
            ..
        }) => {
            panic!("❌ Expected HTML data, got compressed data");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Data(decoded_data),
            ..
        }) => {
            // Debug: print what we got instead
            let content_preview = if decoded_data.bytes.len() > 200 {
                String::from_utf8_lossy(&decoded_data.bytes[..200]).to_string()
            } else {
                String::from_utf8_lossy(&decoded_data.bytes).to_string()
            };
            panic!(
                "❌ Expected HTML data, got Data variant\n   Content-type: {}\n   Size: {} bytes\n   Preview: {}...",
                decoded_data.content_type,
                decoded_data.size_bytes,
                content_preview
            );
        }
        Some(DecodedData::Counterparty { .. }) => {
            panic!("❌ Expected Bitcoin Stamps data, got Counterparty");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

// =============================================================================
// WORKING COUNTERPARTY TESTS
// =============================================================================

#[tokio::test]
async fn test_decode_counterparty_issuance_e5e9f6a6() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_issuance_e5e9f6a6");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty issuance decoding");
    println!("Transaction: {}", COUNTERPARTY_ISSUANCE_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_ISSUANCE_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { data }) => {
            println!("✅ Successfully decoded Counterparty data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            // Validate the decoded data
            assert_eq!(data.txid, COUNTERPARTY_ISSUANCE_TXID);
            assert!(data.file_path.exists(), "Counterparty file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("counterparty");
            assert!(
                data.file_path.starts_with(&expected_dir),
                "Counterparty data should be in counterparty directory"
            );

            println!("✅ Counterparty validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected Counterparty data, got Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_counterparty_send_da3ed1ef() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_send_da3ed1ef");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty send decoding");
    println!("Transaction: {}", COUNTERPARTY_SEND_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_SEND_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { data }) => {
            println!("✅ Successfully decoded Counterparty data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            // Validate the decoded data
            assert_eq!(data.txid, COUNTERPARTY_SEND_TXID);
            assert!(data.file_path.exists(), "Counterparty file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("counterparty");
            assert!(
                data.file_path.starts_with(&expected_dir),
                "Counterparty data should be in counterparty directory"
            );

            println!("✅ Counterparty validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected Counterparty data, got Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_counterparty_broadcast_21c2cd5b() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_broadcast_21c2cd5b");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty broadcast decoding");
    println!("Transaction: {}", COUNTERPARTY_BROADCAST_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_BROADCAST_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { data }) => {
            println!("✅ Successfully decoded Counterparty data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            // Validate the decoded data
            assert_eq!(data.txid, COUNTERPARTY_BROADCAST_TXID);
            assert!(data.file_path.exists(), "Counterparty file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("counterparty");
            assert!(
                data.file_path.starts_with(&expected_dir),
                "Counterparty data should be in counterparty directory"
            );

            println!("✅ Counterparty validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected Counterparty data, got Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_counterparty_olga_lock_34da6ecf() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_olga_lock_34da6ecf");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty olga lock decoding");
    println!("Transaction: {}", COUNTERPARTY_OLGA_LOCK_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_OLGA_LOCK_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { data }) => {
            println!("✅ Successfully decoded Counterparty data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            // Validate the decoded data
            assert_eq!(data.txid, COUNTERPARTY_OLGA_LOCK_TXID);
            assert!(data.file_path.exists(), "Counterparty file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("counterparty");
            assert!(
                data.file_path.starts_with(&expected_dir),
                "Counterparty data should be in counterparty directory"
            );

            println!("✅ Counterparty validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected Counterparty data, got Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_counterparty_salvation_541e640f() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_salvation_541e640f");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty salvation decoding");
    println!("Transaction: {}", COUNTERPARTY_SALVATION_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_SALVATION_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { data }) => {
            println!("✅ Successfully decoded Counterparty data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            // Validate the decoded data
            assert_eq!(data.txid, COUNTERPARTY_SALVATION_TXID);
            assert!(data.file_path.exists(), "Counterparty file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("counterparty");
            assert!(
                data.file_path.starts_with(&expected_dir),
                "Counterparty data should be in counterparty directory"
            );

            println!("✅ Counterparty validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected Counterparty data, got Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_counterparty_type0_585f50f1() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_type0_585f50f1");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty type0 decoding");
    println!("Transaction: {}", COUNTERPARTY_TYPE0_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_TYPE0_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { data }) => {
            println!("✅ Successfully decoded Counterparty data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            // Validate the decoded data
            assert_eq!(data.txid, COUNTERPARTY_TYPE0_TXID);
            assert!(data.file_path.exists(), "Counterparty file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("counterparty");
            assert!(
                data.file_path.starts_with(&expected_dir),
                "Counterparty data should be in counterparty directory"
            );

            println!("✅ Counterparty validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected Counterparty data, got Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_counterparty_type30_627ae48d() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_type30_627ae48d");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty type30 decoding");
    println!("Transaction: {}", COUNTERPARTY_TYPE30_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_TYPE30_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { data }) => {
            println!("✅ Successfully decoded Counterparty data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            // Validate the decoded data
            assert_eq!(data.txid, COUNTERPARTY_TYPE30_TXID);
            assert!(data.file_path.exists(), "Counterparty file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("counterparty");
            assert!(
                data.file_path.starts_with(&expected_dir),
                "Counterparty data should be in counterparty directory"
            );

            println!("✅ Counterparty validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected Counterparty data, got Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Unexpected Omni Layer data");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_counterparty_subasset_793566ef() -> anyhow::Result<()> {
    let (decoder, _temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_subasset_793566ef");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty subasset issuance");
    println!("Transaction: {}", COUNTERPARTY_SUBASSET_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_SUBASSET_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { .. }) => {
            println!("✅ Successfully decoded as Counterparty (subasset issuance)");
            println!("✅ Counterparty subasset validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ This is Counterparty, not Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ This is Counterparty, not Omni Layer");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_counterparty_transport_31a96a3b() -> anyhow::Result<()> {
    let decoder = match create_test_decoder_with_project_dir().await {
        Ok(decoder) => decoder,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_counterparty_transport_31a96a3b");
            return Ok(());
        }
    };

    println!("🔍 Testing Bitcoin Stamps with Counterparty transport (Type 20 issuance)");
    println!("Transaction: {}", STAMPS_COUNTERPARTY_TRANSPORT_TXID);
    println!("Note: This transaction has STAMP: signature in Counterparty issuance description");

    let result = decoder
        .decode_txid(STAMPS_COUNTERPARTY_TRANSPORT_TXID)
        .await?;

    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Image(decoded_image),
            ..
        }) => {
            println!("✅ Successfully decoded as Bitcoin Stamps (Counterparty-embedded)");
            println!("   Format: {:?}", decoded_image.format);
            println!("   Size: {} bytes", decoded_image.size_bytes);
            println!("   File: {:?}", decoded_image.file_path);

            // Verify the image matches the reference
            let reference_path = "tests/test_data/stamps/decoded_data/31a96a3bd86600b4af3c81bc960b15e89e506f855e93fbbda6f701963b1936ac_test.png";
            let reference_bytes = std::fs::read(reference_path)?;

            assert_eq!(decoded_image.size_bytes, 1921, "Image should be 1921 bytes");
            assert_eq!(
                decoded_image.size_bytes,
                reference_bytes.len(),
                "Decoded image size should match reference"
            );
            assert_eq!(
                decoded_image.bytes, reference_bytes,
                "Decoded image bytes should match reference"
            );

            println!(
                "✅ Counterparty transport validation passed - STAMP: signature correctly detected"
            );
            println!("✅ Decoded image matches reference perfectly!");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Json(_),
            ..
        }) => {
            panic!("❌ Expected image data, got JSON");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Html(_),
            ..
        }) => {
            panic!("❌ Expected image data, got HTML");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Compressed(_),
            ..
        }) => {
            panic!("❌ Expected image data, got compressed data");
        }
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Data(_),
            ..
        }) => {
            panic!("❌ Expected image data, got generic data");
        }
        Some(DecodedData::Counterparty { .. }) => {
            panic!("❌ This should be Bitcoin Stamps - has 'STAMP:' in description field");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ This should be Bitcoin Stamps, not Omni Layer");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_counterparty_modern_1of3_a63ee2b1() -> anyhow::Result<()> {
    let (decoder, _temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_counterparty_modern_1of3_a63ee2b1");
            return Ok(());
        }
    };

    println!("🔍 Testing Counterparty modern 1-of-3 format");
    println!("Transaction: {}", COUNTERPARTY_MODERN_1OF3_TXID);

    let result = decoder.decode_txid(COUNTERPARTY_MODERN_1OF3_TXID).await?;

    match result {
        Some(DecodedData::Counterparty { .. }) => {
            println!("✅ Successfully decoded as Counterparty (modern 1-of-3 format)");
            println!("✅ Counterparty validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ This is Counterparty, not Bitcoin Stamps");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ This is Counterparty, not Omni Layer");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Unexpected Chancecoin data");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Unexpected DataStorage data");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

// =============================================================================
// ERROR HANDLING TESTS
// =============================================================================

#[tokio::test]
async fn test_decode_nonexistent_transaction() -> anyhow::Result<()> {
    let (decoder, _temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_nonexistent_transaction");
            return Ok(());
        }
    };

    println!("🔍 Testing non-existent transaction handling");

    // Use a properly formatted but non-existent TXID
    let fake_txid = "70dc5fcda12e7b1e1ce8b50addf8894e82cdf3e36e6a5fe18b5e67b9c0a45f35";

    let result = decoder.decode_txid(fake_txid).await;

    // Should return an error for non-existent transaction
    match result {
        Err(e) => {
            println!(
                "✅ Correctly returned error for non-existent transaction: {}",
                e
            );
            println!("✅ Non-existent transaction handling works correctly");
        }
        Ok(Some(data)) => {
            panic!(
                "❌ Should not decode non-existent transaction, got: {:?}",
                data
            );
        }
        Ok(None) => {
            // Also acceptable - transaction not found returns None
            println!("✅ Correctly returned None for non-existent transaction");
            println!("✅ Non-existent transaction handling works correctly");
        }
    }

    Ok(())
}
// =============================================================================
// OMNI LAYER TESTS
// =============================================================================

#[tokio::test]
async fn test_decode_omni_multi_packet_153091() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_multi_packet_153091");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer multi-packet decoding (CreatePropertyFixed)");
    println!("Transaction: {}", OMNI_MULTI_PACKET_TXID);

    let result = decoder.decode_txid(OMNI_MULTI_PACKET_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   Size: {} bytes", data.deobfuscated_payload.len());
            println!("   File: {:?}", data.file_path);

            // Validate the decoded data
            assert_eq!(data.txid, OMNI_MULTI_PACKET_TXID);
            assert_eq!(data.packet_count, 11, "Should have 11 packets");
            assert!(data.file_path.exists(), "Omni file should exist");

            // Check that it's in the correct directory
            let expected_dir = temp_dir.path().join("omni");
            assert!(
                data.file_path.starts_with(&expected_dir),
                "Omni data should be in omni directory"
            );

            // Verify parsed data exists in JSON
            let json_content = std::fs::read_to_string(&data.file_path)?;
            let json_obj: serde_json::Value = serde_json::from_str(&json_content)?;

            assert!(json_obj.get("parsed").is_some(), "Should have parsed data");
            let parsed = json_obj.get("parsed").unwrap();
            assert_eq!(parsed["message_type"], 50);
            assert_eq!(parsed["fields"]["name"], "AnuCoin");
            assert_eq!(parsed["fields"]["ecosystem_name"], "Test");

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected Omni data, got Bitcoin Stamps");
        }
        Some(DecodedData::Counterparty { .. }) => {
            panic!("❌ Expected Omni data, got Counterparty");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Expected Omni data, got Chancecoin");
        }
        Some(DecodedData::DataStorage(_)) => {
            panic!("❌ Expected Omni data, got DataStorage");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_property_fixed_725ba7() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_property_fixed_725ba7");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer fixed property creation");
    println!("Transaction: {}", OMNI_PROPERTY_FIXED_TXID);

    let result = decoder.decode_txid(OMNI_PROPERTY_FIXED_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_PROPERTY_FIXED_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_send_to_owners_0937f1() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_send_to_owners_0937f1");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer send to owners");
    println!("Transaction: {}", OMNI_SEND_TO_OWNERS_TXID);

    let result = decoder.decode_txid(OMNI_SEND_TO_OWNERS_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_SEND_TO_OWNERS_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_dex_offer_9a0177() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_dex_offer_9a0177");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer DEX sell offer");
    println!("Transaction: {}", OMNI_DEX_OFFER_TXID);

    let result = decoder.decode_txid(OMNI_DEX_OFFER_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_DEX_OFFER_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            // Verify parsed data exists
            let json_content = std::fs::read_to_string(&data.file_path)?;
            let json_obj: serde_json::Value = serde_json::from_str(&json_content)?;

            assert!(json_obj.get("parsed").is_some(), "Should have parsed data");
            let parsed = json_obj.get("parsed").unwrap();
            assert_eq!(parsed["message_type"], 20, "Should be TradeOffer type 20");

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_variable_property_b01d15() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_variable_property_b01d15");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer variable property creation");
    println!("Transaction: {}", OMNI_VARIABLE_PROPERTY_TXID);

    let result = decoder.decode_txid(OMNI_VARIABLE_PROPERTY_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_VARIABLE_PROPERTY_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            // Verify parsed data exists
            let json_content = std::fs::read_to_string(&data.file_path)?;
            let json_obj: serde_json::Value = serde_json::from_str(&json_content)?;

            assert!(json_obj.get("parsed").is_some(), "Should have parsed data");
            let parsed = json_obj.get("parsed").unwrap();
            assert_eq!(
                parsed["message_type"], 51,
                "Should be CreatePropertyVariable type 51"
            );

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_manual_property_73914f() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_manual_property_73914f");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer manual property creation");
    println!("Transaction: {}", OMNI_MANUAL_PROPERTY_TXID);

    let result = decoder.decode_txid(OMNI_MANUAL_PROPERTY_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_MANUAL_PROPERTY_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_grant_tokens_1caf04() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_grant_tokens_1caf04");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer grant property tokens");
    println!("Transaction: {}", OMNI_GRANT_TOKENS_TXID);

    let result = decoder.decode_txid(OMNI_GRANT_TOKENS_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_GRANT_TOKENS_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_revoke_tokens_742973() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_revoke_tokens_742973");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer revoke property tokens");
    println!("Transaction: {}", OMNI_REVOKE_TOKENS_TXID);

    let result = decoder.decode_txid(OMNI_REVOKE_TOKENS_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_REVOKE_TOKENS_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_dex_accept_3d7742() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_dex_accept_3d7742");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer DEX accept offer");
    println!("Transaction: {}", OMNI_DEX_ACCEPT_TXID);

    let result = decoder.decode_txid(OMNI_DEX_ACCEPT_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_DEX_ACCEPT_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_crowdsale_creation_eda3d2() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_crowdsale_creation_eda3d2");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer crowdsale creation");
    println!("Transaction: {}", OMNI_CROWDSALE_CREATION_TXID);

    let result = decoder.decode_txid(OMNI_CROWDSALE_CREATION_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_CROWDSALE_CREATION_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_crowdsale_participation_c1ff92() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_crowdsale_participation_c1ff92");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer crowdsale participation");
    println!("Transaction: {}", OMNI_CROWDSALE_PARTICIPATION_TXID);

    let result = decoder
        .decode_txid(OMNI_CROWDSALE_PARTICIPATION_TXID)
        .await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_CROWDSALE_PARTICIPATION_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_omni_close_crowdsale_b88645() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_omni_close_crowdsale_b88645");
            return Ok(());
        }
    };

    println!("🔍 Testing Omni Layer close crowdsale");
    println!("Transaction: {}", OMNI_CLOSE_CROWDSALE_TXID);

    let result = decoder.decode_txid(OMNI_CLOSE_CROWDSALE_TXID).await?;

    match result {
        Some(DecodedData::Omni { data }) => {
            println!("✅ Successfully decoded Omni Layer data:");
            println!("   Message Type: {:?}", data.message_type);
            println!("   Sender: {}", data.sender_address);
            println!("   Packets: {}", data.packet_count);
            println!("   File: {:?}", data.file_path);

            assert_eq!(data.txid, OMNI_CLOSE_CROWDSALE_TXID);
            assert!(data.file_path.exists(), "Omni file should exist");

            let expected_dir = temp_dir.path().join("omni");
            assert!(data.file_path.starts_with(&expected_dir));

            println!("✅ Omni validation passed");
        }
        Some(DecodedData::Chancecoin { .. }) => panic!("❌ Unexpected Chancecoin data"),
        Some(DecodedData::DataStorage(_)) => panic!("❌ Unexpected DataStorage data"),
        Some(DecodedData::BitcoinStamps { .. }) => panic!("❌ Expected Omni data, got Stamps"),
        Some(DecodedData::Counterparty { .. }) => panic!("❌ Expected Omni data, got Counterparty"),
        None => panic!("❌ Expected decoded data, got None"),
    }

    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_original_image() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_original_image");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(STAMPS_ORIGINAL_IMAGE_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps { data, .. }) => match data {
            BitcoinStampsData::Image(img) => {
                assert_eq!(img.txid, STAMPS_ORIGINAL_IMAGE_TXID);
                assert!(img.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
                assert!(img.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Json(json) => {
                assert_eq!(json.txid, STAMPS_ORIGINAL_IMAGE_TXID);
                assert!(json.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
                assert!(json.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Html(html) => {
                assert_eq!(html.txid, STAMPS_ORIGINAL_IMAGE_TXID);
                assert!(html.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
                assert!(html.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Compressed(compressed) => {
                assert_eq!(compressed.txid, STAMPS_ORIGINAL_IMAGE_TXID);
                assert!(compressed.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("compressed");
                assert!(compressed.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Data(data) => {
                assert_eq!(data.txid, STAMPS_ORIGINAL_IMAGE_TXID);
                assert!(data.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("data");
                assert!(data.file_path.starts_with(&expected_dir));
            }
        },
        Some(DecodedData::Counterparty { .. }) => panic!("Expected Stamps, got Counterparty"),
        Some(DecodedData::Omni { .. }) => panic!("Expected Stamps, got Omni"),
        Some(DecodedData::Chancecoin { .. }) => panic!("Expected Stamps, got Chancecoin"),
        Some(DecodedData::DataStorage(_)) => panic!("Expected Stamps, got DataStorage"),
        None => panic!("Expected decoded data, got None"),
    }
    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_classic_4d89d7() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_classic_4d89d7");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(STAMPS_CLASSIC_4D89D7_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps { data, .. }) => match data {
            BitcoinStampsData::Image(img) => {
                assert_eq!(img.txid, STAMPS_CLASSIC_4D89D7_TXID);
                assert!(img.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
                assert!(img.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Json(json) => {
                assert_eq!(json.txid, STAMPS_CLASSIC_4D89D7_TXID);
                assert!(json.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
                assert!(json.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Html(html) => {
                assert_eq!(html.txid, STAMPS_CLASSIC_4D89D7_TXID);
                assert!(html.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
                assert!(html.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Compressed(compressed) => {
                assert_eq!(compressed.txid, STAMPS_CLASSIC_4D89D7_TXID);
                assert!(compressed.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("compressed");
                assert!(compressed.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Data(data) => {
                assert_eq!(data.txid, STAMPS_CLASSIC_4D89D7_TXID);
                assert!(data.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("data");
                assert!(data.file_path.starts_with(&expected_dir));
            }
        },
        Some(DecodedData::Counterparty { .. }) => panic!("Expected Stamps, got Counterparty"),
        Some(DecodedData::Omni { .. }) => panic!("Expected Stamps, got Omni"),
        Some(DecodedData::Chancecoin { .. }) => panic!("Expected Stamps, got Chancecoin"),
        Some(DecodedData::DataStorage(_)) => panic!("Expected Stamps, got DataStorage"),
        None => panic!("Expected decoded data, got None"),
    }
    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_classic_f35382() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_classic_f35382");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(STAMPS_CLASSIC_F35382_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps { data, .. }) => match data {
            BitcoinStampsData::Image(img) => {
                assert_eq!(img.txid, STAMPS_CLASSIC_F35382_TXID);
                assert!(img.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
                assert!(img.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Json(json) => {
                assert_eq!(json.txid, STAMPS_CLASSIC_F35382_TXID);
                assert!(json.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
                assert!(json.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Html(html) => {
                assert_eq!(html.txid, STAMPS_CLASSIC_F35382_TXID);
                assert!(html.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
                assert!(html.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Compressed(compressed) => {
                assert_eq!(compressed.txid, STAMPS_CLASSIC_F35382_TXID);
                assert!(compressed.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("compressed");
                assert!(compressed.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Data(data) => {
                assert_eq!(data.txid, STAMPS_CLASSIC_F35382_TXID);
                assert!(data.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("data");
                assert!(data.file_path.starts_with(&expected_dir));
            }
        },
        Some(DecodedData::Counterparty { .. }) => panic!("Expected Stamps, got Counterparty"),
        Some(DecodedData::Omni { .. }) => panic!("Expected Stamps, got Omni"),
        Some(DecodedData::Chancecoin { .. }) => panic!("Expected Stamps, got Chancecoin"),
        Some(DecodedData::DataStorage(_)) => panic!("Expected Stamps, got DataStorage"),
        None => panic!("Expected decoded data, got None"),
    }
    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_recent_c8c383() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_recent_c8c383");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(STAMPS_RECENT_C8C383_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps { data, .. }) => match data {
            BitcoinStampsData::Image(img) => {
                assert_eq!(img.txid, STAMPS_RECENT_C8C383_TXID);
                assert!(img.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
                assert!(img.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Json(json) => {
                assert_eq!(json.txid, STAMPS_RECENT_C8C383_TXID);
                assert!(json.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
                assert!(json.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Html(html) => {
                assert_eq!(html.txid, STAMPS_RECENT_C8C383_TXID);
                assert!(html.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
                assert!(html.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Compressed(compressed) => {
                assert_eq!(compressed.txid, STAMPS_RECENT_C8C383_TXID);
                assert!(compressed.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("compressed");
                assert!(compressed.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Data(data) => {
                assert_eq!(data.txid, STAMPS_RECENT_C8C383_TXID);
                assert!(data.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("data");
                assert!(data.file_path.starts_with(&expected_dir));
            }
        },
        Some(DecodedData::Counterparty { .. }) => panic!("Expected Stamps, got Counterparty"),
        Some(DecodedData::Omni { .. }) => panic!("Expected Stamps, got Omni"),
        Some(DecodedData::Chancecoin { .. }) => panic!("Expected Stamps, got Chancecoin"),
        Some(DecodedData::DataStorage(_)) => panic!("Expected Stamps, got DataStorage"),
        None => panic!("Expected decoded data, got None"),
    }
    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_image_359aef() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_image_359aef");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(STAMPS_IMAGE_359AEF_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps { data, .. }) => match data {
            BitcoinStampsData::Image(img) => {
                assert_eq!(img.txid, STAMPS_IMAGE_359AEF_TXID);
                assert!(img.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
                assert!(img.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Json(json) => {
                assert_eq!(json.txid, STAMPS_IMAGE_359AEF_TXID);
                assert!(json.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
                assert!(json.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Html(html) => {
                assert_eq!(html.txid, STAMPS_IMAGE_359AEF_TXID);
                assert!(html.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
                assert!(html.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Compressed(compressed) => {
                assert_eq!(compressed.txid, STAMPS_IMAGE_359AEF_TXID);
                assert!(compressed.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("compressed");
                assert!(compressed.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Data(data) => {
                assert_eq!(data.txid, STAMPS_IMAGE_359AEF_TXID);
                assert!(data.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("data");
                assert!(data.file_path.starts_with(&expected_dir));
            }
        },
        Some(DecodedData::Counterparty { .. }) => panic!("Expected Stamps, got Counterparty"),
        Some(DecodedData::Omni { .. }) => panic!("Expected Stamps, got Omni"),
        Some(DecodedData::Chancecoin { .. }) => panic!("Expected Stamps, got Chancecoin"),
        Some(DecodedData::DataStorage(_)) => panic!("Expected Stamps, got DataStorage"),
        None => panic!("Expected decoded data, got None"),
    }
    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_image_50aeb7() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_image_50aeb7");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(STAMPS_IMAGE_50AEB7_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps { data, .. }) => match data {
            BitcoinStampsData::Image(img) => {
                assert_eq!(img.txid, STAMPS_IMAGE_50AEB7_TXID);
                assert!(img.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
                assert!(img.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Json(json) => {
                assert_eq!(json.txid, STAMPS_IMAGE_50AEB7_TXID);
                assert!(json.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
                assert!(json.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Html(html) => {
                assert_eq!(html.txid, STAMPS_IMAGE_50AEB7_TXID);
                assert!(html.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
                assert!(html.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Compressed(compressed) => {
                assert_eq!(compressed.txid, STAMPS_IMAGE_50AEB7_TXID);
                assert!(compressed.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("compressed");
                assert!(compressed.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Data(data) => {
                assert_eq!(data.txid, STAMPS_IMAGE_50AEB7_TXID);
                assert!(data.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("data");
                assert!(data.file_path.starts_with(&expected_dir));
            }
        },
        Some(DecodedData::Counterparty { .. }) => panic!("Expected Stamps, got Counterparty"),
        Some(DecodedData::Omni { .. }) => panic!("Expected Stamps, got Omni"),
        Some(DecodedData::Chancecoin { .. }) => panic!("Expected Stamps, got Chancecoin"),
        Some(DecodedData::DataStorage(_)) => panic!("Expected Stamps, got DataStorage"),
        None => panic!("Expected decoded data, got None"),
    }
    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_image_582a46() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_image_582a46");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(STAMPS_IMAGE_582A46_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps { data, .. }) => match data {
            BitcoinStampsData::Image(img) => {
                assert_eq!(img.txid, STAMPS_IMAGE_582A46_TXID);
                assert!(img.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
                assert!(img.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Json(json) => {
                assert_eq!(json.txid, STAMPS_IMAGE_582A46_TXID);
                assert!(json.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
                assert!(json.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Html(html) => {
                assert_eq!(html.txid, STAMPS_IMAGE_582A46_TXID);
                assert!(html.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
                assert!(html.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Compressed(compressed) => {
                assert_eq!(compressed.txid, STAMPS_IMAGE_582A46_TXID);
                assert!(compressed.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("compressed");
                assert!(compressed.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Data(data) => {
                assert_eq!(data.txid, STAMPS_IMAGE_582A46_TXID);
                assert!(data.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("data");
                assert!(data.file_path.starts_with(&expected_dir));
            }
        },
        Some(DecodedData::Counterparty { .. }) => panic!("Expected Stamps, got Counterparty"),
        Some(DecodedData::Omni { .. }) => panic!("Expected Stamps, got Omni"),
        Some(DecodedData::Chancecoin { .. }) => panic!("Expected Stamps, got Chancecoin"),
        Some(DecodedData::DataStorage(_)) => panic!("Expected Stamps, got DataStorage"),
        None => panic!("Expected decoded data, got None"),
    }
    Ok(())
}

#[tokio::test]
async fn test_decode_stamps_image_5e7d66() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_stamps_image_5e7d66");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(STAMPS_IMAGE_5E7D66_TXID).await?;

    match result {
        Some(DecodedData::BitcoinStamps { data, .. }) => match data {
            BitcoinStampsData::Image(img) => {
                assert_eq!(img.txid, STAMPS_IMAGE_5E7D66_TXID);
                assert!(img.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("images");
                assert!(img.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Json(json) => {
                assert_eq!(json.txid, STAMPS_IMAGE_5E7D66_TXID);
                assert!(json.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("json");
                assert!(json.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Html(html) => {
                assert_eq!(html.txid, STAMPS_IMAGE_5E7D66_TXID);
                assert!(html.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("html");
                assert!(html.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Compressed(compressed) => {
                assert_eq!(compressed.txid, STAMPS_IMAGE_5E7D66_TXID);
                assert!(compressed.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("compressed");
                assert!(compressed.file_path.starts_with(&expected_dir));
            }
            BitcoinStampsData::Data(data) => {
                assert_eq!(data.txid, STAMPS_IMAGE_5E7D66_TXID);
                assert!(data.file_path.exists());
                let expected_dir = temp_dir.path().join("bitcoin_stamps").join("data");
                assert!(data.file_path.starts_with(&expected_dir));
            }
        },
        Some(DecodedData::Counterparty { .. }) => panic!("Expected Stamps, got Counterparty"),
        Some(DecodedData::Omni { .. }) => panic!("Expected Stamps, got Omni"),
        Some(DecodedData::Chancecoin { .. }) => panic!("Expected Stamps, got Chancecoin"),
        Some(DecodedData::DataStorage(_)) => panic!("Expected Stamps, got DataStorage"),
        None => panic!("Expected decoded data, got None"),
    }
    Ok(())
}

/// Test decoding the Bitcoin Whitepaper PDF embedded in the blockchain
///
/// This transaction contains the original Bitcoin Whitepaper (Satoshi Nakamoto, 2008)
/// embedded across 946 P2MS outputs, totaling 184,292 bytes (180KB).
///
/// Historical significance: This is one of the most famous examples of data embedding
/// in the Bitcoin blockchain, demonstrating the DataStorage protocol's ability to
/// reconstruct large binary files from multi-output P2MS transactions.
#[tokio::test]
async fn test_decode_datastorage_bitcoin_whitepaper_pdf() -> anyhow::Result<()> {
    let (decoder, _temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_decode_datastorage_bitcoin_whitepaper_pdf");
            return Ok(());
        }
    };

    println!("🔍 Testing DataStorage PDF decoding - Bitcoin Whitepaper");
    println!("Transaction: {}", DATASTORAGE_BITCOIN_WHITEPAPER_TXID);
    println!("Expected: 946 P2MS outputs, 184,292 bytes (180KB)");

    let result = decoder
        .decode_txid(DATASTORAGE_BITCOIN_WHITEPAPER_TXID)
        .await?;

    match result {
        Some(DecodedData::DataStorage(data)) => {
            println!("✅ Successfully decoded DataStorage data:");
            println!("   Pattern: {}", data.pattern);
            println!("   Size: {} bytes", data.decoded_data.len());
            println!("   Metadata: {}", data.metadata);

            // Validate the decoded data
            assert_eq!(data.txid, DATASTORAGE_BITCOIN_WHITEPAPER_TXID);

            // Compare against the canonical on-disk PDF fixture
            let expected_path = Path::new("tests/test_data/datastorage/bitcoin.pdf");
            let expected_bytes = fs::read(expected_path)?;

            assert_eq!(
                data.decoded_data.len(),
                expected_bytes.len(),
                "Bitcoin Whitepaper should be {} bytes",
                expected_bytes.len()
            );

            assert_eq!(
                data.decoded_data, expected_bytes,
                "Decoded PDF bytes must match canonical fixture"
            );

            // Validate hash for additional assurance
            let actual_hash = Sha256::digest(&data.decoded_data);
            let expected_hash = Sha256::digest(&expected_bytes);
            assert_eq!(
                actual_hash, expected_hash,
                "Decoded PDF SHA-256 hash mismatch"
            );

            // Verify it's a valid PDF by checking magic bytes
            // Note: Some embedded PDFs may have leading padding bytes
            let pdf_offset = data
                .decoded_data
                .windows(4)
                .position(|w| w == b"%PDF")
                .expect("Should contain PDF magic bytes");
            assert!(
                pdf_offset < 20,
                "PDF magic bytes should be near the start (found at offset {})",
                pdf_offset
            );
            assert!(
                data.decoded_data.windows(5).any(|w| w == b"%%EOF"),
                "Should contain PDF EOF marker"
            );

            // Pattern should indicate it's a binary file (PDF)
            assert!(
                data.pattern.contains("PDF") || data.pattern.contains("BinaryFile"),
                "Pattern should indicate PDF file type"
            );

            println!("✅ Bitcoin Whitepaper PDF validation passed");
            println!("   • Valid PDF structure confirmed");
            println!("   • Size matches expected {} bytes", expected_bytes.len());
            println!("   • Successfully extracted from 946 P2MS outputs");
        }
        Some(DecodedData::BitcoinStamps { .. }) => {
            panic!("❌ Expected DataStorage data, got Bitcoin Stamps");
        }
        Some(DecodedData::Counterparty { .. }) => {
            panic!("❌ Expected DataStorage data, got Counterparty");
        }
        Some(DecodedData::Omni { .. }) => {
            panic!("❌ Expected DataStorage data, got Omni");
        }
        Some(DecodedData::Chancecoin { .. }) => {
            panic!("❌ Expected DataStorage data, got Chancecoin");
        }
        None => {
            panic!("❌ Expected decoded data, got None");
        }
    }

    Ok(())
}
