/// Integration tests for PPk Protocol Decoder
///
/// Tests the end-to-end decoding of PPk (PPkPub) protocol transactions from
/// Beijing University of Posts and Telecommunications (2015-2019).
///
/// PPk attempted to create a decentralised naming and identity system on Bitcoin
/// using P2MS outputs with a specific marker pubkey.
///
/// ## Test Coverage
///
/// - Profile: JSON profile data via RT transport (two transport encodings tested):
///   - OP_RETURN transport: RT TLV in OP_RETURN + 1-of-2 multisig
///   - P2MS-embedded transport: RT split between P2MS pubkey #3 and OP_RETURN + 1-of-3 multisig
/// - Registration: Quoted number strings in OP_RETURN (e.g., "315"})
/// - Message: Promotional text containing "PPk" or ≥80% printable ASCII
/// - Unknown: PPk marker present but no specific pattern matches
///
/// ## ODIN Identifier Format
///
/// `ppk:[BLOCK_HEIGHT].[TRANSACTION_INDEX]/[DSS]`
///
/// where DSS (Data Specification String) varies by variant:
/// - Profile: Inferred from RT JSON ("ap" field, "title", or default)
/// - Registration: `reg_<number>.txt`
/// - Message: `message.txt`
/// - Unknown: `unknown.bin`
///
/// These tests require a running Bitcoin Core node with txindex=1.
use crate::common::rpc_helpers::{create_test_rpc_config, skip_if_rpc_unavailable};
use data_carry_research::decoder::ProtocolDecoder;
use tempfile::TempDir;
use tokio;

/// Helper to create decoder with temp directory
async fn create_test_decoder() -> anyhow::Result<(ProtocolDecoder, TempDir)> {
    let temp_dir = TempDir::new()?;
    let output_dir = temp_dir.path().to_path_buf();
    let rpc_config = create_test_rpc_config();

    let decoder = ProtocolDecoder::new(rpc_config, output_dir).await?;
    Ok((decoder, temp_dir))
}

/// PPk test TXIDs for all 4 variants (Profile variant has 2 transport encodings)
const PPK_PROFILE_OPRETURN_TXID: &str =
    "ed95e04018dcc2f01ba8cd699d86852f85ca0af63d05f715a9b2701bb61c6b00";
const PPK_PROFILE_P2MS_TXID: &str =
    "20cb5958edce385c3fa3ec7f3b12391f158442c7a742a924312556eca891f400";
const PPK_REGISTRATION_TXID: &str =
    "a72d797a108fca918efbded273623ce1f9348b716c0f700bab97f12fe5837200";
const PPK_MESSAGE_TXID: &str = "a7fcc7391e2db0fe13b3a12d37fdbdc6138b2c76a9a447020fa92071a64dfe0c";
const PPK_UNKNOWN_TXID: &str = "39dc482ec69056ae445d1acad9507f8167d3f91fc93b9076e94cfb866e639600";

/// Test Profile variant decoding (OP_RETURN transport)
///
/// Pattern: OP_RETURN with RT TLV + 1-of-2 multisig + PPk marker
/// Expected: ODIN identifier with DSS inferred from RT JSON
#[tokio::test]
#[serial_test::serial]
async fn test_ppk_profile_opreturn_decoding() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_ppk_profile_opreturn_decoding");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(PPK_PROFILE_OPRETURN_TXID).await?;
    let decoded = result.expect("Should decode PPk transaction");

    // Verify PPk protocol detected
    assert!(decoded.is_ppk(), "Should detect PPk protocol");

    // Verify ODIN identifier created
    if let Some(ppk_data) = decoded.ppk_data() {
        assert!(
            ppk_data.odin_identifier.is_some(),
            "Profile (OP_RETURN transport) should have ODIN identifier"
        );

        let odin = ppk_data.odin_identifier.as_ref().unwrap();
        println!("✅ ODIN: {}", odin.full_identifier);
        println!("   • Block: {}", odin.block_height);
        println!("   • TX index: {}", odin.tx_index);
        println!("   • DSS: {}", odin.dss);

        // Verify DSS format (should be inferred from JSON)
        assert!(
            odin.dss.ends_with(".json") || odin.dss.contains("profile") || odin.dss.contains("data"),
            "DSS should be JSON-related: {}",
            odin.dss
        );

        // Verify RT JSON extracted
        assert!(
            ppk_data.rt_json.is_some(),
            "Profile should have parsed RT JSON"
        );
    } else {
        panic!("PPk data missing from decoded result");
    }

    // Verify JSON file created
    let ppk_output_dir = temp_dir.path().join("ppk");
    assert!(
        ppk_output_dir.exists(),
        "PPk output directory should be created"
    );

    let json_files: Vec<_> = std::fs::read_dir(&ppk_output_dir)
        .expect("Failed to read PPk directory")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .collect();

    assert!(
        !json_files.is_empty(),
        "Should create JSON file for Profile variant"
    );

    Ok(())
}

/// Test Profile variant decoding (P2MS-embedded transport)
///
/// Pattern: RT in pubkey #3, JSON split between P2MS + OP_RETURN, 1-of-3 multisig
/// Expected: ODIN identifier with combined JSON extracted
#[tokio::test]
#[serial_test::serial]
async fn test_ppk_profile_p2ms_decoding() -> anyhow::Result<()> {
    let (decoder, _temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_ppk_profile_p2ms_decoding");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(PPK_PROFILE_P2MS_TXID).await?;
    let decoded = result.expect("Should decode PPk transaction");
    assert!(decoded.is_ppk(), "Should detect PPk protocol");

    if let Some(ppk_data) = decoded.ppk_data() {
        assert!(
            ppk_data.odin_identifier.is_some(),
            "Profile (P2MS-embedded transport) should have ODIN identifier"
        );

        let odin = ppk_data.odin_identifier.as_ref().unwrap();
        println!("✅ ODIN: {}", odin.full_identifier);
        println!("   • Variant: Profile (P2MS-embedded transport)");
        println!("   • DSS: {}", odin.dss);

        // Verify RT JSON extracted and combined
        assert!(
            ppk_data.rt_json.is_some(),
            "Profile should have parsed RT JSON"
        );

        println!(
            "   • RT JSON: {}",
            ppk_data.rt_json.as_ref().unwrap()
        );
    } else {
        panic!("PPk data missing from decoded result");
    }

    Ok(())
}

/// Test Registration variant decoding
///
/// Pattern: Quoted number string in OP_RETURN (e.g., "315"})
/// Expected: ODIN with `reg_<number>.txt` DSS
#[tokio::test]
#[serial_test::serial]
async fn test_ppk_registration_decoding() -> anyhow::Result<()> {
    let (decoder, _temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_ppk_rt_p2ms_embedded_decoding");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(PPK_REGISTRATION_TXID).await?;
    let decoded = result.expect("Should decode PPk transaction");
    assert!(decoded.is_ppk(), "Should detect PPk protocol");

    if let Some(ppk_data) = decoded.ppk_data() {
        assert!(
            ppk_data.odin_identifier.is_some(),
            "Registration should have ODIN identifier"
        );

        let odin = ppk_data.odin_identifier.as_ref().unwrap();
        println!("✅ ODIN: {}", odin.full_identifier);
        println!("   • Variant: Registration");
        println!("   • DSS: {}", odin.dss);

        // Verify DSS format is reg_<number>.txt
        assert!(
            odin.dss.starts_with("reg_") && odin.dss.ends_with(".txt"),
            "Registration DSS should be 'reg_<number>.txt': {}",
            odin.dss
        );
    } else {
        panic!("PPk data missing from decoded result");
    }

    // Note: File output for PPk Registration variant not yet implemented
    // The decoder successfully extracts and validates the data, but file writing
    // is handled separately in the output management system

    Ok(())
}

/// Test Message variant decoding
///
/// Pattern: OP_RETURN contains "PPk"/"ppk" OR ≥80% printable ASCII
/// Expected: ODIN with `message.txt` DSS
#[tokio::test]
#[serial_test::serial]
async fn test_ppk_message_decoding() -> anyhow::Result<()> {
    let (decoder, _temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_ppk_rt_p2ms_embedded_decoding");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(PPK_MESSAGE_TXID).await?;
    let decoded = result.expect("Should decode PPk transaction");
    assert!(decoded.is_ppk(), "Should detect PPk protocol");

    if let Some(ppk_data) = decoded.ppk_data() {
        assert!(
            ppk_data.odin_identifier.is_some(),
            "Message should have ODIN identifier"
        );

        let odin = ppk_data.odin_identifier.as_ref().unwrap();
        println!("✅ ODIN: {}", odin.full_identifier);
        println!("   • Variant: Message");
        println!("   • DSS: {}", odin.dss);

        // Verify DSS is message.txt
        assert_eq!(
            odin.dss, "message.txt",
            "Message DSS should be 'message.txt'"
        );
    } else {
        panic!("PPk data missing from decoded result");
    }

    Ok(())
}

/// Test Unknown variant decoding
///
/// Pattern: PPk marker present but no specific variant matches
/// Expected: ODIN with `unknown.bin` DSS
#[tokio::test]
#[serial_test::serial]
async fn test_ppk_unknown_decoding() -> anyhow::Result<()> {
    let (decoder, _temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_ppk_rt_p2ms_embedded_decoding");
            return Ok(());
        }
    };

    let result = decoder.decode_txid(PPK_UNKNOWN_TXID).await?;
    let decoded = result.expect("Should decode PPk transaction");
    assert!(decoded.is_ppk(), "Should detect PPk protocol");

    if let Some(ppk_data) = decoded.ppk_data() {
        assert!(
            ppk_data.odin_identifier.is_some(),
            "Unknown should have ODIN identifier"
        );

        let odin = ppk_data.odin_identifier.as_ref().unwrap();
        println!("✅ ODIN: {}", odin.full_identifier);
        println!("   • Variant: Unknown");
        println!("   • DSS: {}", odin.dss);

        // Verify DSS is unknown.bin
        assert_eq!(
            odin.dss, "unknown.bin",
            "Unknown DSS should be 'unknown.bin'"
        );
    } else {
        panic!("PPk data missing from decoded result");
    }

    // Note: File output for PPk Unknown variant not yet implemented
    // The decoder successfully extracts and validates the data, but file writing
    // is handled separately in the output management system

    Ok(())
}

/// Test PPk marker detection - verify non-PPk transactions are not classified
#[tokio::test]
#[serial_test::serial]
async fn test_non_ppk_transaction() -> anyhow::Result<()> {
    let (decoder, temp_dir) = match create_test_decoder().await {
        Ok(setup) => setup,
        Err(e) => {
            skip_if_rpc_unavailable(e, "test_non_ppk_transaction");
            return Ok(());
        }
    };

    // Use a known Bitcoin Stamps transaction (different marker)
    const NON_PPK_TXID: &str =
        "54fdeda90c4573f8a93fa45251a3c6214bcc79aa8549728dfb08ffe3e7dd3d81";

    let result = decoder.decode_txid(NON_PPK_TXID).await?;
    let decoded_opt = result;

    // Verify PPk NOT detected
    if let Some(decoded) = decoded_opt {
        assert!(
            !decoded.is_ppk(),
            "Should NOT detect PPk protocol on non-PPk transaction"
        );
    }

    // Verify no PPk output directory created
    let ppk_output_dir = temp_dir.path().join("ppk");
    assert!(
        !ppk_output_dir.exists(),
        "Should not create PPk directory for non-PPk transaction"
    );

    Ok(())
}
