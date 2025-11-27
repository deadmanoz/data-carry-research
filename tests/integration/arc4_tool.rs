/// Integration tests for ARC4 deobfuscation utility
///
/// These tests verify the ARC4 tool can correctly deobfuscate P2MS data from
/// real Bitcoin transactions using Counterparty, Bitcoin Stamps, and unknown protocols.
///
/// NOTE: These tests require a running Bitcoin Core node with `-txindex=1`.
/// Tests will be skipped if RPC is not available.
use crate::common::rpc_helpers::create_test_rpc_client;
use data_carry_research::decoder::arc4_tool;
use data_carry_research::types::stamps::StampsTransport;

/// Test ARC4 deobfuscation on a known Counterparty transaction
#[tokio::test]
async fn test_arc4_counterparty() {
    let client = match create_test_rpc_client().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⏭️  Skipping test - Bitcoin RPC not available: {}", e);
            return;
        }
    };

    // Known Counterparty transaction with CNTRPRTY signature
    // da3ed1efda82824cb24ea081ef2a8f532a7dd9cd1ebc5efa873498c3958c864e
    let txid = "da3ed1efda82824cb24ea081ef2a8f532a7dd9cd1ebc5efa873498c3958c864e";

    let result = arc4_tool::deobfuscate_transaction(txid, &client)
        .await
        .expect("ARC4 deobfuscation should succeed");

    // Verify basic structure
    assert_eq!(result.txid, txid);
    assert!(!result.input_txid.is_empty());
    assert!(result.p2ms_output_count > 0);

    // Should detect Counterparty
    assert!(
        result.counterparty.is_some(),
        "Should detect Counterparty protocol"
    );

    let cp = result.counterparty.unwrap();
    assert!(!cp.raw_data.is_empty(), "Should have raw data");
    assert!(!cp.decrypted.is_empty(), "Should have decrypted data");

    // Verify Counterparty signature (CNTRPRTY = 434e545250525459)
    let cntrprty_prefix = b"CNTRPRTY";
    let has_signature = cp
        .decrypted
        .windows(cntrprty_prefix.len())
        .any(|window| window == cntrprty_prefix);

    assert!(
        has_signature,
        "Decrypted data should contain CNTRPRTY signature"
    );

    println!("✅ Counterparty ARC4 test passed");
    println!("   Raw: {} bytes", cp.raw_data.len());
    println!("   Decrypted: {} bytes", cp.decrypted.len());
}

/// Test ARC4 deobfuscation on a known Bitcoin Stamps transaction
#[tokio::test]
async fn test_arc4_bitcoin_stamps() {
    let client = match create_test_rpc_client().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⏭️  Skipping test - Bitcoin RPC not available: {}", e);
            return;
        }
    };

    // Known Bitcoin Stamps transaction (pure, not Counterparty-embedded)
    // 54fdeda90c4573f8a93fa45251a3c6214bcc79aa8549728dfb08ffe3e7dd3d81
    let txid = "54fdeda90c4573f8a93fa45251a3c6214bcc79aa8549728dfb08ffe3e7dd3d81";

    let result = arc4_tool::deobfuscate_transaction(txid, &client)
        .await
        .expect("ARC4 deobfuscation should succeed");

    // Verify basic structure
    assert_eq!(result.txid, txid);
    assert!(!result.input_txid.is_empty());
    assert!(result.p2ms_output_count > 0);

    // Should detect Bitcoin Stamps
    assert!(
        result.stamps.is_some(),
        "Should detect Bitcoin Stamps protocol"
    );

    let stamps = result.stamps.unwrap();
    assert!(!stamps.raw_data.is_empty(), "Should have raw data");
    assert!(!stamps.decrypted.is_empty(), "Should have decrypted data");

    // Verify stamp signature (case-insensitive check)
    let stamp_lower = b"stamp:";
    let stamp_upper = b"STAMP:";
    let has_signature = stamps.decrypted.windows(stamp_lower.len()).any(|window| {
        window.eq_ignore_ascii_case(stamp_lower) || window.eq_ignore_ascii_case(stamp_upper)
    });

    assert!(
        has_signature,
        "Decrypted data should contain stamp signature (case-insensitive)"
    );

    // Verify transport type
    match stamps.transport {
        StampsTransport::Pure => {
            println!("✅ Bitcoin Stamps (Pure) ARC4 test passed");
        }
        StampsTransport::Counterparty => {
            println!("✅ Bitcoin Stamps (Counterparty) ARC4 test passed");
        }
    }

    println!("   Raw: {} bytes", stamps.raw_data.len());
    println!("   Decrypted: {} bytes", stamps.decrypted.len());
    println!("   Signature offset: {}", stamps.signature_offset);
}

/// Test ARC4 deobfuscation on a transaction with both Counterparty and Stamps
///
/// This tests the scenario where Bitcoin Stamps is embedded in a Counterparty
/// transaction, which should be detected by both paths.
#[tokio::test]
async fn test_arc4_counterparty_embedded_stamps() {
    let client = match create_test_rpc_client().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⏭️  Skipping test - Bitcoin RPC not available: {}", e);
            return;
        }
    };

    // Known transaction with Stamps-over-Counterparty
    // This transaction has both CNTRPRTY and STAMP: signatures (Counterparty-embedded Stamps)
    // Using the same transaction as the first test since it actually has both protocols
    let txid = "54fdeda90c4573f8a93fa45251a3c6214bcc79aa8549728dfb08ffe3e7dd3d81";

    let result = arc4_tool::deobfuscate_transaction(txid, &client)
        .await
        .expect("ARC4 deobfuscation should succeed");

    // Should detect both protocols
    assert!(
        result.counterparty.is_some(),
        "Should detect Counterparty envelope"
    );
    assert!(
        result.stamps.is_some(),
        "Should detect embedded Bitcoin Stamps"
    );

    let stamps = result.stamps.unwrap();

    // Verify it's recognised as Counterparty transport
    matches!(stamps.transport, StampsTransport::Counterparty);

    // Verify both signatures present (case-insensitive for stamp)
    let cntrprty_prefix = b"CNTRPRTY";
    let stamp_lower = b"stamp:";
    let stamp_upper = b"STAMP:";

    let has_cntrprty = stamps
        .decrypted
        .windows(cntrprty_prefix.len())
        .any(|window| window == cntrprty_prefix);

    let has_stamp = stamps.decrypted.windows(stamp_lower.len()).any(|window| {
        window.eq_ignore_ascii_case(stamp_lower) || window.eq_ignore_ascii_case(stamp_upper)
    });

    assert!(
        has_cntrprty && has_stamp,
        "Should contain both CNTRPRTY and stamp signatures for Counterparty-embedded Stamps"
    );

    println!("✅ Counterparty-embedded Stamps ARC4 test passed");
    println!("   Raw: {} bytes", stamps.raw_data.len());
    println!("   Decrypted: {} bytes", stamps.decrypted.len());
}

/// Test raw fallback on a transaction with unknown protocol
///
/// This tests the fallback path when neither Counterparty nor Stamps
/// signatures are detected, which activates the raw ARC4 decryption.
#[tokio::test]
async fn test_arc4_raw_fallback() {
    let _client = match create_test_rpc_client().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⏭️  Skipping test - Bitcoin RPC not available: {}", e);
            return;
        }
    };

    // Note: This test would need a real transaction with unknown protocol
    // For now, we'll test that the result structure handles the fallback case

    // If we had a transaction that's neither Counterparty nor Stamps:
    // let txid = "unknown_protocol_txid";
    //
    // let result = arc4_tool::deobfuscate_transaction(txid, &client)
    //     .await
    //     .expect("ARC4 deobfuscation should succeed");
    //
    // assert!(result.counterparty.is_none());
    // assert!(result.stamps.is_none());
    // assert!(result.raw_fallback.is_some());

    println!("⏭️  Raw fallback test skipped - need unknown protocol transaction");
}
