//! Stage 3 AsciiIdentifierProtocols Protocol Classification Tests
//!
//! This test suite validates the AsciiIdentifierProtocols protocol classification functionality
//! for TB0001, TEST01, and Metronotes protocols.
//!
//! ## Test Coverage
//!
//! ### Transaction Patterns Tested:
//! - **TB0001 1-of-2 multisig**: TB0001 signature in second pubkey
//! - **TB0001 1-of-3 multisig**: TB0001 signature in second pubkey
//! - **TEST01 1-of-2 multisig**: TEST01 signature in FIRST pubkey (critical difference!)
//! - **TEST01 1-of-3 multisig**: TEST01 signature in FIRST pubkey
//! - **Metronotes 1-of-2 multisig**: METROXMN signature in second pubkey
//!
//! ### Height-based Filtering:
//! - TB0001: Active from block 357000+ (May 2015)
//! - TEST01: Active blocks 354000-357000 (May 2015)
//! - Metronotes: Active blocks 346000-357000 (March-April 2015)

use data_carry_research::types::{
    EnrichedTransaction, ProtocolType, ProtocolVariant, TransactionOutput,
};
use serial_test::serial;

// Import standardised test utilities
use crate::common::db_seeding::seed_enriched_transaction_simple;
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    run_stage3_processor, setup_protocol_test, verify_classification, verify_stage3_completion,
};

/// AsciiIdentifierProtocols protocol test data helpers
mod test_data {
    use super::*;
    use data_carry_research::types::script_metadata::MultisigInfo;

    /// Create TB0001 1-of-2 multisig transaction
    pub fn create_tb0001_1of2_transaction(txid: &str, height: u32) -> EnrichedTransaction {
        // Create pubkeys with TB0001 signature in second pubkey
        // TB0001 signature: "TB0001" = hex 544230303031
        // Format: 02 + 544230303031 + padding to 33 bytes (compressed pubkey)
        let pubkey1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; // Valid compressed pubkey
        let pubkey2 = format!("02544230303031{}", "00".repeat(20)); // TB0001 signature at bytes 1-7

        let info = MultisigInfo {
            pubkeys: vec![pubkey1.to_string(), pubkey2.to_string()],
            required_sigs: 1,
            total_pubkeys: 2,
        };

        let output = TransactionOutput {
            txid: txid.to_string(),
            vout: 1,
            height,
            amount: 10_000,
            script_hex: "dummy".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(info).unwrap(),
            address: None,
        };

        let mut tx = fixtures::create_test_enriched_transaction(txid);
        tx.outputs = vec![output];
        tx.p2ms_outputs_count = 1;
        tx
    }

    /// Create TB0001 1-of-3 multisig transaction
    pub fn create_tb0001_1of3_transaction(txid: &str, height: u32) -> EnrichedTransaction {
        // TB0001 signature should be in SECOND pubkey (index 1)
        let pubkey1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey2 = format!("02544230303031{}", "00".repeat(20)); // TB0001 signature
        let pubkey3 = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        let info = MultisigInfo {
            pubkeys: vec![
                pubkey1.to_string(),
                pubkey2.to_string(),
                pubkey3.to_string(),
            ],
            required_sigs: 1,
            total_pubkeys: 3,
        };

        let output = TransactionOutput {
            txid: txid.to_string(),
            vout: 1,
            height,
            amount: 10_000,
            script_hex: "dummy".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(info).unwrap(),
            address: None,
        };

        let mut tx = fixtures::create_test_enriched_transaction(txid);
        tx.outputs = vec![output];
        tx.p2ms_outputs_count = 1;
        tx
    }

    /// Create Metronotes 1-of-2 multisig transaction
    pub fn create_metronotes_transaction(txid: &str, height: u32) -> EnrichedTransaction {
        // METROXMN signature: "METROXMN" = hex 4d4554524f584d4e
        let pubkey1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey2 = format!("4d4554524f584d4e{}", "00".repeat(25)); // METROXMN signature

        let info = MultisigInfo {
            pubkeys: vec![pubkey1.to_string(), pubkey2.to_string()],
            required_sigs: 1,
            total_pubkeys: 2,
        };

        let output = TransactionOutput {
            txid: txid.to_string(),
            vout: 0,
            height,
            amount: 10_000,
            script_hex: "dummy".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(info).unwrap(),
            address: None,
        };

        let mut tx = fixtures::create_test_enriched_transaction(txid);
        tx.outputs = vec![output];
        tx.p2ms_outputs_count = 1;
        tx
    }

    /// Create TEST01 1-of-2 multisig transaction
    /// CRITICAL: TEST01 signature is in FIRST pubkey (unlike TB0001 which uses second)
    pub fn create_test01_1of2_transaction(txid: &str, height: u32) -> EnrichedTransaction {
        // TEST01 signature: "TEST01" = hex 544553543031
        // Format: 02 + 544553543031 + padding to 33 bytes (compressed pubkey)
        let pubkey1 = format!("02544553543031{}", "00".repeat(20)); // TEST01 signature at bytes 1-7
        let pubkey2 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; // Valid compressed pubkey

        let info = MultisigInfo {
            pubkeys: vec![pubkey1.to_string(), pubkey2.to_string()],
            required_sigs: 1,
            total_pubkeys: 2,
        };

        let output = TransactionOutput {
            txid: txid.to_string(),
            vout: 1,
            height,
            amount: 10_000,
            script_hex: "dummy".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(info).unwrap(),
            address: None,
        };

        let mut tx = fixtures::create_test_enriched_transaction(txid);
        tx.outputs = vec![output];
        tx.p2ms_outputs_count = 1;
        tx
    }

    /// Create TEST01 1-of-3 multisig transaction
    /// CRITICAL: TEST01 signature is in FIRST pubkey (index 0)
    pub fn create_test01_1of3_transaction(txid: &str, height: u32) -> EnrichedTransaction {
        let pubkey1 = format!("02544553543031{}", "00".repeat(20)); // TEST01 signature in FIRST pubkey
        let pubkey2 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey3 = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

        let info = MultisigInfo {
            pubkeys: vec![
                pubkey1.to_string(),
                pubkey2.to_string(),
                pubkey3.to_string(),
            ],
            required_sigs: 1,
            total_pubkeys: 3,
        };

        let output = TransactionOutput {
            txid: txid.to_string(),
            vout: 1,
            height,
            amount: 10_000,
            script_hex: "dummy".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 100,
            metadata: serde_json::to_value(info).unwrap(),
            address: None,
        };

        let mut tx = fixtures::create_test_enriched_transaction(txid);
        tx.outputs = vec![output];
        tx.p2ms_outputs_count = 1;
        tx
    }

    /// Run AsciiIdentifierProtocols test
    pub async fn run_ascii_identifier_test(
        tx: EnrichedTransaction,
        test_name: &str,
        expected_variant: ProtocolVariant,
    ) -> anyhow::Result<()> {
        let (mut test_db, config) = setup_protocol_test(test_name)?;

        println!("\n╔══════════════════════════════════════════════════════════════");
        println!("║ AsciiIdentifierProtocols Protocol Classification Test");
        println!("╠══════════════════════════════════════════════════════════════");
        println!("║ Test: {}", test_name);
        println!("║ TXID: {}", tx.txid);
        println!("║ Height: {}", tx.height);
        println!("║ Expected Variant: {:?}", expected_variant);
        println!("╟──────────────────────────────────────────────────────────────");

        // Display P2MS outputs
        for (i, output) in tx.outputs.iter().enumerate() {
            println!(
                "║ Output #{} (vout={}, {} pubkeys):",
                i,
                output.vout,
                output.multisig_info().map(|i| i.total_pubkeys).unwrap_or(0)
            );
            if let Some(info) = output.multisig_info() {
                for (j, pubkey) in info.pubkeys.iter().enumerate() {
                    println!("║   Pubkey {}: {}...", j, &pubkey[..20]);

                    // Check for protocol signatures
                    if let Ok(data) = hex::decode(pubkey) {
                        if data.len() >= 7 && &data[1..7] == b"TB0001" {
                            println!("║   ✅ TB0001 signature detected!");
                        }
                        if data.len() >= 7 && &data[1..7] == b"TEST01" {
                            println!("║   ✅ TEST01 signature detected!");
                        }
                        // Check for METROXMN signature
                        if data.windows(8).any(|window| window == b"METROXMN") {
                            println!("║   ✅ METROXMN signature detected!");
                        }
                    }
                }
            }
            println!("║");
        }

        // Seed database via helper to ensure FK-safe Stage 1 + Stage 2 insertion
        seed_enriched_transaction_simple(&mut test_db, &tx, Vec::new())?;

        println!("║ Running Stage 3 Classification...");
        println!("╟──────────────────────────────────────────────────────────────");

        // Run Stage 3
        let results = run_stage3_processor(test_db.path(), config).await?;

        // Verify results
        verify_stage3_completion(&results, 1, 1);

        println!("║ ✅ Classified: {}/{}", results.total_classified, 1);
        println!(
            "║ ASCII ID Protocols: {}",
            results.ascii_identifier_protocols
        );
        println!("║");

        // Verify AsciiIdentifierProtocols classification
        verify_classification(
            &test_db,
            &tx.txid,
            ProtocolType::AsciiIdentifierProtocols,
            Some(expected_variant.clone()),
        )?;

        println!("║ ✅ Protocol: AsciiIdentifierProtocols");
        println!("║ ✅ Variant: {:?}", expected_variant);
        println!("╚══════════════════════════════════════════════════════════════\n");

        Ok(())
    }
}

/// Test TB0001 1-of-2 multisig pattern detection
///
/// **Pattern**: TB0001 signature (hex 544230303031) in second pubkey
/// **Expected Classification**: AsciiIdentifierProtocols / TB0001
#[tokio::test]
#[serial]
async fn test_tb0001_1of2_detection() {
    let tx = test_data::create_tb0001_1of2_transaction(
        "0000000000000000000000000000000000000000000000000000000000000001",
        360_000,
    );

    let result = test_data::run_ascii_identifier_test(
        tx,
        "tb0001_1of2",
        ProtocolVariant::AsciiIdentifierTB0001,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("TB0001 1-of-2 test failed: {}", e);
    }
}

/// Test TB0001 1-of-3 multisig pattern detection
///
/// **Pattern**: TB0001 signature in SECOND pubkey of 1-of-3 multisig
/// **Expected Classification**: AsciiIdentifierProtocols / TB0001
#[tokio::test]
#[serial]
async fn test_tb0001_1of3_detection() {
    let tx = test_data::create_tb0001_1of3_transaction(
        "0000000000000000000000000000000000000000000000000000000000000002",
        360_500,
    );

    let result = test_data::run_ascii_identifier_test(
        tx,
        "tb0001_1of3",
        ProtocolVariant::AsciiIdentifierTB0001,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("TB0001 1-of-3 test failed: {}", e);
    }
}

/// Test Metronotes 1-of-2 multisig pattern detection
///
/// **Pattern**: METROXMN signature (hex 4d4554524f584d4e) in second pubkey
/// **Expected Classification**: AsciiIdentifierProtocols / Metronotes
#[tokio::test]
#[serial]
async fn test_metronotes_detection() {
    let tx = test_data::create_metronotes_transaction(
        "0000000000000000000000000000000000000000000000000000000000000003",
        350_000,
    );

    let result = test_data::run_ascii_identifier_test(
        tx,
        "metronotes",
        ProtocolVariant::AsciiIdentifierMetronotes,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("Metronotes test failed: {}", e);
    }
}

/// Test TEST01 1-of-2 detection
/// CRITICAL: TEST01 signature is in FIRST pubkey (unlike TB0001 which uses second)
#[tokio::test]
#[serial]
async fn test_test01_1of2_detection() {
    let tx = test_data::create_test01_1of2_transaction(
        "0000000000000000000000000000000000000000000000000000000000000006",
        355_000, // Within TEST01 range (354000-357000)
    );

    let result = test_data::run_ascii_identifier_test(
        tx,
        "test01_1of2",
        ProtocolVariant::AsciiIdentifierTEST01,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("TEST01 1-of-2 test failed: {}", e);
    }
}

/// Test TEST01 1-of-3 detection
#[tokio::test]
#[serial]
async fn test_test01_1of3_detection() {
    let tx = test_data::create_test01_1of3_transaction(
        "0000000000000000000000000000000000000000000000000000000000000007",
        356_000, // Within TEST01 range (354000-357000)
    );

    let result = test_data::run_ascii_identifier_test(
        tx,
        "test01_1of3",
        ProtocolVariant::AsciiIdentifierTEST01,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("TEST01 1-of-3 test failed: {}", e);
    }
}

/// Test NEWBCOIN detection with real blockchain data
///
/// **Pattern**: NEWBCOIN signature (hex 4e455742434f494e) in second pubkey
/// **Real TXID**: 9f73c7e16966905530f144fdcdc6be7e426ad1764df95d061710aaf5e7de5812
/// **Expected Classification**: AsciiIdentifierProtocols / AsciiIdentifierOther
#[tokio::test]
#[serial]
async fn test_newbcoin_detection() {
    use crate::common::protocol_test_base::build_transaction_from_script_hex;

    // Real NEWBCOIN script from blockchain
    // TXID: 9f73c7e16966905530f144fdcdc6be7e426ad1764df95d061710aaf5e7de5812
    let script_hex = "512102c0fc0285e4dc4300582ff0f9ff2c72be486ea3f36e68806750d503dedd2490f721164e455742434f494e00000029000000000098968000010000000000000000000052ae";

    let tx = build_transaction_from_script_hex(
        "9f73c7e16966905530f144fdcdc6be7e426ad1764df95d061710aaf5e7de5812",
        script_hex,
    )
    .expect("Failed to build NEWBCOIN transaction");

    let result = test_data::run_ascii_identifier_test(
        tx,
        "newbcoin_detection",
        ProtocolVariant::AsciiIdentifierOther,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("NEWBCOIN detection test failed: {}", e);
    }
}

/// Test PRVCY detection with real blockchain data
///
/// **Pattern**: PRVCY signature (hex 505256435901) in multiple pubkeys
/// **Real TXID**: 42409ab67cd856ecf648e1c63eaff23bf99ad8a5e8793f31812bfa6eb30c6112
/// **Expected Classification**: AsciiIdentifierProtocols / AsciiIdentifierOther
#[tokio::test]
#[serial]
async fn test_prvcy_detection() {
    use crate::common::protocol_test_base::build_transaction_from_script_hex;

    // Real PRVCY script from blockchain (1-of-3 multisig)
    // TXID: 42409ab67cd856ecf648e1c63eaff23bf99ad8a5e8793f31812bfa6eb30c6112
    let script_hex = "51210250525643590100010000000251d75544b04a9471eec80d5c1b8f5e127b0935824104505256435901f094ce936bdef34e1d63109cf3fe8dd21801e4a470309da63dbf3a49955d957900000000000000000000000000000000000000000000000000002103613a80d61c79d4ba7e8704133f63e53435add99275bfd894bab1f700e90dc8fd53ae";

    let tx = build_transaction_from_script_hex(
        "42409ab67cd856ecf648e1c63eaff23bf99ad8a5e8793f31812bfa6eb30c6112",
        script_hex,
    )
    .expect("Failed to build PRVCY transaction");

    let result = test_data::run_ascii_identifier_test(
        tx,
        "prvcy_detection",
        ProtocolVariant::AsciiIdentifierOther,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("PRVCY detection test failed: {}", e);
    }
}

/// Test false positive prevention with allowlist approach
///
/// **Pattern**: ASCII text "FOOBAR" in pubkey (NOT on allowlist)
/// **Expected Classification**: Should NOT match AsciiIdentifierOther
#[tokio::test]
#[serial]
async fn test_ascii_identifier_false_positive() {
    use crate::common::protocol_test_base::{build_fake_ascii_tx, setup_protocol_test};

    let tx = build_fake_ascii_tx(
        "0000000000000000000000000000000000000000000000000000000000000099",
        "FOOBAR",
    )
    .expect("Failed to build fake ASCII tx");

    let (mut test_db, config) =
        setup_protocol_test("ascii_false_positive").expect("Failed to setup test");

    println!("\n╔══════════════════════════════════════════════════════════════");
    println!("║ AsciiIdentifierProtocols False Positive Test");
    println!("╠══════════════════════════════════════════════════════════════");
    println!("║ Test: ascii_false_positive");
    println!("║ TXID: {}", tx.txid);
    println!("║ ASCII Text: FOOBAR (NOT on allowlist)");
    println!("║ Expected: Should NOT match AsciiIdentifierOther");
    println!("╟──────────────────────────────────────────────────────────────");

    seed_enriched_transaction_simple(&mut test_db, &tx, Vec::new())
        .expect("Failed to seed transaction");

    println!("║ Running Stage 3 Classification...");
    println!("╟──────────────────────────────────────────────────────────────");

    // Run Stage 3
    use crate::common::protocol_test_base::run_stage3_processor;
    let results = run_stage3_processor(test_db.path(), config)
        .await
        .expect("Stage 3 processing failed");

    println!("║ ✅ Classified: {}", results.total_classified);
    println!(
        "║ ASCII ID Protocols: {}",
        results.ascii_identifier_protocols
    );
    println!("║");

    // Verify it was NOT classified as AsciiIdentifierProtocols
    if results.ascii_identifier_protocols > 0 {
        panic!(
            "❌ False positive! FOOBAR was classified as AsciiIdentifierOther, but it's not on the allowlist"
        );
    }

    // Should be classified as something else (likely DataStorage or Unknown)
    assert!(
        results.total_classified > 0,
        "Transaction should still be classified (just not as AsciiIdentifierOther)"
    );

    println!("║ ✅ False positive test passed!");
    println!("║ ✅ Allowlist approach prevented FOOBAR from matching");
    println!("╚══════════════════════════════════════════════════════════════\n");
}

/// Test TB0001 detection in FIRST pubkey position (edge case)
///
/// **Pattern**: TB0001 signature (hex 544230303031) in FIRST pubkey (not second)
/// **Real TXID**: 67792f9c87eb1632408bc537c42517c98c5218216df8f2d295eb17d617eb2006
/// **Expected Classification**: AsciiIdentifierProtocols / TB0001
/// **Note**: Most TB0001 transactions have signature in second pubkey, this tests first position
#[tokio::test]
#[serial]
async fn test_tb0001_first_pubkey_edge_case() {
    use crate::common::protocol_test_base::build_transaction_from_script_hex;

    // Real TB0001 script with signature in FIRST pubkey (vout 0)
    // TXID: 67792f9c87eb1632408bc537c42517c98c5218216df8f2d295eb17d617eb2006
    let script_hex = "5121025442303030310010f06710cb9e9eebbd325bd4a2e9299fc300000000000000122103b23751bb95b2559c816c8f01ddd5abf5104a5039da91c01317296fe1746ac73a52ae";

    let tx = build_transaction_from_script_hex(
        "67792f9c87eb1632408bc537c42517c98c5218216df8f2d295eb17d617eb2006",
        script_hex,
    )
    .expect("Failed to build TB0001 first-pubkey transaction");

    let result = test_data::run_ascii_identifier_test(
        tx,
        "tb0001_first_pubkey",
        ProtocolVariant::AsciiIdentifierTB0001,
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("TB0001 first-pubkey edge case test failed: {}", e);
    }
}
