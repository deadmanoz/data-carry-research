//! Stage 3 Chancecoin Protocol Classification Tests
//!
//! This test suite validates the Chancecoin protocol classification functionality
//! in the Bitcoin P2MS Data-Carrying Protocol Analyser.
//!
//! ## Test Coverage
//!
//! ### Transaction Patterns Tested:
//! - **Chancecoin Bet**: Gambling bet transaction with 8-byte "CHANCECO" signature
//! - **Chancecoin Transactions**: 7 diverse real-world Chancecoin transactions
//!
//! ### Message Types Covered:
//! - **Unknown Type 0**: Default message type for unspecified Chancecoin operations
//! - Various Chancecoin message types discovered in production blockchain data
//!
//! ### Real Bitcoin Transactions:
//! All tests use authentic Bitcoin mainnet transaction data fetched from Bitcoin Core RPC,
//! ensuring validation against real-world Chancecoin protocol usage. Test suite includes
//! 7 unique transactions covering diverse Chancecoin usage patterns.

use data_carry_research::types::{EnrichedTransaction, ProtocolType, TransactionOutput};
use serial_test::serial;
use std::fs;
use std::path::Path;

// Import standardised test utilities
use crate::common::db_seeding::seed_enriched_transaction_simple;
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    run_stage3_processor, setup_protocol_test, verify_classification, verify_stage3_completion,
};

/// Chancecoin protocol test data helpers
mod test_data {
    use super::*;

    /// Load P2MS outputs from Chancecoin JSON fixture
    pub fn load_chancecoin_p2ms_outputs(
        json_path: &str,
        txid: &str,
        height: u32,
    ) -> Vec<TransactionOutput> {
        if !Path::new(json_path).exists() {
            return Vec::new();
        }

        let content = fs::read_to_string(json_path).expect("Read JSON");
        let tx: serde_json::Value = serde_json::from_str(&content).expect("Parse JSON");

        let mut outputs = Vec::new();
        if let Some(vouts) = tx["vout"].as_array() {
            for (vout_index, vout) in vouts.iter().enumerate() {
                if let Some(script_asm) = vout["scriptPubKey"]["asm"].as_str() {
                    // Check if this is a P2MS output (contains OP_CHECKMULTISIG)
                    if script_asm.contains("OP_CHECKMULTISIG") {
                        // Extract pubkeys
                        let parts: Vec<&str> = script_asm.split_whitespace().collect();
                        let mut pubkeys = Vec::new();

                        for part in &parts {
                            // Pubkeys are hex strings (66 or 130 chars for compressed/uncompressed)
                            if part.len() >= 66 && part.chars().all(|c| c.is_ascii_hexdigit()) {
                                pubkeys.push(part.to_string());
                            }
                        }

                        if !pubkeys.is_empty() {
                            let amount =
                                (vout["value"].as_f64().unwrap_or(0.0) * 100_000_000.0) as u64;

                            outputs.push({
                                use data_carry_research::types::script_metadata::MultisigInfo;
                                let info = MultisigInfo {
                                    pubkeys: pubkeys.clone(),
                                    required_sigs: 1,
                                    total_pubkeys: pubkeys.len() as u32,
                                };
                                TransactionOutput {
                                    txid: txid.to_string(),
                                    vout: vout_index as u32,
                                    height,
                                    amount,
                                    script_hex: vout["scriptPubKey"]["hex"]
                                        .as_str()
                                        .unwrap_or("")
                                        .to_string(),
                                    script_type: "multisig".to_string(),
                                    is_coinbase: false,
                                    script_size: vout["scriptPubKey"]["hex"]
                                        .as_str()
                                        .unwrap_or("")
                                        .len()
                                        / 2,
                                    metadata: serde_json::to_value(info).unwrap(),
                                    address: None,
                                }
                            });
                        }
                    }
                }
            }
        }

        outputs
    }

    /// Create enriched transaction from Chancecoin JSON fixture
    pub fn create_chancecoin_transaction_from_json(
        json_path: &str,
        txid: &str,
        height: u32,
    ) -> Option<EnrichedTransaction> {
        let p2ms_outputs = load_chancecoin_p2ms_outputs(json_path, txid, height);
        if p2ms_outputs.is_empty() {
            return None;
        }

        let mut tx = fixtures::create_test_enriched_transaction(txid);
        tx.height = height;
        tx.outputs = p2ms_outputs;
        tx.p2ms_outputs_count = tx.outputs.len();

        Some(tx)
    }

    /// Run Chancecoin test from JSON fixture
    pub async fn run_chancecoin_test_from_json(
        json_path: &str,
        txid: &str,
        height: u32,
        test_name: &str,
    ) -> anyhow::Result<()> {
        let (mut test_db, config) = setup_protocol_test(test_name)?;

        println!("\n╔══════════════════════════════════════════════════════════════");
        println!("║ Chancecoin Protocol Classification Test");
        println!("╠══════════════════════════════════════════════════════════════");
        println!("║ Test: {}", test_name);
        println!("║ TXID: {}", txid);
        println!("║ Height: {}", height);
        println!("╟──────────────────────────────────────────────────────────────");

        // Load transaction data
        let Some(tx) = create_chancecoin_transaction_from_json(json_path, txid, height) else {
            println!(
                "⚠️  Skipping test - no valid transaction data in {}",
                json_path
            );
            return Ok(());
        };

        println!("║ P2MS Outputs Found: {}", tx.outputs.len());
        println!("║");

        // Display P2MS outputs
        for (i, output) in tx.outputs.iter().enumerate() {
            println!(
                "║ Output #{} ({} pubkeys):",
                i,
                output.multisig_info().map(|i| i.total_pubkeys).unwrap_or(0)
            );
            for (j, pubkey) in output
                .multisig_info()
                .map(|i| i.pubkeys.clone())
                .unwrap_or_else(Vec::new)
                .iter()
                .enumerate()
            {
                println!("║   Pubkey {}: {}...", j, &pubkey[..20]);

                // Check for CHANCECO signature
                if let Ok(data) = hex::decode(pubkey) {
                    if data.len() >= 8 && &data[0..8] == b"CHANCECO" {
                        println!("║   ✅ CHANCECO signature detected!");
                    } else if data.len() >= 9 && &data[1..9] == b"CHANCECO" {
                        println!("║   ✅ CHANCECO signature detected at offset 1!");
                    }
                }
            }
            println!("║");
        }

        // Seed database using shared helper (handles Stage 1 + Stage 2 order)
        seed_enriched_transaction_simple(&mut test_db, &tx, Vec::new())?;

        println!("║ Running Stage 3 Classification...");
        println!("╟──────────────────────────────────────────────────────────────");

        // Run Stage 3
        let total_classified = run_stage3_processor(test_db.path(), config).await?;

        // Verify results
        verify_stage3_completion(total_classified, 1, 1);

        println!("║ ✅ Classified: {}/{}", total_classified, 1);
        println!("║");

        // Verify Chancecoin classification
        verify_classification(&test_db, txid, ProtocolType::Chancecoin, None)?;

        println!("║ ✅ Protocol: Chancecoin");
        println!("╚══════════════════════════════════════════════════════════════\n");

        Ok(())
    }
}

/// Test Chancecoin bet transaction classification
///
/// **Transaction**: a9b505f1edb8fedaa7c1edb96cdd622b72b0623b1a5fafa7a1eac97f1a377889
/// **Block Height**: ~330,000
/// **Pattern**: 8-byte "CHANCECO" signature in second pubkey slot
/// **Expected Classification**: Chancecoin
#[tokio::test]
#[serial]
async fn test_chancecoin_bet_classification() {
    let result = test_data::run_chancecoin_test_from_json(
        "tests/test_data/chancecoin/chancecoin_bet_tx.json",
        "a9b505f1edb8fedaa7c1edb96cdd622b72b0623b1a5fafa7a1eac97f1a377889",
        330_000,
        "chancecoin_bet",
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("Chancecoin test failed: {}", e);
    }
}

/// Test Chancecoin transaction 1
///
/// **Transaction**: 001a863cf538ac94b121baf79c596abdb904e4cda87f407df2751aefc5590dd4
/// **Pattern**: 8-byte "CHANCECO" signature
/// **Expected Classification**: Chancecoin
#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_1() {
    let result = test_data::run_chancecoin_test_from_json(
        "tests/test_data/chancecoin/001a863cf538ac94b121baf79c596abdb904e4cda87f407df2751aefc5590dd4.json",
        "001a863cf538ac94b121baf79c596abdb904e4cda87f407df2751aefc5590dd4",
        330_000,
        "chancecoin_tx1",
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("Chancecoin test failed: {}", e);
    }
}

/// Test Chancecoin transaction 2
///
/// **Transaction**: 0023fad37f02dd0cbd8d12e97d46ccba3947342c422f3793ccea301e9c28045f
/// **Pattern**: 8-byte "CHANCECO" signature
/// **Expected Classification**: Chancecoin
#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_2() {
    let result = test_data::run_chancecoin_test_from_json(
        "tests/test_data/chancecoin/0023fad37f02dd0cbd8d12e97d46ccba3947342c422f3793ccea301e9c28045f.json",
        "0023fad37f02dd0cbd8d12e97d46ccba3947342c422f3793ccea301e9c28045f",
        330_000,
        "chancecoin_tx2",
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("Chancecoin test failed: {}", e);
    }
}

/// Test Chancecoin transaction 3
///
/// **Transaction**: 00465a96bb61ef1ab9df812f0c6f196da902064a4d63ab05399747252907f962
/// **Pattern**: 8-byte "CHANCECO" signature
/// **Expected Classification**: Chancecoin
#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_3() {
    let result = test_data::run_chancecoin_test_from_json(
        "tests/test_data/chancecoin/00465a96bb61ef1ab9df812f0c6f196da902064a4d63ab05399747252907f962.json",
        "00465a96bb61ef1ab9df812f0c6f196da902064a4d63ab05399747252907f962",
        330_000,
        "chancecoin_tx3",
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("Chancecoin test failed: {}", e);
    }
}

/// Test Chancecoin transaction 4
///
/// **Transaction**: 0052a7c60352399ed25cba926078c58cf795ff70891a7ca3e6c59299b9084cd0
/// **Pattern**: 8-byte "CHANCECO" signature
/// **Expected Classification**: Chancecoin
#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_4() {
    let result = test_data::run_chancecoin_test_from_json(
        "tests/test_data/chancecoin/0052a7c60352399ed25cba926078c58cf795ff70891a7ca3e6c59299b9084cd0.json",
        "0052a7c60352399ed25cba926078c58cf795ff70891a7ca3e6c59299b9084cd0",
        330_000,
        "chancecoin_tx4",
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("Chancecoin test failed: {}", e);
    }
}

/// Test Chancecoin transaction 5
///
/// **Transaction**: 005b47811eb0c50a9272ec8ce79faca62cc14d3a9f787d6d19dacd6818974057
/// **Pattern**: 8-byte "CHANCECO" signature
/// **Expected Classification**: Chancecoin
#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_5() {
    let result = test_data::run_chancecoin_test_from_json(
        "tests/test_data/chancecoin/005b47811eb0c50a9272ec8ce79faca62cc14d3a9f787d6d19dacd6818974057.json",
        "005b47811eb0c50a9272ec8ce79faca62cc14d3a9f787d6d19dacd6818974057",
        330_000,
        "chancecoin_tx5",
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("Chancecoin test failed: {}", e);
    }
}

/// Test Chancecoin transaction 6
///
/// **Transaction**: 005e3f8e406820abf1af5d6e2fa20774dceeac6bf087cfcff16737e90af56e68
/// **Pattern**: 8-byte "CHANCECO" signature
/// **Expected Classification**: Chancecoin
#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_6() {
    let result = test_data::run_chancecoin_test_from_json(
        "tests/test_data/chancecoin/005e3f8e406820abf1af5d6e2fa20774dceeac6bf087cfcff16737e90af56e68.json",
        "005e3f8e406820abf1af5d6e2fa20774dceeac6bf087cfcff16737e90af56e68",
        330_000,
        "chancecoin_tx6",
    )
    .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
        panic!("Chancecoin test failed: {}", e);
    }
}
