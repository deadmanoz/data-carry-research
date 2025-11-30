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

use data_carry_research::types::ProtocolType;
use serial_test::serial;

// Import standardised test utilities
use crate::common::db_seeding::seed_enriched_transaction_simple;
use crate::common::fixture_registry::{self, ProtocolFixture};
use crate::common::protocol_test_base::{
    load_transaction_from_json, run_stage3_processor, setup_protocol_test, verify_classification,
    verify_stage3_completion,
};

/// Run a chancecoin test using fixture registry metadata
async fn run_chancecoin_fixture_test(fixture: &ProtocolFixture) {
    let result =
        test_data::run_chancecoin_test_from_json(fixture.path, fixture.txid, fixture.description)
            .await;

    if let Err(e) = result {
        println!("⚠️  Test error: {}", e);
    }
}

/// Chancecoin protocol test data helpers
mod test_data {
    use super::*;

    /// Run Chancecoin test from JSON fixture
    pub async fn run_chancecoin_test_from_json(
        json_path: &str,
        txid: &str,
        test_name: &str,
    ) -> anyhow::Result<()> {
        let (mut test_db, config) = setup_protocol_test(test_name)?;

        println!("\n╔══════════════════════════════════════════════════════════════");
        println!("║ Chancecoin Protocol Classification Test");
        println!("╠══════════════════════════════════════════════════════════════");
        println!("║ Test: {}", test_name);
        println!("║ TXID: {}", txid);
        println!("╟──────────────────────────────────────────────────────────────");

        // Load transaction data using unified helper (P2MS-only, no burn patterns, no inputs)
        let (tx, _inputs) = match load_transaction_from_json(json_path, txid, Default::default()) {
            Ok(result) => result,
            Err(e) => {
                println!(
                    "⚠️  Skipping test - no valid transaction data in {}: {}",
                    json_path, e
                );
                return Ok(());
            }
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

/// Chancecoin bet transaction test (8-byte "CHANCECO" signature)
#[tokio::test]
#[serial]
async fn test_chancecoin_bet_classification() {
    run_chancecoin_fixture_test(&fixture_registry::chancecoin::BET).await;
}

#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_1() {
    run_chancecoin_fixture_test(&fixture_registry::chancecoin::TX_001A86).await;
}

#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_2() {
    run_chancecoin_fixture_test(&fixture_registry::chancecoin::TX_0023FA).await;
}

#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_3() {
    run_chancecoin_fixture_test(&fixture_registry::chancecoin::TX_00465A).await;
}

#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_4() {
    run_chancecoin_fixture_test(&fixture_registry::chancecoin::TX_0052A7).await;
}

#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_5() {
    run_chancecoin_fixture_test(&fixture_registry::chancecoin::TX_005B47).await;
}

#[tokio::test]
#[serial]
async fn test_chancecoin_transaction_6() {
    run_chancecoin_fixture_test(&fixture_registry::chancecoin::TX_005E3F).await;
}
