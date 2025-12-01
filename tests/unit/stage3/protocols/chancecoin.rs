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

use serial_test::serial;

// Import standardised test utilities
use crate::common::fixture_registry::{self, ProtocolFixture};
use crate::common::protocol_test_base::ProtocolTestBuilder;

/// Run a chancecoin test using the unified ProtocolTestBuilder
async fn run_chancecoin_fixture_test(fixture: &'static ProtocolFixture) {
    // Chancecoin tests don't need content_type verification (variant is None in fixtures)
    let result = ProtocolTestBuilder::from_fixture(fixture)
        .skip_content_type()
        .execute()
        .await;

    if let Err(e) = result {
        panic!("Chancecoin test failed: {}", e);
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
