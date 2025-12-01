//! Stage 3 Counterparty Protocol Classification Tests
//!
//! This test suite validates the Counterparty protocol classification functionality
//! in the Bitcoin P2MS Data-Carrying Protocol Analyser.
//!
//! ## Test Coverage
//!
//! ### Transaction Patterns Tested:
//! - **Modern 1-of-3 Multi-Output**: ARC4 encrypted format (post-2024)
//! - **Legacy 1-of-2 Single Output**: Plaintext format (2014 era)
//! - **Legacy 1-of-2 Multi-Output**: Plaintext format with data spanning multiple outputs
//!
//! ### Message Types Covered:
//! - **Type 0**: Send operations (asset transfers)
//! - **Type 20**: Issuance operations (asset creation, locking, ownership transfer)
//! - **Type 30**: Broadcast operations (data publishing)
//!
//! ### Real Bitcoin Transactions:
//! All tests use authentic Bitcoin mainnet transaction data from JSON fixtures.

use serial_test::serial;

use crate::common::fixture_registry::{self, ProtocolFixture};
use crate::common::protocol_test_base::ProtocolTestBuilder;

/// Run a counterparty test using the unified ProtocolTestBuilder
async fn run_counterparty_fixture_test(fixture: &'static ProtocolFixture) {
    // Counterparty requires inputs for ARC4 key derivation (first input TXID)
    let result = ProtocolTestBuilder::from_fixture(fixture)
        .with_inputs()
        .execute()
        .await;

    if let Err(e) = result {
        panic!("Counterparty test failed: {}", e);
    }
}

/// Modern Counterparty format tests (1-of-3 multi-output)
mod modern_format {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_modern_1of3_multi_output() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::MODERN_1OF3).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_modern_broadcast() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::MODERN_BROADCAST).await;
    }
}

/// Legacy Counterparty format tests (1-of-2)
mod legacy_format {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_legacy_1of2_send() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::LEGACY_1OF2_SEND).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_legacy_1of2_issuance() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::LEGACY_1OF2_ISSUANCE).await;
    }
}

/// Message type specific tests
mod message_types {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_type_0_send() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::TYPE0_SEND).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_type_20_issuance() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::TYPE20_ISSUANCE).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_type_30_broadcast() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::TYPE30_BROADCAST).await;
    }
}

/// Real-world transaction tests using historical data
mod historical_transactions {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_salvation_ownership_transfer() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::SALVATION_TRANSFER).await;
    }
}

/// Subasset and advanced feature tests
mod advanced_features {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_subasset_issuance() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::SUBASSET).await;
    }
}

/// Edge cases and validation tests
mod edge_cases {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_olga_lock() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::OLGA_LOCK).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_mixed_pubkey_format() {
        run_counterparty_fixture_test(&fixture_registry::counterparty::MIXED_PUBKEY_FORMAT).await;
    }
}
