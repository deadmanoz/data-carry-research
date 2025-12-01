//! Stage 3 Omni Layer Protocol Classification Tests
//!
//! This test suite comprehensively validates the Omni Layer Class B (P2MS) protocol classification
//! functionality in the Bitcoin P2MS Data-Carrying Protocol Analyser. It focuses specifically on
//! Omni transactions that use Pay-to-Multisig encoding with SHA256-based obfuscation.
//!
//! ## Test Data Provenance
//!
//! **All transaction data sourced from authoritative Omni Layer repositories:**
//! - **OmniEngine**: Reference implementation transaction examples (tx.example)
//!   - Source: https://github.com/OmniLayer/omniengine
//!   - Contains verified mainnet transactions with message type classifications
//! - **OmniExplorer**: Block explorer API data validation
//!   - Source: https://github.com/OmniLayer/omniexplorer
//!   - Cross-referenced for transaction details and block heights
//! - **Bitcoin Core RPC**: Direct blockchain verification
//!   - All block heights verified against actual Bitcoin blockchain
//!   - Transaction existence confirmed via getrawtransaction calls
//!
//! ## Test Coverage
//!
//! ### Transaction Patterns Tested:
//! - **Class B P2MS**: SHA256 deobfuscated format (primary Omni method)
//! - **Exodus Address Validation**: Mandatory output to 1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P
//! - **Multi-Packet Data**: Large payloads across multiple P2MS outputs with sequence ordering
//! - **Sender Address Resolution**: P2PKH address derivation for deobfuscation keys
//!
//! ### Message Types Covered:
//! - **Type 0**: Simple Send (USDT and other token transfers)
//! - **Type 3**: Send To Owners (dividend distributions)
//! - **Type 20**: DEX Trade Offers
//! - **Type 25**: DEX Payments
//! - **Type 50/51**: Property Creation (token issuance)
//! - **Type 53**: Close Crowdsale
//! - **Type 55**: Grant Property Tokens
//!
//! ### Real Bitcoin Transactions:
//! All tests use authentic Bitcoin mainnet transaction data from the 320000s block height range,
//! ensuring validation against real-world Omni Layer protocol usage during the protocol's
//! active period.

use serial_test::serial;

use crate::common::fixture_registry::{self, ProtocolFixture};
use crate::common::protocol_test_base::ProtocolTestBuilder;

/// Run an Omni test using the unified ProtocolTestBuilder
async fn run_omni_fixture_test(fixture: &'static ProtocolFixture) {
    // Omni requires inputs for SHA256 deobfuscation (sender address)
    // Omni requires all outputs for Exodus address detection
    let result = ProtocolTestBuilder::from_fixture(fixture)
        .with_inputs()
        .with_all_outputs()
        .execute()
        .await;

    if let Err(e) = result {
        panic!("Omni test failed: {}", e);
    }
}

/// Framework validation tests
mod framework_validation {
    use data_carry_research::types::omni::{OmniMessageType, OmniP2msData, OmniPacket};
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_omni_framework_validation() {
        let test_packet = OmniPacket {
            vout: 0,
            position: 2,
            sequence_number: 1,
            obfuscated_data: [0u8; 31],
            deobfuscated_data: None,
        };

        let _test_data = OmniP2msData {
            raw_packets: vec![test_packet],
            deobfuscated_data: vec![0, 0, 0, 0],
            sender_address: "1TestSenderAddress".to_string(),
            message_type: OmniMessageType::SimpleSend,
            payload: Vec::new(),
            total_packets: 1,
        };

        assert_eq!(
            OmniMessageType::from_u32(0),
            Some(OmniMessageType::SimpleSend)
        );
        assert_eq!(
            OmniMessageType::from_u32(3),
            Some(OmniMessageType::SendToOwners)
        );
        assert_eq!(
            OmniMessageType::from_u32(20),
            Some(OmniMessageType::TradeOffer)
        );
        assert_eq!(
            OmniMessageType::from_u32(50),
            Some(OmniMessageType::CreatePropertyFixed)
        );
    }

    #[test]
    #[serial]
    fn test_omni_message_type_variants() {
        let test_cases = vec![
            (0, Some(OmniMessageType::SimpleSend)),
            (3, Some(OmniMessageType::SendToOwners)),
            (20, Some(OmniMessageType::TradeOffer)),
            (50, Some(OmniMessageType::CreatePropertyFixed)),
            (51, Some(OmniMessageType::CreatePropertyVariable)),
            (999, None),
        ];

        for (input, expected) in test_cases {
            assert_eq!(OmniMessageType::from_u32(input), expected);
        }
    }
}

/// Simple Send transaction tests (Type 0)
mod simple_send {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_omni_usdt_grant_tokens() {
        run_omni_fixture_test(&fixture_registry::omni::USDT_GRANT_TOKENS).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_dex_sell_offer_cancel() {
        run_omni_fixture_test(&fixture_registry::omni::DEX_SELL_OFFER_CANCEL).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_multi_packet_transaction() {
        run_omni_fixture_test(&fixture_registry::omni::MULTI_PACKET).await;
    }
}

/// Send To Owners transaction tests (Type 3)
mod send_to_owners {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_omni_send_to_owners() {
        run_omni_fixture_test(&fixture_registry::omni::SEND_TO_OWNERS).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_close_crowdsale() {
        run_omni_fixture_test(&fixture_registry::omni::CLOSE_CROWDSALE).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_crowdsale_participation_1() {
        run_omni_fixture_test(&fixture_registry::omni::CROWDSALE_PARTICIPATION_1).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_crowdsale_participation_2() {
        run_omni_fixture_test(&fixture_registry::omni::CROWDSALE_PARTICIPATION_2).await;
    }
}

/// Trade Offer transaction tests (Type 20)
mod trade_offers {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_omni_manual_property_creation() {
        run_omni_fixture_test(&fixture_registry::omni::MANUAL_PROPERTY_CREATION).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_revoke_property_tokens() {
        run_omni_fixture_test(&fixture_registry::omni::REVOKE_PROPERTY_TOKENS).await;
    }
}

/// Property Creation transaction tests (Type 50/51)
mod property_creation {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_omni_crowdsale_creation() {
        run_omni_fixture_test(&fixture_registry::omni::CROWDSALE_CREATION).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_fixed_property_creation() {
        run_omni_fixture_test(&fixture_registry::omni::PROPERTY_FIXED).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_variable_property_creation() {
        run_omni_fixture_test(&fixture_registry::omni::VARIABLE_PROPERTY_CREATION).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_dex_sell_offer_2() {
        run_omni_fixture_test(&fixture_registry::omni::DEX_SELL_OFFER_2).await;
    }
}

/// Historical transaction tests using real mainnet data
mod historical_transactions {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_omni_fixed_property_creation_2() {
        run_omni_fixture_test(&fixture_registry::omni::FIXED_PROPERTY_CREATION_2).await;
    }
}

/// Edge cases and validation tests
mod edge_cases {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_omni_dex_accept_offer() {
        run_omni_fixture_test(&fixture_registry::omni::DEX_ACCEPT_OFFER).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_omni_deobfuscation_failure() {
        run_omni_fixture_test(&fixture_registry::omni::DEOBFUSCATION_FAIL).await;
    }
}
