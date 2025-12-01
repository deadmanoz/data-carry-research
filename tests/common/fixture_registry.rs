//! Fixture Registry for Protocol Classification Tests
//!
//! Centralised registry of all protocol test fixtures with metadata.
//! This enables the `ProtocolTestBuilder` pattern and ensures consistent
//! fixture management across all protocol tests.
//!
//! # Design Rationale
//!
//! Each fixture constant captures:
//! - File path (relative to project root)
//! - Transaction ID (for ARC4 key derivation, deobfuscation, etc.)
//! - Expected protocol classification
//! - Expected variant (if applicable)
//! - Expected content type (if applicable)
//! - Input fixture path (for Omni deobfuscation)
//! - Description for test documentation
//!
//! # Usage
//!
//! ```rust
//! use crate::common::fixture_registry::stamps;
//!
//! let fixture = &stamps::SRC20_DEPLOY;
//! assert_eq!(fixture.protocol, ProtocolType::BitcoinStamps);
//! ```

use data_carry_research::types::ProtocolType;

/// Metadata for a protocol test fixture
#[derive(Debug, Clone)]
pub struct ProtocolFixture {
    /// Path to the fixture JSON file (relative to project root)
    pub path: &'static str,
    /// Transaction ID
    pub txid: &'static str,
    /// Expected protocol classification
    pub protocol: ProtocolType,
    /// Expected protocol variant (e.g., "StampsSRC20", "CounterpartyIssuance")
    pub variant: Option<&'static str>,
    /// Expected content type (e.g., "application/json", "image/png")
    pub content_type: Option<&'static str>,
    /// Path to input fixture (for Omni deobfuscation) - contains first input txid
    pub input_fixture_path: Option<&'static str>,
    /// Human-readable description for test documentation
    pub description: &'static str,
}

impl ProtocolFixture {
    /// Check if this fixture requires input fixtures for deobfuscation
    pub fn requires_inputs(&self) -> bool {
        self.input_fixture_path.is_some()
    }
}

/// Bitcoin Stamps protocol fixtures
pub mod stamps {
    use super::*;

    pub const SRC20_DEPLOY: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_src20_deploy_tx.json",
        txid: "0d5a0c9f4e29646d2dbafab12aaad8465f9e2dc637697ef83899f9d7086cc56b",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsSRC20"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "SRC-20 token deployment",
    };

    pub const SRC20_MINT: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_src20_mint_tx.json",
        txid: "64ca6c21ff26401bafd2af4902157c1f3eef25bbb027a427250e39d552d86755",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsSRC20"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "SRC-20 token minting",
    };

    pub const SRC20_TRANSFER: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_src20_transfer_tx.json",
        txid: "bddb00f8877af253283de07abc28597b855bf820b170ffc091da0faac5abf415",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsSRC20"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "SRC-20 token transfer",
    };

    pub const CLASSIC_4D89D7: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_classic_4d89d7.json",
        txid: "4d89d7f69ee77c3ddda041f94270b4112d002fc67b88008f29710fadfb486da8",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsSRC20"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "SRC-20 JSON stamp",
    };

    pub const RECENT_C8C383: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_recent_c8c383.json",
        txid: "3809059d32b51e3c2e680c6ffbd8e15e152daa06554f62fc1b9f2aea3be39e32",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsSRC20"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "SRC-20 stamp with recent multisig format",
    };

    pub const ORIGINAL_IMAGE: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_original_image.json",
        txid: "56bba57e6405e553cfff1b78ab8f7f0f0f419c5056c06b72a81e0e5deae48d15",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsSRC20"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "SRC-20 stamp",
    };

    pub const CLASSIC_F35382: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_classic_f35382.json",
        txid: "f353823cdc63ee24fe2167ca14d3bb9b6a54dd063b53382c0cd42f05d7262808",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsSRC20"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "SRC-20 stamp from May 2023",
    };

    pub const TRANSFER_934DC3: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_transfer_934dc3.json",
        txid: "934dc31e690d0237d8d0d6a69355a7448920dbd12ff21abf694af48cfb30d715",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsClassic"),
        content_type: Some("image/png"),
        input_fixture_path: None,
        description: "Transfer conflict scenario with PNG image",
    };

    pub const MALFORMED_E2AA45: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/stamps/stamps_malformed_e2aa45.json",
        txid: "e2aa459ebfe0ba3625c917143452678a3e80636489fe0ec8cc7e9651cfd4ddb2",
        protocol: ProtocolType::BitcoinStamps,
        variant: Some("StampsSRC20"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "Malformed SRC-20 data handling",
    };

    /// Returns all stamps fixtures for iteration
    pub fn all() -> Vec<&'static ProtocolFixture> {
        vec![
            &SRC20_DEPLOY,
            &SRC20_MINT,
            &SRC20_TRANSFER,
            &CLASSIC_4D89D7,
            &RECENT_C8C383,
            &ORIGINAL_IMAGE,
            &CLASSIC_F35382,
            &TRANSFER_934DC3,
            &MALFORMED_E2AA45,
        ]
    }
}

/// Counterparty protocol fixtures
pub mod counterparty {
    use super::*;

    pub const MODERN_1OF3: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_modern_1of3_tx.json",
        txid: "a63ee2b1e64d98784ba39c9e6738bc923fd88a808d618dd833254978247d66ea",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Modern 1-of-3 multi-output format (Type 22)",
    };

    pub const MODERN_BROADCAST: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_modern_broadcast_tx.json",
        txid: "21c2cd5b369c2e7a350bf92ad43c31e5abb0aa85ccba11368b08f9f4abb8e0af",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyOracle"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Modern broadcast transaction (Type 30)",
    };

    pub const LEGACY_1OF2_SEND: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_legacy_1of2_send_tx.json",
        txid: "da3ed1efda82824cb24ea081ef2a8f532a7dd9cd1ebc5efa873498c3958c864e",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyTransfer"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Legacy 1-of-2 plaintext send (Type 0)",
    };

    pub const LEGACY_1OF2_ISSUANCE: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_legacy_1of2_issuance_tx.json",
        txid: "e5e9f6a63ede5315994cf2d8a5f8fe760f1f37f6261e5fbb1263bed54114768a",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Legacy 1-of-2 plaintext issuance (Type 20)",
    };

    pub const TYPE0_SEND: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_type0_send_tx.json",
        txid: "585f50f12288cd9044705483672fbbddb71dff8198b390b40ab3de30db0a88dd",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyTransfer"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Type 0 send operation",
    };

    pub const TYPE20_ISSUANCE: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_type20_issuance_tx.json",
        txid: "31a96a3bd86600b4af3c81bc960b15e89e506f855e93fbbda6f701963b1936ac",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Type 20 issuance with STAMP image",
    };

    pub const TYPE30_BROADCAST: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_type30_broadcast_tx.json",
        txid: "627ae48d6b4cffb2ea734be1016dedef4cee3f8ffefaea5602dd58c696de6b74",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyOracle"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Type 30 broadcast with OLGA image",
    };

    pub const SALVATION_TRANSFER: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_salvation_transfer_tx.json",
        txid: "541e640fbb527c35e0ee32d724efa4a5506c4c52acfba1ebc3b45949780c08a8",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Ownership transfer (Type 20)",
    };

    pub const SUBASSET: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_subasset_tx.json",
        txid: "793566ef1644a14c2658aed6b3c2df41bc519941f121f9cff82825f48911e451",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Subasset issuance (Type 21)",
    };

    pub const OLGA_LOCK: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/counterparty_olga_lock_tx.json",
        txid: "34da6ecf10c66ed659054aa6c71900c807875cb57b96abea4cee4f7a831ed690",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Asset locking (Type 20)",
    };

    pub const MIXED_PUBKEY_FORMAT: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/counterparty/9b4afd1d54dc88b50dbda166e837fb4ce110f4185b432c6155a403ca0fb2eb75.json",
        txid: "9b4afd1d54dc88b50dbda166e837fb4ce110f4185b432c6155a403ca0fb2eb75",
        protocol: ProtocolType::Counterparty,
        variant: Some("CounterpartyOracle"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Mixed compressed-uncompressed pubkeys (Type 30)",
    };

    /// Returns all counterparty fixtures for iteration
    pub fn all() -> Vec<&'static ProtocolFixture> {
        vec![
            &MODERN_1OF3,
            &MODERN_BROADCAST,
            &LEGACY_1OF2_SEND,
            &LEGACY_1OF2_ISSUANCE,
            &TYPE0_SEND,
            &TYPE20_ISSUANCE,
            &TYPE30_BROADCAST,
            &SALVATION_TRANSFER,
            &SUBASSET,
            &OLGA_LOCK,
            &MIXED_PUBKEY_FORMAT,
        ]
    }
}

/// Omni Layer protocol fixtures
pub mod omni {
    use super::*;

    pub const USDT_GRANT_TOKENS: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_usdt_grant_tokens_tx.json",
        txid: "1caf0432ef165b19d5b5d726dc7fd1461390283c15bade2c9683fd712099e53b",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "USDT grant tokens (Type 55)",
    };

    pub const DEX_SELL_OFFER_CANCEL: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_dex_sell_offer_cancel_tx.json",
        txid: "f706f60ff3f8cfb4161e9135af82d432f5bc588cae77dfdfedde011ec8baf287",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniDEX"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "DEX sell offer cancel (Type 20)",
    };

    pub const SEND_TO_OWNERS: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_send_to_owners_0937f1.json",
        txid: "0937f1627f7c8663bbc59c7e8f2c7e039c067c659fa5e5a0e0ee7f9f96bb27f1",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniDistribution"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Send to owners dividend (Type 3)",
    };

    pub const CLOSE_CROWDSALE: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_close_crowdsale_tx.json",
        txid: "b8864525a2eef4f76a58f33a4af50dc24461445e1a420e21bcc99a1901740e79",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniAdministration"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Close crowdsale (Type 53)",
    };

    pub const CROWDSALE_PARTICIPATION_1: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_crowdsale_participation_tx.json",
        txid: "c1ff92f278432d6e14e08ab60f2dceab4d8b4396b4d7e62b5b10e88e840b39d4",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniTransfer"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Crowdsale participation (Type 0)",
    };

    pub const CROWDSALE_PARTICIPATION_2: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_crowdsale_participation_8fbd96.json",
        txid: "8fbd9600ae1b3cc96406e983d7bbc017a0f2cf99f6e32a3ffd5a88ee9b39ebe2",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniTransfer"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Crowdsale participation 2 (Type 0)",
    };

    pub const MANUAL_PROPERTY_CREATION: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_manual_property_creation_tx.json",
        txid: "73914fb386c19f09181ac01cb3680eaee01268ef0781dff9f25d5c069b5334f0",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniIssuance"),
        content_type: Some("text/plain"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Manual property creation (Type 54)",
    };

    pub const REVOKE_PROPERTY_TOKENS: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_revoke_property_tokens_tx.json",
        txid: "7429731487105e72ab915a77e677a59d08e6be43b4e8daab58906058382ffbce",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniDestruction"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Revoke property tokens (Type 56)",
    };

    pub const CROWDSALE_CREATION: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_crowdsale_creation_eda3d2.json",
        txid: "eda3d2bb0d23797e6f3c76be50b0a28f57e24c1ad387e926ce9c4b1f1b5c9e30",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Crowdsale creation (Type 51)",
    };

    pub const PROPERTY_FIXED: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_property_fixed_tx.json",
        txid: "725ba706446baa48a2416ab2ffc229c56600d59f31b782ac6c5c82868e1ad97f",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniDEX"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Fixed property creation (Type 25)",
    };

    pub const VARIABLE_PROPERTY_CREATION: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_variable_property_creation_tx.json",
        txid: "b01d1594a7e2083ebcd428706045df003f290c4dc7bd6d77c93df9fcca68232f",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniIssuance"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Variable property creation (Type 51)",
    };

    pub const DEX_SELL_OFFER_2: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_dex_sell_offer_2_tx.json",
        txid: "9a017721f168c0a733d7a8495ffbab102c5c56ac3907f57382dc10a18357b004",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniDEX"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "DEX sell offer (Type 20)",
    };

    pub const DEX_ACCEPT_OFFER: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_dex_accept_offer_tx.json",
        txid: "3d7742608f3df0436c7d482465b092344c083105fb4d8f5f7745494074ec1d3b",
        protocol: ProtocolType::OmniLayer,
        variant: Some("OmniDEX"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "DEX accept offer (Type 22)",
    };

    pub const MULTI_PACKET: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_multi_packet_transaction_tx.json",
        txid: "153091863886921ab8bf6a7cc17ea99610795522f48b1824d2e417954e466281",
        protocol: ProtocolType::OmniLayer,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Multi-packet transaction",
    };

    pub const FIXED_PROPERTY_CREATION_2: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_fixed_property_creation_2_tx.json",
        txid: "3bfadbdaa445bb0b5c6ba35d03cad7dc5631a0c26229edd234d0dc409619f03f",
        protocol: ProtocolType::OmniLayer,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Fixed property creation (Type 50) - second example",
    };

    pub const DEOBFUSCATION_FAIL: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/omni/omni_deobfuscation_fail_tx.json",
        txid: "243e1d05d7098c3da5decb823707b67d4f547eb0588f26f1847ace57df7a9907",
        protocol: ProtocolType::OmniLayer,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: Some("tests/test_data/omni/inputs/"),
        description: "Failed deobfuscation scenario",
    };

    /// Returns all omni fixtures for iteration
    pub fn all() -> Vec<&'static ProtocolFixture> {
        vec![
            &USDT_GRANT_TOKENS,
            &DEX_SELL_OFFER_CANCEL,
            &SEND_TO_OWNERS,
            &CLOSE_CROWDSALE,
            &CROWDSALE_PARTICIPATION_1,
            &CROWDSALE_PARTICIPATION_2,
            &MANUAL_PROPERTY_CREATION,
            &REVOKE_PROPERTY_TOKENS,
            &CROWDSALE_CREATION,
            &PROPERTY_FIXED,
            &VARIABLE_PROPERTY_CREATION,
            &DEX_SELL_OFFER_2,
            &DEX_ACCEPT_OFFER,
            &MULTI_PACKET,
            &FIXED_PROPERTY_CREATION_2,
            &DEOBFUSCATION_FAIL,
        ]
    }
}

/// PPk protocol fixtures
pub mod ppk {
    use super::*;

    pub const RT_STANDARD: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/ppk/ppk_rt_standard.json",
        txid: "ed95e04018dcc2f01ba8cd699d86852f85ca0af63d05f715a9b2701bb61c6b00",
        protocol: ProtocolType::PPk,
        variant: Some("PPkProfile"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "Profile data via OP_RETURN transport",
    };

    pub const RT_P2MS_EMBEDDED: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/ppk/ppk_rt_p2ms_embedded.json",
        txid: "20cb5958edce385c3fa3ec7f3b12391f158442c7a742a924312556eca891f400",
        protocol: ProtocolType::PPk,
        variant: Some("PPkProfile"),
        content_type: Some("application/json"),
        input_fixture_path: None,
        description: "Profile data via P2MS-embedded transport",
    };

    pub const REGISTRATION: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/ppk/ppk_registration.json",
        txid: "a72d797a108fca918efbded273623ce1f9348b716c0f700bab97f12fe5837200",
        protocol: ProtocolType::PPk,
        variant: Some("PPkRegistration"),
        content_type: Some("text/plain"),
        input_fixture_path: None,
        description: "Number string registration",
    };

    pub const MESSAGE: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/ppk/ppk_message.json",
        txid: "a7fcc7391e2db0fe13b3a12d37fdbdc6138b2c76a9a447020fa92071a64dfe0c",
        protocol: ProtocolType::PPk,
        variant: Some("PPkMessage"),
        content_type: Some("text/plain"),
        input_fixture_path: None,
        description: "Promotional message with PPk substring",
    };

    pub const UNKNOWN: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/ppk/ppk_unknown.json",
        txid: "39dc482ec69056ae445d1acad9507f8167d3f91fc93b9076e94cfb866e639600",
        protocol: ProtocolType::PPk,
        variant: Some("PPkUnknown"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Unknown PPk application",
    };

    /// Returns all PPk fixtures for iteration
    pub fn all() -> Vec<&'static ProtocolFixture> {
        vec![
            &RT_STANDARD,
            &RT_P2MS_EMBEDDED,
            &REGISTRATION,
            &MESSAGE,
            &UNKNOWN,
        ]
    }
}

/// Chancecoin protocol fixtures
pub mod chancecoin {
    use super::*;

    pub const BET: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/chancecoin/chancecoin_bet_tx.json",
        txid: "a9b505f1edb8fedaa7c1edb96cdd622b72b0623b1a5fafa7a1eac97f1a377889",
        protocol: ProtocolType::Chancecoin,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Gambling bet with CHANCECO signature",
    };

    pub const TX_001A86: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/chancecoin/001a863cf538ac94b121baf79c596abdb904e4cda87f407df2751aefc5590dd4.json",
        txid: "001a863cf538ac94b121baf79c596abdb904e4cda87f407df2751aefc5590dd4",
        protocol: ProtocolType::Chancecoin,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Chancecoin transaction 1",
    };

    pub const TX_0023FA: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/chancecoin/0023fad37f02dd0cbd8d12e97d46ccba3947342c422f3793ccea301e9c28045f.json",
        txid: "0023fad37f02dd0cbd8d12e97d46ccba3947342c422f3793ccea301e9c28045f",
        protocol: ProtocolType::Chancecoin,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Chancecoin transaction 2",
    };

    pub const TX_00465A: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/chancecoin/00465a96bb61ef1ab9df812f0c6f196da902064a4d63ab05399747252907f962.json",
        txid: "00465a96bb61ef1ab9df812f0c6f196da902064a4d63ab05399747252907f962",
        protocol: ProtocolType::Chancecoin,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Chancecoin transaction 3",
    };

    pub const TX_0052A7: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/chancecoin/0052a7c60352399ed25cba926078c58cf795ff70891a7ca3e6c59299b9084cd0.json",
        txid: "0052a7c60352399ed25cba926078c58cf795ff70891a7ca3e6c59299b9084cd0",
        protocol: ProtocolType::Chancecoin,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Chancecoin transaction 4",
    };

    pub const TX_005B47: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/chancecoin/005b47811eb0c50a9272ec8ce79faca62cc14d3a9f787d6d19dacd6818974057.json",
        txid: "005b47811eb0c50a9272ec8ce79faca62cc14d3a9f787d6d19dacd6818974057",
        protocol: ProtocolType::Chancecoin,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Chancecoin transaction 5",
    };

    pub const TX_005E3F: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/chancecoin/005e3f8e406820abf1af5d6e2fa20774dceeac6bf087cfcff16737e90af56e68.json",
        txid: "005e3f8e406820abf1af5d6e2fa20774dceeac6bf087cfcff16737e90af56e68",
        protocol: ProtocolType::Chancecoin,
        variant: None,
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Chancecoin transaction 6",
    };

    /// Returns all chancecoin fixtures for iteration
    pub fn all() -> Vec<&'static ProtocolFixture> {
        vec![
            &BET, &TX_001A86, &TX_0023FA, &TX_00465A, &TX_0052A7, &TX_005B47, &TX_005E3F,
        ]
    }
}

/// OP_RETURN signalled protocol fixtures
pub mod opreturn_signalled {
    use super::*;

    pub const CLIPPERZ_V1: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/opreturn_signalled/clipperz_v1.json",
        txid: "08437467cbb88640b40185169293b138e216ec1a970f596e3c915ce74021d85e",
        protocol: ProtocolType::OpReturnSignalled,
        variant: Some("OpReturnCLIPPERZ"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "CLIPPERZ notarisation v1",
    };

    pub const CLIPPERZ_V2: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/opreturn_signalled/clipperz_v2.json",
        txid: "4bc03ae94ae9775db84fc3d7ef859fad9d4267beacf209ac53bd960ed6a4a0b2",
        protocol: ProtocolType::OpReturnSignalled,
        variant: Some("OpReturnCLIPPERZ"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "CLIPPERZ notarisation v2",
    };

    pub const PROTOCOL47930: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/opreturn_signalled/protocol47930.json",
        txid: "82d0872a72032c21cadfa1f7590f661f00c1bc663c4eb93b5730df40c7b87cbf",
        protocol: ProtocolType::OpReturnSignalled,
        variant: Some("OpReturnProtocol47930"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "Protocol47930 (0xbb3a marker)",
    };

    /// Returns all opreturn_signalled fixtures for iteration
    pub fn all() -> Vec<&'static ProtocolFixture> {
        vec![&CLIPPERZ_V1, &CLIPPERZ_V2, &PROTOCOL47930]
    }
}

/// LikelyLegitimateMultisig fixtures
pub mod likely_legitimate {
    use super::*;

    pub const MULTISIG_2OF3_CD27C9: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/likely_legitimate/legitimate_multisig_cd27c9.json",
        txid: "cd27c98d834dd96c4f16d16f33560d99a3a8805a255ef9d9007f803a07d5f457",
        protocol: ProtocolType::LikelyLegitimateMultisig,
        variant: Some("LegitimateMultisig"),
        content_type: None, // LikelyLegitimateMultisig has no content type (not data-carrying)
        input_fixture_path: None,
        description: "Real 2-of-3 multisig from block 234568 (May 2013)",
    };

    /// Returns all likely_legitimate fixtures for iteration
    pub fn all() -> Vec<&'static ProtocolFixture> {
        vec![&MULTISIG_2OF3_CD27C9]
    }
}

/// DataStorage protocol fixtures
pub mod datastorage {
    use super::*;

    pub const LINPYRO_1: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/datastorage/3344647bc080.json",
        txid: "3344647bc0801d3c4f5ca9a33106e6e4ed34754a1d7833e7bbcdc9094db347b0",
        protocol: ProtocolType::DataStorage,
        variant: Some("EmbeddedData"),
        content_type: Some("application/gzip"),
        input_fixture_path: None,
        description: "Linpyro GZIP-compressed data transaction 1",
    };

    pub const LINPYRO_2: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/datastorage/d246f58b59be.json",
        txid: "d246f58b59be6595df03c404a6497177564c7b2bf5396596641e59d268b1b40d",
        protocol: ProtocolType::DataStorage,
        variant: Some("EmbeddedData"),
        content_type: Some("application/gzip"),
        input_fixture_path: None,
        description: "Linpyro GZIP-compressed data transaction 2",
    };

    pub const WIKILEAKS_PYTHON_1: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/datastorage/wikileaks_python_6c53cd98.json",
        txid: "6c53cd987119ef797d5adccd76241247988a0a5ef783572a9972e7371c5fb0cc",
        protocol: ProtocolType::DataStorage,
        variant: Some("EmbeddedData"),
        content_type: Some("text/x-python"),
        input_fixture_path: None,
        description: "WikiLeaks Python downloader script",
    };

    pub const WIKILEAKS_PYTHON_2: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/datastorage/wikileaks_python_4b72a223.json",
        txid: "4b72a223007eab8a951d43edc171befeabc7b5dca4213770c88e09ba5b936e17",
        protocol: ProtocolType::DataStorage,
        variant: Some("EmbeddedData"),
        content_type: Some("text/x-python"),
        input_fixture_path: None,
        description: "WikiLeaks Python insertion tool script",
    };

    pub const NULL_DATA: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/datastorage/nulldata_9cf7c3fc.json",
        txid: "9cf7c3fcf15ec0427a98623abe1fa752ad10c1615670c0dbe0a11516f277540e",
        protocol: ProtocolType::DataStorage,
        variant: Some("DataStorageNullData"),
        content_type: None,
        input_fixture_path: None,
        description: "All-zero pubkey data (null data pattern)",
    };

    pub const URL_EMBEDDING: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/datastorage/url_embedding.json",
        txid: "0716406f435e576bea06a9de51b3756594f59c8c7272f9c41b63a90442348d07",
        protocol: ProtocolType::DataStorage,
        variant: Some("EmbeddedData"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "URL embedded in pubkeys (midasrezerv.com)",
    };

    pub const ASCII_MESSAGE: ProtocolFixture = ProtocolFixture {
        path: "tests/test_data/datastorage/ascii_message_4a3574cd.json",
        txid: "4a3574cd6053c14f6858555b942da16d1f6594aa1750e515c1f6be77e7f686e4",
        protocol: ProtocolType::DataStorage,
        variant: Some("EmbeddedData"),
        content_type: Some("application/octet-stream"),
        input_fixture_path: None,
        description: "ASCII personal message (Hello People!)",
    };

    /// Returns all datastorage fixtures for iteration
    pub fn all() -> Vec<&'static ProtocolFixture> {
        vec![
            &LINPYRO_1,
            &LINPYRO_2,
            &WIKILEAKS_PYTHON_1,
            &WIKILEAKS_PYTHON_2,
            &NULL_DATA,
            &URL_EMBEDDING,
            &ASCII_MESSAGE,
        ]
    }
}

/// Get all fixtures across all protocols
pub fn all_fixtures() -> Vec<&'static ProtocolFixture> {
    let mut all = Vec::new();
    all.extend(stamps::all());
    all.extend(counterparty::all());
    all.extend(omni::all());
    all.extend(ppk::all());
    all.extend(chancecoin::all());
    all.extend(opreturn_signalled::all());
    all.extend(likely_legitimate::all());
    all.extend(datastorage::all());
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn all_fixture_paths_exist() {
        let mut missing = Vec::new();
        for fixture in all_fixtures() {
            if !Path::new(fixture.path).exists() {
                missing.push(fixture.path);
            }
        }
        assert!(
            missing.is_empty(),
            "Missing fixture files:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn all_fixtures_have_valid_txids() {
        for fixture in all_fixtures() {
            assert_eq!(
                fixture.txid.len(),
                64,
                "Fixture {} has invalid txid length: {} (expected 64)",
                fixture.path,
                fixture.txid.len()
            );
            assert!(
                fixture.txid.chars().all(|c| c.is_ascii_hexdigit()),
                "Fixture {} has non-hex characters in txid",
                fixture.path
            );
        }
    }

    #[test]
    fn fixture_count_matches_expected() {
        // This test documents the expected fixture counts per protocol
        assert_eq!(stamps::all().len(), 9, "Expected 9 stamps fixtures");
        assert_eq!(
            counterparty::all().len(),
            11,
            "Expected 11 counterparty fixtures"
        );
        assert_eq!(omni::all().len(), 16, "Expected 16 omni fixtures");
        assert_eq!(ppk::all().len(), 5, "Expected 5 ppk fixtures");
        assert_eq!(chancecoin::all().len(), 7, "Expected 7 chancecoin fixtures");
        assert_eq!(
            opreturn_signalled::all().len(),
            3,
            "Expected 3 opreturn_signalled fixtures"
        );
        assert_eq!(
            likely_legitimate::all().len(),
            1,
            "Expected 1 likely_legitimate fixture"
        );
        assert_eq!(
            datastorage::all().len(),
            7,
            "Expected 7 datastorage fixtures"
        );

        // Total: 9 + 11 + 16 + 5 + 7 + 3 + 1 + 7 = 59 fixtures
        assert_eq!(all_fixtures().len(), 59, "Expected 59 total fixtures");
    }
}
