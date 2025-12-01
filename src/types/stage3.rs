//! Stage 3 specific types and configurations
//!
//! This module contains types specific to Stage 3 protocol classification,
//! including classification results, protocol types, and configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::burn_patterns;

/// Configuration for Stage 3 protocol classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage3Config {
    pub database_path: PathBuf,
    pub batch_size: usize,
    pub progress_interval: usize,
}

impl Default for Stage3Config {
    fn default() -> Self {
        Self {
            database_path: "./test_output/testing.db".into(),
            batch_size: 100,
            progress_interval: 1000,
        }
    }
}

impl Stage3Config {
    /// Validate the current configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.batch_size == 0 {
            return Err("Batch size cannot be zero".to_string());
        }

        if self.progress_interval == 0 {
            return Err("Progress interval cannot be zero".to_string());
        }

        Ok(())
    }

    /// Get the progress reporting interval
    pub fn get_progress_interval(&self) -> usize {
        self.progress_interval
    }
}

/// Classification result for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub txid: String,
    pub protocol: ProtocolType,
    pub variant: Option<ProtocolVariant>,
    pub classification_details: ClassificationDetails,
    pub classification_timestamp: u64,
}

impl ClassificationResult {
    /// Create a new classification result with current timestamp
    pub fn new(
        txid: String,
        protocol: ProtocolType,
        variant: Option<ProtocolVariant>,
        classification_details: ClassificationDetails,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        Self {
            txid,
            protocol,
            variant,
            classification_details,
            classification_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Check if this is a high-confidence classification
    pub fn is_high_confidence(&self) -> bool {
        self.classification_details.protocol_signature_found
            && self.classification_details.height_check_passed
    }

    /// Get a human-readable classification summary
    pub fn summary(&self) -> String {
        let protocol_name = match self.protocol {
            ProtocolType::BitcoinStamps => "Bitcoin Stamps",
            ProtocolType::Counterparty => "Counterparty",
            ProtocolType::AsciiIdentifierProtocols => "ASCII Identifier Protocols",
            ProtocolType::OmniLayer => "Omni Layer",
            ProtocolType::Chancecoin => "Chancecoin",
            ProtocolType::PPk => "PPk",
            ProtocolType::OpReturnSignalled => "OP_RETURN Signalled",
            ProtocolType::DataStorage => "Data Storage",
            ProtocolType::LikelyDataStorage => "Likely Data Storage",
            ProtocolType::LikelyLegitimateMultisig => "Likely Legitimate Multisig",
            ProtocolType::Unknown => "Unknown",
        };

        if let Some(variant) = &self.variant {
            format!("{} ({:?})", protocol_name, variant)
        } else {
            protocol_name.to_string()
        }
    }
}

/// Definitive protocol classifications - no ambiguity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    BitcoinStamps,
    Counterparty,
    AsciiIdentifierProtocols, // Protocols with ASCII identifiers embedded in P2MS data (TB0001, TEST01, Metronotes)
    OmniLayer,
    Chancecoin,
    PPk, // PPk blockchain infrastructure protocol (identified by marker pubkey, with RT, Registration, Message variants)
    OpReturnSignalled, // Protocols identified by OP_RETURN markers (Protocol47930, CLIPPERZ)
    DataStorage,
    LikelyDataStorage, // Suspicious patterns (invalid EC points, high output count, dust amounts)
    LikelyLegitimateMultisig, // All pubkeys are valid EC points - likely legitimate multisig
    Unknown,
}

impl ProtocolType {
    /// Get human-readable display name with proper spacing
    ///
    /// This is the single source of truth for protocol display names used in
    /// reports, charts, and user-facing output.
    pub fn display_name(&self) -> &'static str {
        match self {
            ProtocolType::BitcoinStamps => "Bitcoin Stamps",
            ProtocolType::Counterparty => "Counterparty",
            ProtocolType::AsciiIdentifierProtocols => "ASCII Identifier Protocols",
            ProtocolType::OmniLayer => "Omni Layer",
            ProtocolType::Chancecoin => "Chancecoin",
            ProtocolType::PPk => "PPk",
            ProtocolType::OpReturnSignalled => "OP_RETURN Signalled",
            ProtocolType::DataStorage => "Data Storage",
            ProtocolType::LikelyDataStorage => "Likely Data Storage",
            ProtocolType::LikelyLegitimateMultisig => "Likely Legitimate Multisig",
            ProtocolType::Unknown => "Unknown",
        }
    }

    /// Convert protocol string to display name
    ///
    /// Parses a protocol string (e.g., "BitcoinStamps") and returns its
    /// human-readable display name. Returns the original string if parsing fails.
    pub fn str_to_display_name(s: &str) -> String {
        std::str::FromStr::from_str(s)
            .map(|p: ProtocolType| p.display_name().to_string())
            .unwrap_or_else(|_| s.to_string())
    }

    /// Get sort order for a protocol string
    ///
    /// Returns the enum variant order for sorting protocols consistently.
    /// Unknown strings sort to the end (u8::MAX).
    pub fn str_to_sort_order(s: &str) -> u8 {
        std::str::FromStr::from_str(s)
            .map(|p: ProtocolType| p as u8)
            .unwrap_or(u8::MAX)
    }
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::BitcoinStamps => write!(f, "BitcoinStamps"),
            ProtocolType::Counterparty => write!(f, "Counterparty"),
            ProtocolType::AsciiIdentifierProtocols => write!(f, "AsciiIdentifierProtocols"),
            ProtocolType::OmniLayer => write!(f, "OmniLayer"),
            ProtocolType::Chancecoin => write!(f, "Chancecoin"),
            ProtocolType::PPk => write!(f, "PPk"),
            ProtocolType::OpReturnSignalled => write!(f, "OpReturnSignalled"),
            ProtocolType::DataStorage => write!(f, "DataStorage"),
            ProtocolType::LikelyDataStorage => write!(f, "LikelyDataStorage"),
            ProtocolType::LikelyLegitimateMultisig => write!(f, "LikelyLegitimateMultisig"),
            ProtocolType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::str::FromStr for ProtocolType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BitcoinStamps" => Ok(ProtocolType::BitcoinStamps),
            "Counterparty" => Ok(ProtocolType::Counterparty),
            "AsciiIdentifierProtocols" => Ok(ProtocolType::AsciiIdentifierProtocols),
            "OmniLayer" => Ok(ProtocolType::OmniLayer),
            "Chancecoin" => Ok(ProtocolType::Chancecoin),
            "PPk" => Ok(ProtocolType::PPk),
            "OpReturnSignalled" => Ok(ProtocolType::OpReturnSignalled),
            "DataStorage" => Ok(ProtocolType::DataStorage),
            "LikelyDataStorage" => Ok(ProtocolType::LikelyDataStorage),
            "LikelyLegitimateMultisig" => Ok(ProtocolType::LikelyLegitimateMultisig),
            "Unknown" => Ok(ProtocolType::Unknown),
            _ => Err(format!("Unknown protocol type: {}", s)),
        }
    }
}

/// Protocol-specific variants (determined during classification)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProtocolVariant {
    // Bitcoin Stamps variants
    StampsClassic,    // Image data
    StampsSRC20,      // SRC-20 token
    StampsSRC721,     // SRC-721 NFT
    StampsSRC101,     // SRC-101 domain
    StampsHTML,       // HTML documents and JavaScript applications
    StampsCompressed, // Compressed data (ZLIB, GZIP)
    StampsData,       // Generic data (XML, non-SRC JSON, binary)
    StampsUnknown,    // Unrecognizable content or burn-pattern-only

    // Counterparty variants (7 semantically coherent categories)
    CounterpartyTransfer, // Asset transfers: Send (0), EnhancedSend (2), Mpma (3), Sweep (4), Dividend (50)
    CounterpartyIssuance, // Asset creation: Issuance (20/21/22), FairMinter (90), FairMint (91)
    CounterpartyDestruction, // Asset destruction: Destroy (110), Burn (60)
    CounterpartyDEX,      // DEX operations: Order (10), BtcPay (11), Dispenser (12), Cancel (70)
    CounterpartyOracle,   // Oracle broadcasts: Broadcast (30)
    CounterpartyGaming,   // Betting and gaming: Bet (40), Rps (80), RpsResolve (81)
    CounterpartyUtility,  // UTXO operations: Utxo (100), Attach (101), Detach (102)

    // ASCII Identifier Protocols (protocols with ASCII identifiers in P2MS data)
    AsciiIdentifierTB0001,     // TB0001 protocol (May 2015, ~150 txs)
    AsciiIdentifierTEST01,     // TEST01 protocol (May 2015, ~91 txs)
    AsciiIdentifierMetronotes, // Metronotes/METROXMN (March 2015, ~100 txs)
    AsciiIdentifierOther,      // Other ASCII protocols (NEWBCOIN, PRVCY)
    AsciiIdentifierUnknown,    // Unknown ASCII identifier protocol

    // Omni Layer variants (7 semantic categories + 1 special case)
    OmniTransfer,            // Types 0,2,4,5: P2P asset transfers
    OmniDistribution,        // Type 3: Broadcast to all holders (dividends/airdrops)
    OmniIssuance,            // Types 50,51,52,54,55: Property creation & token minting
    OmniDestruction,         // Type 56: Token burning/revocation
    OmniDEX,                 // Types 20,22,25-28: Exchange operations
    OmniAdministration,      // Types 53,70,71,72,185,186: Admin controls & restrictions
    OmniUtility,             // Types 31,200: Notifications & arbitrary data
    OmniFailedDeobfuscation, // Exodus address present but deobfuscation failed

    // Chancecoin variants
    ChancecoinSend,    // Token transfer (ID=0)
    ChancecoinOrder,   // DEX order (ID=10)
    ChancecoinBTCPay,  // BTC payment (ID=11)
    ChancecoinRoll,    // Bet resolution (ID=14)
    ChancecoinBet,     // Gambling bet (ID=40/41)
    ChancecoinCancel,  // Cancel order (ID=70)
    ChancecoinUnknown, // Unknown Chancecoin message type

    // PPk protocol variants (infrastructure with RT and other applications)
    PPkProfile, // JSON profile data via RT transport (2,010 txs total - combines OP_RETURN and P2MS-embedded)
    PPkRegistration, // Number string registrations (~1,000 txs)
    PPkMessage, // PPk promotional messages (~500 txs)
    PPkUnknown, // Other PPk applications (~1,196 txs)

    // OP_RETURN-signalled protocol variants
    OpReturnProtocol47930, // 0xbb3a marker (2-of-2 P2MS, ~9000 sats, blocks 554753+)
    OpReturnCLIPPERZ,      // CLIPPERZ notarization (2-of-2 P2MS, 238 txs, blocks 403627-443835)
    OpReturnGenericASCII, // Generic ASCII OP_RETURN protocols (one-off protocols: PRVCY, unsuccessful, @DEVCHA, etc.)

    // LikelyDataStorage variants
    LikelyDataStorageInvalidECPoint, // Invalid EC points (not on secp256k1 curve - obvious data embedding)
    LikelyDataStorageHighOutputCount, // 5+ P2MS outputs with valid EC points
    LikelyDataStorageDustAmount,     // P2MS outputs with dust-level amounts (<= 1000 sats)

    // LikelyLegitimateMultisig variants
    LegitimateMultisig,            // Standard multisig with valid EC points
    LegitimateMultisigDupeKeys,    // Valid EC points but duplicate keys
    LegitimateMultisigWithNullKey, // Mix of valid EC points + all-null pubkeys (spendable if M ≤ real keys)

    // DataStorage variants
    DataStorageProofOfBurn,        // All 0xFF burn patterns
    DataStorageFileMetadata,       // File sharing metadata (WikiLeaks, etc.)
    DataStorageEmbeddedData,       // Data embedded in pubkey coordinates
    DataStorageWikiLeaksCablegate, // WikiLeaks Cablegate archive (April 2013, 132 txs, heights 229991-230256)
    DataStorageBitcoinWhitepaper,  // The Bitcoin Whitepaper PDF (height 230009, tx 54e48e5f...)
    DataStorageNullData,           // Null/zero byte padding (empty data)
    DataStorageGeneric,            // Other data storage patterns
}

impl std::fmt::Display for ProtocolVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            ProtocolVariant::StampsClassic => "Classic",
            ProtocolVariant::StampsSRC20 => "SRC-20",
            ProtocolVariant::StampsSRC721 => "SRC-721",
            ProtocolVariant::StampsSRC101 => "SRC-101",
            ProtocolVariant::StampsHTML => "HTML",
            ProtocolVariant::StampsCompressed => "Compressed",
            ProtocolVariant::StampsData => "Data",
            ProtocolVariant::StampsUnknown => "Unknown",
            ProtocolVariant::CounterpartyTransfer => "Transfer",
            ProtocolVariant::CounterpartyIssuance => "Issuance",
            ProtocolVariant::CounterpartyDestruction => "Destruction",
            ProtocolVariant::CounterpartyDEX => "DEX",
            ProtocolVariant::CounterpartyOracle => "Oracle",
            ProtocolVariant::CounterpartyGaming => "Gaming",
            ProtocolVariant::CounterpartyUtility => "Utility",
            ProtocolVariant::AsciiIdentifierTB0001 => "TB0001",
            ProtocolVariant::AsciiIdentifierTEST01 => "TEST01",
            ProtocolVariant::AsciiIdentifierMetronotes => "Metronotes",
            ProtocolVariant::AsciiIdentifierOther => "Other ASCII Protocol",
            ProtocolVariant::AsciiIdentifierUnknown => "Unknown Variant",
            ProtocolVariant::OmniTransfer => "Transfer",
            ProtocolVariant::OmniDistribution => "Distribution",
            ProtocolVariant::OmniIssuance => "Issuance",
            ProtocolVariant::OmniDestruction => "Destruction",
            ProtocolVariant::OmniDEX => "DEX",
            ProtocolVariant::OmniAdministration => "Administration",
            ProtocolVariant::OmniUtility => "Utility",
            ProtocolVariant::OmniFailedDeobfuscation => "Failed Deobfuscation",
            ProtocolVariant::ChancecoinSend => "Send",
            ProtocolVariant::ChancecoinOrder => "Order",
            ProtocolVariant::ChancecoinBTCPay => "BTCPay",
            ProtocolVariant::ChancecoinRoll => "Roll",
            ProtocolVariant::ChancecoinBet => "Bet",
            ProtocolVariant::ChancecoinCancel => "Cancel",
            ProtocolVariant::ChancecoinUnknown => "Unknown",
            ProtocolVariant::PPkProfile => "PPkProfile",
            ProtocolVariant::PPkRegistration => "PPkRegistration",
            ProtocolVariant::PPkMessage => "PPkMessage",
            ProtocolVariant::PPkUnknown => "PPkUnknown",
            ProtocolVariant::OpReturnProtocol47930 => "Protocol47930",
            ProtocolVariant::OpReturnCLIPPERZ => "CLIPPERZ",
            ProtocolVariant::OpReturnGenericASCII => "GenericASCII",
            ProtocolVariant::LikelyDataStorageInvalidECPoint => "Invalid EC Point",
            ProtocolVariant::LikelyDataStorageHighOutputCount => "High Output Count",
            ProtocolVariant::LikelyDataStorageDustAmount => "Dust Amount",
            ProtocolVariant::LegitimateMultisig => "Legitimate Multisig",
            ProtocolVariant::LegitimateMultisigDupeKeys => "Legitimate Multisig (Duplicate Keys)",
            ProtocolVariant::LegitimateMultisigWithNullKey => "Legitimate Multisig (Null-Padded)",
            ProtocolVariant::DataStorageProofOfBurn => "Proof of Burn",
            ProtocolVariant::DataStorageFileMetadata => "File Metadata",
            ProtocolVariant::DataStorageEmbeddedData => "Embedded Data",
            ProtocolVariant::DataStorageWikiLeaksCablegate => "WikiLeaks Cablegate",
            ProtocolVariant::DataStorageBitcoinWhitepaper => "Bitcoin Whitepaper",
            ProtocolVariant::DataStorageNullData => "Null Data",
            ProtocolVariant::DataStorageGeneric => "Generic",
        };
        write!(f, "{}", name)
    }
}

/// Pure data structure for output classification (used during classification, before DB write)
///
/// This struct represents output classification data in pure form, without database
/// coupling. Classifiers build these during classification and return them via
/// `get_output_classifications()`, which Stage3Processor then batch-inserts.
///
/// # Design Rationale
///
/// Separation of concerns - classifiers should produce data, not perform DB operations.
/// This enables proper FK ordering (transaction classifications before output classifications)
/// and allows classifiers to remain stateless and testable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputClassificationData {
    pub vout: u32,
    pub protocol: ProtocolType,
    pub variant: Option<ProtocolVariant>,
    pub details: OutputClassificationDetails,
}

impl OutputClassificationData {
    /// Create new output classification data
    pub fn new(
        vout: u32,
        protocol: ProtocolType,
        variant: Option<ProtocolVariant>,
        details: OutputClassificationDetails,
    ) -> Self {
        Self {
            vout,
            protocol,
            variant,
            details,
        }
    }
}

/// Details about per-output classification with spendability analysis
///
/// This struct is used for individual P2MS output classifications and includes
/// spendability fields that are meaningless at the transaction level.
///
/// # Design Rationale
///
/// Spendability is fundamentally an **output-level property**, not a transaction-level one:
/// - Different outputs in the same transaction can have different spendability
/// - Each output has different public keys requiring independent EC validation
/// - Key counts (real/burn/data) vary per output based on actual keys present
///
/// Therefore, this struct is used ONLY for per-output classifications via
/// `insert_output_classification()`, while `ClassificationDetails` (without spendability)
/// is used for transaction-level `ClassificationResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputClassificationDetails {
    pub burn_patterns_detected: Vec<burn_patterns::BurnPatternType>,
    pub height_check_passed: bool,
    pub protocol_signature_found: bool,
    pub classification_method: String,
    pub additional_metadata: Option<String>,
    pub content_type: Option<String>,

    // Spendability analysis (required for output-level classification)
    pub is_spendable: bool,          // Can this specific output be spent?
    pub spendability_reason: String, // Reason for spendability determination
    pub real_pubkey_count: u8,       // Number of valid EC point pubkeys in THIS output
    pub burn_key_count: u8,          // Number of burn keys in THIS output
    pub data_key_count: u8,          // Number of data keys in THIS output
}

impl OutputClassificationDetails {
    /// Create output classification details from spendability analysis
    pub fn new(
        burn_patterns: Vec<burn_patterns::BurnPatternType>,
        height_check_passed: bool,
        protocol_signature_found: bool,
        method: String,
        spendability: crate::types::spendability::SpendabilityResult,
    ) -> Self {
        Self {
            burn_patterns_detected: burn_patterns,
            height_check_passed,
            protocol_signature_found,
            classification_method: method,
            additional_metadata: None,
            content_type: None,
            is_spendable: spendability.is_spendable,
            spendability_reason: spendability.reason.to_string(),
            real_pubkey_count: spendability.real_pubkey_count,
            burn_key_count: spendability.burn_key_count,
            data_key_count: spendability.data_key_count,
        }
    }

    /// Add metadata to the output classification
    pub fn with_metadata<S: Into<String>>(mut self, metadata: S) -> Self {
        self.additional_metadata = Some(metadata.into());
        self
    }

    /// Add content type (MIME type) to the output classification
    pub fn with_content_type<S: Into<String>>(mut self, content_type: S) -> Self {
        self.content_type = Some(content_type.into());
        self
    }
}

/// Details about transaction-level classification (NO spendability)
///
/// This struct represents classification metadata at the transaction level.
/// It intentionally EXCLUDES spendability fields because spendability is an
/// output-level property, not a transaction-level one.
///
/// For per-output classifications with spendability, use `OutputClassificationDetails`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationDetails {
    pub burn_patterns_detected: Vec<burn_patterns::BurnPatternType>,
    pub height_check_passed: bool,
    pub protocol_signature_found: bool,
    pub classification_method: String, // e.g., "CNTRPRTY identifier", "Burn pattern match"
    pub additional_metadata: Option<String>, // JSON for protocol-specific metadata
    pub content_type: Option<String>,  // MIME type string (e.g., "image/png", "application/json")
}

impl ClassificationDetails {
    /// Create new transaction-level classification details (no spendability)
    pub fn new(
        burn_patterns: Vec<burn_patterns::BurnPatternType>,
        height_check_passed: bool,
        protocol_signature_found: bool,
        method: String,
    ) -> Self {
        Self {
            burn_patterns_detected: burn_patterns,
            height_check_passed,
            protocol_signature_found,
            classification_method: method,
            additional_metadata: None,
            content_type: None,
        }
    }

    /// Add metadata to the classification
    pub fn with_metadata<S: Into<String>>(mut self, metadata: S) -> Self {
        self.additional_metadata = Some(metadata.into());
        self
    }

    /// Add content type (MIME type) to the classification
    pub fn with_content_type<S: Into<String>>(mut self, content_type: S) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Check if this is a strong classification (has protocol signature)
    pub fn is_strong_classification(&self) -> bool {
        self.protocol_signature_found
    }

    /// Check if this classification is based on burn patterns only
    pub fn is_burn_pattern_only(&self) -> bool {
        !self.burn_patterns_detected.is_empty() && !self.protocol_signature_found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage3_config_default() {
        let config = Stage3Config::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.progress_interval, 1000);
    }

    #[test]
    fn test_stage3_config_custom() {
        let config = Stage3Config {
            database_path: "/path/to/db.sqlite".into(),
            batch_size: 200,
            progress_interval: 500,
        };

        assert_eq!(config.database_path, PathBuf::from("/path/to/db.sqlite"));
        assert_eq!(config.batch_size, 200);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_stage3_config_validation() {
        // Test invalid batch size
        let config = Stage3Config {
            batch_size: 0,
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Batch size cannot be zero"));

        // Test invalid progress interval
        let config = Stage3Config {
            progress_interval: 0,
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Progress interval cannot be zero"));
    }

    #[test]
    fn test_classification_result() {
        use super::burn_patterns::BurnPatternType;

        let details = ClassificationDetails::new(
            vec![BurnPatternType::Stamps22Pattern],
            true,
            true,
            "Burn pattern match".to_string(),
        );

        let result = ClassificationResult::new(
            "test_txid".to_string(),
            ProtocolType::BitcoinStamps,
            Some(ProtocolVariant::StampsClassic),
            details,
        );

        assert_eq!(result.txid, "test_txid");
        assert_eq!(result.protocol, ProtocolType::BitcoinStamps);
        assert_eq!(result.variant, Some(ProtocolVariant::StampsClassic));
        assert!(result.is_high_confidence());
        assert_eq!(result.summary(), "Bitcoin Stamps (StampsClassic)");
    }

    #[test]
    fn test_classification_details() {
        use super::burn_patterns::BurnPatternType;

        let details = ClassificationDetails::new(
            vec![BurnPatternType::ProofOfBurn],
            true,
            false,
            "Burn pattern only".to_string(),
        )
        .with_metadata("{\"confidence\": \"medium\"}");

        assert!(!details.is_strong_classification());
        assert!(details.is_burn_pattern_only());
        assert!(details.additional_metadata.is_some());
    }

    #[test]
    fn test_protocol_type_display() {
        assert_eq!(ProtocolType::BitcoinStamps.to_string(), "BitcoinStamps");
        assert_eq!(ProtocolType::Counterparty.to_string(), "Counterparty");
        assert_eq!(ProtocolType::OmniLayer.to_string(), "OmniLayer");
        assert_eq!(ProtocolType::DataStorage.to_string(), "DataStorage");
        assert_eq!(
            ProtocolType::LikelyLegitimateMultisig.to_string(),
            "LikelyLegitimateMultisig"
        );
        assert_eq!(ProtocolType::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_protocol_variant_display() {
        // Bitcoin Stamps
        assert_eq!(ProtocolVariant::StampsClassic.to_string(), "Classic");

        // Counterparty
        assert_eq!(
            ProtocolVariant::CounterpartyTransfer.to_string(),
            "Transfer"
        );

        // Omni Layer - Test all 8 variants
        assert_eq!(ProtocolVariant::OmniTransfer.to_string(), "Transfer");
        assert_eq!(
            ProtocolVariant::OmniDistribution.to_string(),
            "Distribution"
        );
        assert_eq!(ProtocolVariant::OmniIssuance.to_string(), "Issuance");
        assert_eq!(ProtocolVariant::OmniDestruction.to_string(), "Destruction");
        assert_eq!(ProtocolVariant::OmniDEX.to_string(), "DEX");
        assert_eq!(
            ProtocolVariant::OmniAdministration.to_string(),
            "Administration"
        );
        assert_eq!(ProtocolVariant::OmniUtility.to_string(), "Utility");
        assert_eq!(
            ProtocolVariant::OmniFailedDeobfuscation.to_string(),
            "Failed Deobfuscation"
        );

        // DataStorage
        assert_eq!(
            ProtocolVariant::DataStorageProofOfBurn.to_string(),
            "Proof of Burn"
        );
    }
}
