//! Bitcoin Stamps variant and transport types
//!
//! Different types of data that can be embedded using the Stamps protocol
//! and transport mechanisms (Pure vs Counterparty).

use crate::types::ProtocolVariant;
use serde::{Deserialize, Serialize};

/// Bitcoin Stamps protocol variants
/// Different types of data that can be embedded using the Stamps protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampsVariant {
    /// Classic Bitcoin Stamps - embedded images and files
    Classic,
    /// SRC-20 fungible tokens
    SRC20,
    /// SRC-721 non-fungible tokens (NFTs)
    SRC721,
    /// SRC-101 domain names
    SRC101,
    /// HTML documents and JavaScript applications
    HTML,
    /// Compressed data (ZLIB, GZIP)
    Compressed,
    /// Generic data (XML, non-SRC JSON, binary data)
    Data,
    /// Unknown - Unrecognisable content or burn-pattern-only detection
    Unknown,
}

impl From<StampsVariant> for ProtocolVariant {
    fn from(variant: StampsVariant) -> Self {
        match variant {
            StampsVariant::Classic => ProtocolVariant::StampsClassic,
            StampsVariant::SRC20 => ProtocolVariant::StampsSRC20,
            StampsVariant::SRC721 => ProtocolVariant::StampsSRC721,
            StampsVariant::SRC101 => ProtocolVariant::StampsSRC101,
            StampsVariant::HTML => ProtocolVariant::StampsHTML,
            StampsVariant::Compressed => ProtocolVariant::StampsCompressed,
            StampsVariant::Data => ProtocolVariant::StampsData,
            StampsVariant::Unknown => ProtocolVariant::StampsUnknown,
        }
    }
}

/// Bitcoin Stamps transport mechanism
///
/// This enum distinguishes between Pure Bitcoin Stamps (which always use burn keys)
/// and Counterparty-transported Stamps (which may use real signing keys).
///
/// ## Spendability Rules
///
/// - **Pure**: Always uses burn keys -> Always unspendable
/// - **Counterparty**: May use real keys OR burn keys -> Check key composition:
///   - If burn keys present -> Unspendable (even if real keys also present)
///   - If NO burn keys (only real keys) -> Spendable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampsTransport {
    /// Pure Bitcoin Stamps - ALWAYS use burn keys (always unspendable)
    Pure,
    /// Counterparty transport - MAY use real pubkeys (check for burn keys to determine spendability)
    Counterparty,
}
