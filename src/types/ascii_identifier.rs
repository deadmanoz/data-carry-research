//! AsciiIdentifierProtocols type definitions
//!
//! Defines variants for protocols that use ASCII identifiers in P2MS pubkey data.
//! These are legacy protocols from 2015 that embedded ASCII signatures.

use super::ProtocolVariant;
use serde::{Deserialize, Serialize};

/// ASCII identifier protocol constants
pub mod constants {
    /// TB0001 protocol signature (bytes 1-7 of second pubkey)
    pub const TB0001_SIGNATURE: &[u8] = b"TB0001\x00";

    /// TEST01 protocol signature (bytes 1-7 of FIRST pubkey - critical difference from TB0001)
    pub const TEST01_SIGNATURE: &[u8] = b"TEST01\x00";

    /// Metronotes/METROXMN protocol signature
    pub const METRONOTES_SIGNATURE: &[u8] = b"METROXMN";
}

/// AsciiIdentifierProtocols variant types
///
/// These variants represent different ASCII identifier protocols detected
/// in P2MS pubkey data from the 2015 era.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AsciiIdentifierVariant {
    /// TB0001 protocol (May 2015, ~150 transactions)
    ///
    /// Signature in **second** pubkey bytes 1-7.
    /// Note: This is NOT Dogeparty (different blockchain).
    TB0001,

    /// TEST01 protocol (May 2015, ~91 transactions)
    ///
    /// Signature in **FIRST** pubkey bytes 1-7 (critical difference from TB0001).
    TEST01,

    /// Metronotes/METROXMN protocol (March 2015, ~100 transactions)
    ///
    /// Signature in second pubkey.
    Metronotes,

    /// Other ASCII protocols (NEWBCOIN, PRVCY, etc.)
    ///
    /// Catch-all for one-off ASCII identifier protocols.
    Other,

    /// Unknown ASCII identifier protocol
    ///
    /// ASCII pattern detected but doesn't match known protocols.
    Unknown,
}

impl AsciiIdentifierVariant {
    /// Get the display name for this variant
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::TB0001 => "TB0001",
            Self::TEST01 => "TEST01",
            Self::Metronotes => "Metronotes",
            Self::Other => "Other ASCII Protocol",
            Self::Unknown => "Unknown Variant",
        }
    }

    /// Get the short identifier for this variant (used in logging/debugging)
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::TB0001 => "AsciiIdentifierTB0001",
            Self::TEST01 => "AsciiIdentifierTEST01",
            Self::Metronotes => "AsciiIdentifierMetronotes",
            Self::Other => "AsciiIdentifierOther",
            Self::Unknown => "AsciiIdentifierUnknown",
        }
    }
}

impl std::fmt::Display for AsciiIdentifierVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl From<AsciiIdentifierVariant> for ProtocolVariant {
    fn from(variant: AsciiIdentifierVariant) -> Self {
        match variant {
            AsciiIdentifierVariant::TB0001 => ProtocolVariant::AsciiIdentifierTB0001,
            AsciiIdentifierVariant::TEST01 => ProtocolVariant::AsciiIdentifierTEST01,
            AsciiIdentifierVariant::Metronotes => ProtocolVariant::AsciiIdentifierMetronotes,
            AsciiIdentifierVariant::Other => ProtocolVariant::AsciiIdentifierOther,
            AsciiIdentifierVariant::Unknown => ProtocolVariant::AsciiIdentifierUnknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_display_names() {
        assert_eq!(AsciiIdentifierVariant::TB0001.display_name(), "TB0001");
        assert_eq!(AsciiIdentifierVariant::TEST01.display_name(), "TEST01");
        assert_eq!(
            AsciiIdentifierVariant::Metronotes.display_name(),
            "Metronotes"
        );
        assert_eq!(
            AsciiIdentifierVariant::Other.display_name(),
            "Other ASCII Protocol"
        );
        assert_eq!(
            AsciiIdentifierVariant::Unknown.display_name(),
            "Unknown Variant"
        );
    }

    #[test]
    fn test_variant_to_protocol_variant() {
        assert_eq!(
            ProtocolVariant::from(AsciiIdentifierVariant::TB0001),
            ProtocolVariant::AsciiIdentifierTB0001
        );
        assert_eq!(
            ProtocolVariant::from(AsciiIdentifierVariant::TEST01),
            ProtocolVariant::AsciiIdentifierTEST01
        );
        assert_eq!(
            ProtocolVariant::from(AsciiIdentifierVariant::Metronotes),
            ProtocolVariant::AsciiIdentifierMetronotes
        );
    }
}
