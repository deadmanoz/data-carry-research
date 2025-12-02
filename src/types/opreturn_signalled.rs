//! OP_RETURN Signalled protocol type definitions
//!
//! Defines variants for protocols that use OP_RETURN outputs to signal
//! the presence of data in accompanying P2MS outputs.

use super::ProtocolVariant;
use serde::{Deserialize, Serialize};

/// OP_RETURN signalled protocol constants
pub mod constants {
    /// Protocol 47930 marker (0xbb3a in OP_RETURN)
    pub const PROTOCOL_47930_MARKER: &[u8] = &[0xbb, 0x3a];

    /// CLIPPERZ notarisation marker
    pub const CLIPPERZ_MARKER: &[u8] = b"CLIPPERZ";
}

/// OpReturnSignalled variant types
///
/// These variants represent protocols that use OP_RETURN outputs
/// to signal or identify data stored in P2MS outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpReturnVariant {
    /// Protocol 47930 (0xbb3a marker)
    ///
    /// Detected by 0xbb3a marker in OP_RETURN + 2-of-2 P2MS.
    /// ~9000 satoshi outputs, blocks 554753+.
    Protocol47930,

    /// CLIPPERZ notarisation service
    ///
    /// Detected by "CLIPPERZ" ASCII in OP_RETURN + 2-of-2 P2MS.
    /// 238 transactions, blocks 403627-443835.
    CLIPPERZ,

    /// Generic ASCII OP_RETURN protocols
    ///
    /// Catch-all for one-off protocols with ASCII signatures in OP_RETURN.
    /// Examples: PRVCY, unsuccessful, @DEVCHA, etc.
    GenericASCII,
}

impl OpReturnVariant {
    /// Get the display name for this variant
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Protocol47930 => "Protocol47930",
            Self::CLIPPERZ => "CLIPPERZ",
            Self::GenericASCII => "GenericASCII",
        }
    }
}

impl std::fmt::Display for OpReturnVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl From<OpReturnVariant> for ProtocolVariant {
    fn from(variant: OpReturnVariant) -> Self {
        match variant {
            OpReturnVariant::Protocol47930 => ProtocolVariant::OpReturnProtocol47930,
            OpReturnVariant::CLIPPERZ => ProtocolVariant::OpReturnCLIPPERZ,
            OpReturnVariant::GenericASCII => ProtocolVariant::OpReturnGenericASCII,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_display_names() {
        assert_eq!(
            OpReturnVariant::Protocol47930.display_name(),
            "Protocol47930"
        );
        assert_eq!(OpReturnVariant::CLIPPERZ.display_name(), "CLIPPERZ");
        assert_eq!(OpReturnVariant::GenericASCII.display_name(), "GenericASCII");
    }

    #[test]
    fn test_variant_to_protocol_variant() {
        assert_eq!(
            ProtocolVariant::from(OpReturnVariant::Protocol47930),
            ProtocolVariant::OpReturnProtocol47930
        );
        assert_eq!(
            ProtocolVariant::from(OpReturnVariant::CLIPPERZ),
            ProtocolVariant::OpReturnCLIPPERZ
        );
        assert_eq!(
            ProtocolVariant::from(OpReturnVariant::GenericASCII),
            ProtocolVariant::OpReturnGenericASCII
        );
    }
}
