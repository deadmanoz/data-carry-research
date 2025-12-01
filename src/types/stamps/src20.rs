//! SRC-20 token types and P2MS encoding specifications
//!
//! SRC-20 is a fungible token standard on Bitcoin Stamps.

use serde::{Deserialize, Serialize};

/// SRC-20 token operation types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SRC20Operation {
    /// Deploy a new SRC-20 token
    Deploy,
    /// Mint tokens to an address
    Mint,
    /// Transfer tokens between addresses
    Transfer,
}

/// P2MS encoding specifications for Bitcoin Stamps
pub mod encoding {
    /// Standard P2MS pattern for Bitcoin Stamps: 1-of-3 multisig
    pub const REQUIRED_SIGS: u8 = 1;
    pub const TOTAL_PUBKEYS: u8 = 3;

    /// Data capacity per P2MS output (first two 33-byte pubkeys, minus prefix/suffix bytes)
    pub const DATA_BYTES_PER_OUTPUT: usize = 62; // 31 bytes per pubkey * 2 pubkeys

    /// Pubkey structure: 33 bytes total, data in bytes 1-31 (excluding first and last byte)
    pub const PUBKEY_TOTAL_BYTES: usize = 33;
    pub const PUBKEY_DATA_START: usize = 1;
    pub const PUBKEY_DATA_END: usize = 32;
}
