//! Debug display types for verbose transaction decoding output
//!
//! These types capture detailed information about the P2MS decoding process,
//! especially for protocols like Counterparty that use ARC4 obfuscation.
//!
//! **Note**: Impl blocks for these types remain in `crate::decoder::debug_display`
//! where they have access to decoder-specific logic.

/// Information about a single P2MS output during decoding
#[derive(Debug, Clone)]
pub struct P2MSOutputDebugInfo {
    /// Output index (vout)
    pub vout: u32,
    /// Multisig type description (e.g., "1-of-3", "2-of-3")
    pub multisig_type: String,
    /// Number of pubkeys
    pub pubkey_count: usize,
    /// First few bytes of each pubkey (for display)
    pub pubkey_previews: Vec<String>,
    /// Data extraction method used
    pub extraction_method: String,
    /// Raw data extracted from this output (before decryption)
    pub raw_chunk: Vec<u8>,
    /// Decrypted data from this output (if applicable)
    pub decrypted_chunk: Option<Vec<u8>>,
    /// Whether this output contains the CNTRPRTY prefix
    pub has_cntrprty_prefix: bool,
    /// Length prefix found (if this is the first output)
    pub length_prefix: Option<u8>,
    /// Whether this output contains a stamp signature
    pub has_stamp_signature: bool,
    /// Stamp signature details: (variant_name, offset)
    pub stamp_signature: Option<(String, usize)>,
    /// Special notes about this output
    pub notes: Vec<String>,
}

/// Debug information for the entire transaction decoding process
#[derive(Debug, Clone)]
pub struct TransactionDebugInfo {
    pub txid: String,
    pub protocol: String,
    pub p2ms_outputs: Vec<P2MSOutputDebugInfo>,
    pub total_raw_data: usize,
    pub total_decrypted_data: usize,
    pub arc4_key_txid: Option<String>,
    pub message_type: Option<String>,
}
