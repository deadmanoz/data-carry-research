//! Shared pubkey extraction utilities for protocol detection
//!
//! This module consolidates common patterns for extracting data from P2MS pubkeys
//! across multiple protocols (Counterparty, Bitcoin Stamps, Omni, Chancecoin, etc.).
//!
//! ## Common Patterns
//!
//! - **Compressed keys (33 bytes)**: Standard Bitcoin compressed pubkeys
//! - **Uncompressed keys (65 bytes)**: Legacy Bitcoin uncompressed pubkeys
//! - **Length-prefixed**: First byte indicates data length (Counterparty 1-of-2, Chancecoin)
//! - **Range extraction**: Extract specific byte ranges for protocol data

/// Utility for extracting data from multisig pubkeys
pub struct PubkeyExtractor;

impl PubkeyExtractor {
    /// Extract data from a compressed pubkey (33 bytes)
    ///
    /// Compressed pubkeys: `0x02` or `0x03` prefix + 32-byte X coordinate
    ///
    /// # Arguments
    /// * `pubkey_hex` - Hex-encoded pubkey string
    /// * `skip_prefix` - If true, skip first byte (0x02/0x03 prefix)
    ///
    /// # Returns
    /// * `Some(Vec<u8>)` - Extracted data (32 bytes if skip_prefix, 33 if not)
    /// * `None` - Invalid hex or wrong length
    ///
    /// # Example
    /// ```ignore
    /// // Extract 32 bytes of data (skip 0x02/0x03 prefix)
    /// let data = PubkeyExtractor::extract_compressed(pubkey, true)?;
    /// ```
    pub fn extract_compressed(pubkey_hex: &str, skip_prefix: bool) -> Option<Vec<u8>> {
        let bytes = hex::decode(pubkey_hex).ok()?;

        if bytes.len() != 33 {
            return None;
        }

        Some(if skip_prefix {
            bytes[1..].to_vec()
        } else {
            bytes
        })
    }

    /// Extract data from an uncompressed pubkey (65 bytes)
    ///
    /// Uncompressed pubkeys: `0x04` prefix + 32-byte X + 32-byte Y coordinates
    ///
    /// # Arguments
    /// * `pubkey_hex` - Hex-encoded pubkey string
    /// * `skip_prefix` - If true, skip first byte (0x04 prefix)
    ///
    /// # Returns
    /// * `Some(Vec<u8>)` - Extracted data (64 bytes if skip_prefix, 65 if not)
    /// * `None` - Invalid hex or wrong length
    pub fn extract_uncompressed(pubkey_hex: &str, skip_prefix: bool) -> Option<Vec<u8>> {
        let bytes = hex::decode(pubkey_hex).ok()?;

        if bytes.len() != 65 {
            return None;
        }

        Some(if skip_prefix {
            bytes[1..].to_vec()
        } else {
            bytes
        })
    }

    /// Extract data with length prefix (Counterparty 1-of-2, Chancecoin pattern)
    ///
    /// Format: `[length_byte][data...]`
    /// - First byte indicates how many data bytes follow
    /// - Used in Counterparty 1-of-2 multisig and Chancecoin protocols
    ///
    /// # Arguments
    /// * `pubkey_hex` - Hex-encoded pubkey string
    ///
    /// # Returns
    /// * `Some(Vec<u8>)` - Data bytes (excluding length prefix)
    /// * `None` - Invalid hex, length prefix exceeds available data
    ///
    /// # Example
    /// ```ignore
    /// // Pubkey: [0x20, ...32 bytes of data...]
    /// // Returns: Vec<u8> with 32 bytes (0x20 = 32)
    /// let data = PubkeyExtractor::extract_with_length_prefix(pubkey)?;
    /// ```
    pub fn extract_with_length_prefix(pubkey_hex: &str) -> Option<Vec<u8>> {
        let bytes = hex::decode(pubkey_hex).ok()?;

        if bytes.len() < 2 {
            return None;
        }

        let length = bytes[0] as usize;

        // Validate length doesn't exceed available data
        if length > bytes.len() - 1 {
            return None;
        }

        Some(bytes[1..=length].to_vec())
    }

    /// Extract data from a specific byte range
    ///
    /// Generic extraction for arbitrary byte ranges within a pubkey.
    /// Commonly used for extracting signature markers or specific data offsets.
    ///
    /// # Arguments
    /// * `pubkey_hex` - Hex-encoded pubkey string
    /// * `start` - Start byte index (inclusive)
    /// * `end` - End byte index (exclusive)
    ///
    /// # Returns
    /// * `Some(Vec<u8>)` - Extracted bytes from [start..end)
    /// * `None` - Invalid hex or range exceeds pubkey length
    ///
    /// # Example
    /// ```ignore
    /// // Extract bytes 1-7 for signature detection
    /// let sig = PubkeyExtractor::extract_range(pubkey, 1, 7)?;
    /// ```
    pub fn extract_range(pubkey_hex: &str, start: usize, end: usize) -> Option<Vec<u8>> {
        let bytes = hex::decode(pubkey_hex).ok()?;

        if end > bytes.len() || start >= end {
            return None;
        }

        Some(bytes[start..end].to_vec())
    }

    /// Extract standard Bitcoin Stamps data chunk (bytes 1-31 from 33-byte key)
    ///
    /// Bitcoin Stamps uses compressed pubkeys with:
    /// - Byte 0: Prefix (0x02 or 0x03)
    /// - Bytes 1-31: Data payload (31 bytes)
    /// - Byte 32: Checksum/suffix
    ///
    /// This is equivalent to `extract_range(pubkey, 1, 32)` but more explicit.
    ///
    /// # Arguments
    /// * `pubkey_hex` - Hex-encoded compressed pubkey (33 bytes)
    ///
    /// # Returns
    /// * `Some(Vec<u8>)` - 31 bytes of data payload
    /// * `None` - Invalid hex or not a 33-byte compressed key
    pub fn extract_stamps_chunk(pubkey_hex: &str) -> Option<Vec<u8>> {
        let bytes = hex::decode(pubkey_hex).ok()?;

        if bytes.len() != 33 {
            return None;
        }

        // Extract bytes 1-31 (skip prefix byte 0, skip suffix byte 32)
        Some(bytes[1..32].to_vec())
    }

    /// Extract Counterparty/Omni P2MS data chunk (bytes 1-31 from 33-byte key)
    ///
    /// Similar to Bitcoin Stamps but used in Counterparty/Omni Layer protocols.
    /// Extracts 31 bytes of payload data from compressed pubkey.
    ///
    /// This is an alias for `extract_stamps_chunk()` - same format, different protocol.
    ///
    /// # Arguments
    /// * `pubkey_hex` - Hex-encoded compressed pubkey (33 bytes)
    ///
    /// # Returns
    /// * `Some(Vec<u8>)` - 31 bytes of data payload
    /// * `None` - Invalid hex or not a 33-byte compressed key
    pub fn extract_p2ms_chunk(pubkey_hex: &str) -> Option<Vec<u8>> {
        Self::extract_stamps_chunk(pubkey_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_compressed_with_prefix() {
        let pubkey = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let data = PubkeyExtractor::extract_compressed(pubkey, false).unwrap();
        assert_eq!(data.len(), 33);
        assert_eq!(data[0], 0x02);
    }

    #[test]
    fn test_extract_compressed_skip_prefix() {
        let pubkey = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let data = PubkeyExtractor::extract_compressed(pubkey, true).unwrap();
        assert_eq!(data.len(), 32);
        assert!(data.iter().all(|&b| b == 0xaa));
    }

    #[test]
    fn test_extract_compressed_invalid_length() {
        let pubkey = "02aaaa"; // Too short
        assert!(PubkeyExtractor::extract_compressed(pubkey, false).is_none());
    }

    #[test]
    fn test_extract_uncompressed() {
        let pubkey = format!("04{}", "aa".repeat(64));
        let data = PubkeyExtractor::extract_uncompressed(&pubkey, true).unwrap();
        assert_eq!(data.len(), 64);
    }

    #[test]
    fn test_extract_with_length_prefix() {
        // Length byte = 0x20 (32), followed by 32 bytes
        let pubkey = format!("20{}", "bb".repeat(32));
        let data = PubkeyExtractor::extract_with_length_prefix(&pubkey).unwrap();
        assert_eq!(data.len(), 32);
        assert!(data.iter().all(|&b| b == 0xbb));
    }

    #[test]
    fn test_extract_with_length_prefix_exceeds() {
        // Length byte says 50 bytes but only 32 bytes available
        let pubkey = format!("32{}", "cc".repeat(32));
        assert!(PubkeyExtractor::extract_with_length_prefix(&pubkey).is_none());
    }

    #[test]
    fn test_extract_range() {
        let pubkey = "02aabbccddeeff00112233445566778899";
        let data = PubkeyExtractor::extract_range(pubkey, 1, 7).unwrap();
        assert_eq!(data, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_extract_range_invalid() {
        let pubkey = "02aabbccdd";
        assert!(PubkeyExtractor::extract_range(pubkey, 0, 100).is_none());
        assert!(PubkeyExtractor::extract_range(pubkey, 5, 3).is_none()); // start > end
    }

    #[test]
    fn test_extract_stamps_chunk() {
        let pubkey = format!("02{}ff", "aa".repeat(31));
        let data = PubkeyExtractor::extract_stamps_chunk(&pubkey).unwrap();
        assert_eq!(data.len(), 31);
        assert!(data.iter().all(|&b| b == 0xaa));
    }

    #[test]
    fn test_extract_p2ms_chunk_alias() {
        let pubkey = format!("03{}ee", "bb".repeat(31));
        let data = PubkeyExtractor::extract_p2ms_chunk(&pubkey).unwrap();
        assert_eq!(data.len(), 31);
        assert!(data.iter().all(|&b| b == 0xbb));
    }
}
