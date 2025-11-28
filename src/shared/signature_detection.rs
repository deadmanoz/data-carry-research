//! Shared signature detection utilities for protocol identification
//!
//! This module consolidates common patterns for detecting protocol signatures
//! in P2MS pubkeys and decrypted data across multiple protocols.
//!
//! ## Common Detection Patterns
//!
//! - **Prefix matching**: Check if data starts with signature (e.g., `data.starts_with(b"CLIPPERZ")`)
//! - **Offset matching**: Check signature at specific byte offset (e.g., `bytes[1..7] == b"TB0001"`)
//! - **Window search**: Find signature anywhere in data (e.g., `windows().any(|w| w == signature)`)
//! - **Range search**: Find signature within specific byte range

/// Utility for detecting protocol signatures in binary data
pub struct SignatureDetector;

impl SignatureDetector {
    /// Check if data starts with a specific signature
    ///
    /// Efficient prefix matching for protocols that place signatures at the beginning.
    ///
    /// # Arguments
    /// * `data` - Binary data to check
    /// * `signature` - Expected signature bytes
    ///
    /// # Returns
    /// * `true` if data starts with signature, `false` otherwise
    ///
    /// # Example
    /// ```ignore
    /// // Check for CLIPPERZ protocol signature
    /// let has_clipperz = SignatureDetector::has_prefix(data, b"CLIPPERZ");
    /// ```
    pub fn has_prefix(data: &[u8], signature: &[u8]) -> bool {
        data.starts_with(signature)
    }

    /// Check if signature exists at a specific offset in the data
    ///
    /// Used for protocols that place signatures at fixed positions (e.g., TB0001, TEST01).
    ///
    /// # Arguments
    /// * `data` - Binary data to check
    /// * `offset_start` - Start byte index (inclusive)
    /// * `offset_end` - End byte index (exclusive)
    /// * `signature` - Expected signature bytes
    ///
    /// # Returns
    /// * `true` if signature found at specified offset, `false` otherwise
    ///
    /// # Example
    /// ```ignore
    /// // Check for TB0001 signature at bytes 1-7 in pubkey
    /// let has_tb0001 = SignatureDetector::has_at_offset(pubkey_bytes, 1, 7, b"TB0001");
    /// ```
    pub fn has_at_offset(
        data: &[u8],
        offset_start: usize,
        offset_end: usize,
        signature: &[u8],
    ) -> bool {
        if offset_end > data.len() || offset_start >= offset_end {
            return false;
        }

        let expected_len = offset_end - offset_start;
        if signature.len() != expected_len {
            return false;
        }

        &data[offset_start..offset_end] == signature
    }

    /// Find the offset where signature first appears in data
    ///
    /// Scans through data using sliding window to find signature location.
    ///
    /// # Arguments
    /// * `data` - Binary data to search
    /// * `signature` - Signature bytes to find
    ///
    /// # Returns
    /// * `Some(offset)` - Byte offset where signature starts
    /// * `None` - Signature not found
    ///
    /// # Example
    /// ```ignore
    /// // Find "stamp:" signature in decrypted Stamps data
    /// if let Some(offset) = SignatureDetector::find_signature(data, b"stamp:") {
    ///     println!("Stamp signature found at offset {}", offset);
    /// }
    /// ```
    pub fn find_signature(data: &[u8], signature: &[u8]) -> Option<usize> {
        if signature.is_empty() || data.len() < signature.len() {
            return None;
        }

        data.windows(signature.len())
            .position(|window| window == signature)
    }

    /// Check if signature exists anywhere in the data
    ///
    /// Efficient check without returning position. Uses sliding window search.
    ///
    /// # Arguments
    /// * `data` - Binary data to search
    /// * `signature` - Signature bytes to find
    ///
    /// # Returns
    /// * `true` if signature found anywhere in data, `false` otherwise
    ///
    /// # Example
    /// ```ignore
    /// // Check if Counterparty signature exists anywhere in decrypted data
    /// let has_cntrprty = SignatureDetector::has_at_any_offset(data, b"CNTRPRTY");
    /// ```
    pub fn has_at_any_offset(data: &[u8], signature: &[u8]) -> bool {
        if signature.is_empty() || data.len() < signature.len() {
            return false;
        }

        data.windows(signature.len())
            .any(|window| window == signature)
    }

    /// Check if signature exists within a specific byte range
    ///
    /// Useful for protocols with bounded signature positions (e.g., compression headers).
    ///
    /// # Arguments
    /// * `data` - Binary data to search
    /// * `range_start` - Start of search range (inclusive)
    /// * `range_end` - End of search range (exclusive), or None for end of data
    /// * `signature` - Signature bytes to find
    ///
    /// # Returns
    /// * `true` if signature found within specified range, `false` otherwise
    ///
    /// # Example
    /// ```ignore
    /// // Check for ZLIB header within first 32 bytes
    /// let has_zlib = SignatureDetector::has_within_range(data, 0, Some(32), &[0x78, 0x9c]);
    /// ```
    pub fn has_within_range(
        data: &[u8],
        range_start: usize,
        range_end: Option<usize>,
        signature: &[u8],
    ) -> bool {
        if range_start >= data.len() || signature.is_empty() {
            return false;
        }

        let end = range_end.unwrap_or(data.len()).min(data.len());
        if range_start >= end || end - range_start < signature.len() {
            return false;
        }

        let search_slice = &data[range_start..end];
        Self::has_at_any_offset(search_slice, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_prefix() {
        let data = b"CLIPPERZ 1.0 REG extra data";
        assert!(SignatureDetector::has_prefix(data, b"CLIPPERZ"));
        assert!(SignatureDetector::has_prefix(data, b"CLIPPERZ 1.0"));
        assert!(!SignatureDetector::has_prefix(data, b"INVALID"));
        assert!(!SignatureDetector::has_prefix(
            b"SHORT",
            b"LONGER_SIGNATURE"
        ));
    }

    #[test]
    fn test_has_at_offset() {
        let data = b"\x02TB0001data here";
        // TB0001 signature at bytes 1-7
        assert!(SignatureDetector::has_at_offset(data, 1, 7, b"TB0001"));
        // Wrong offset
        assert!(!SignatureDetector::has_at_offset(data, 0, 6, b"TB0001"));
        // Out of bounds
        assert!(!SignatureDetector::has_at_offset(data, 10, 100, b"TB0001"));
        // Wrong signature length
        assert!(!SignatureDetector::has_at_offset(data, 1, 7, b"WRONG"));
    }

    #[test]
    fn test_find_signature() {
        let data = b"prefix CNTRPRTY suffix data";
        assert_eq!(
            SignatureDetector::find_signature(data, b"CNTRPRTY"),
            Some(7)
        );
        assert_eq!(SignatureDetector::find_signature(data, b"prefix"), Some(0));
        assert_eq!(SignatureDetector::find_signature(data, b"suffix"), Some(16));
        assert_eq!(SignatureDetector::find_signature(data, b"NOTFOUND"), None);
    }

    #[test]
    fn test_has_at_any_offset() {
        let data = b"some data with STAMP: signature inside";
        assert!(SignatureDetector::has_at_any_offset(data, b"STAMP:"));
        assert!(SignatureDetector::has_at_any_offset(data, b"some"));
        assert!(SignatureDetector::has_at_any_offset(data, b"inside"));
        assert!(!SignatureDetector::has_at_any_offset(data, b"NOTFOUND"));
        assert!(!SignatureDetector::has_at_any_offset(
            b"short",
            b"longer_signature"
        ));
    }

    #[test]
    fn test_has_within_range() {
        let data = b"header ZLIB data at offset 10: \x78\x9crest of data";

        // ZLIB header within first 50 bytes
        assert!(SignatureDetector::has_within_range(
            data,
            0,
            Some(50),
            &[0x78, 0x9c]
        ));

        // ZLIB header NOT in first 10 bytes
        assert!(!SignatureDetector::has_within_range(
            data,
            0,
            Some(10),
            &[0x78, 0x9c]
        ));

        // Search from offset 30 to end
        assert!(SignatureDetector::has_within_range(
            data,
            30,
            None,
            &[0x78, 0x9c]
        ));

        // Out of bounds range
        assert!(!SignatureDetector::has_within_range(
            data,
            100,
            Some(200),
            b"test"
        ));
    }

    #[test]
    fn test_edge_cases() {
        let data = b"test data";

        // Empty signature
        assert!(!SignatureDetector::has_at_any_offset(data, b""));
        assert_eq!(SignatureDetector::find_signature(data, b""), None);

        // Empty data
        assert!(!SignatureDetector::has_at_any_offset(b"", b"test"));
        assert!(!SignatureDetector::has_prefix(b"", b"test"));

        // Exact match
        assert!(SignatureDetector::has_prefix(b"test", b"test"));
        assert_eq!(SignatureDetector::find_signature(b"test", b"test"), Some(0));
    }
}
