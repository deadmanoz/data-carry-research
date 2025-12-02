//! Helper functions for Bitcoin Stamps validation
//!
//! Low-level utility functions for P2MS validation and data extraction.

use crate::shared::PubkeyExtractor;
use crate::types::burn_patterns::STAMPS_BURN_KEYS;
use crate::types::stamps::src20::encoding;
use base64::{
    alphabet,
    engine::{self, general_purpose::GeneralPurpose, GeneralPurposeConfig},
};

/// Base64 decoder with lenient padding (Bitcoin Stamps often omit padding)
///
/// This is the CANONICAL base64 decoder for Bitcoin Stamps throughout the codebase.
/// Use this instead of STANDARD to handle stamps that omit trailing '=' padding.
///
/// **Why lenient?** Bitcoin Stamps frequently omit base64 padding characters,
/// causing `base64::engine::general_purpose::STANDARD.decode()` to fail.
/// This decoder accepts both padded and unpadded base64.
///
/// **Usage locations**:
/// - Stage 3 classification (stamps.rs) - content type detection
/// - Decoder (decoder/mod.rs) - image extraction
/// - Variant detection (stamps.rs validation) - format identification
pub const BASE64_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(engine::DecodePaddingMode::Indifferent),
);

/// Check for ZLIB compression at specific offsets with checksum validation
///
/// ZLIB detection at multiple offsets catches real-world compressed data:
/// - Offset 0: Standard position for ZLIB headers
/// - Offset 5: Empirical pattern observed in 10 Unknown outputs (heights 300112-327241)
/// - Offset 7: Additional empirical pattern observed in Unknown outputs
///
/// Validates CMF-FLG checksum: (CMF * 256 + FLG) % 31 == 0
pub fn check_zlib_at_offsets(data: &[u8], offsets: &[usize]) -> bool {
    for &offset in offsets {
        // Require at least 4 bytes (header + minimal data) to avoid false positives
        if data.len() >= offset + 4 {
            let cmf = data[offset];
            let flg = data[offset + 1];

            // ZLIB CMF byte check (0x78 for deflate with 32K window)
            if cmf == 0x78 {
                // Validate CMF-FLG checksum: (CMF * 256 + FLG) % 31 == 0
                if ((cmf as u16) * 256 + (flg as u16)).is_multiple_of(31) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a P2MS output matches Bitcoin Stamps pattern
pub fn is_stamps_p2ms(required_sigs: u8, total_pubkeys: u8, pubkeys: &[String]) -> bool {
    required_sigs == encoding::REQUIRED_SIGS
        && total_pubkeys == encoding::TOTAL_PUBKEYS
        && pubkeys.len() == encoding::TOTAL_PUBKEYS as usize
        && pubkeys.get(2).is_some_and(|pk| is_stamps_burn_key(pk))
}

/// Check if a pubkey is a known Bitcoin Stamps burn key
pub fn is_stamps_burn_key(pubkey_hex: &str) -> bool {
    STAMPS_BURN_KEYS
        .iter()
        .any(|k| k.eq_ignore_ascii_case(pubkey_hex))
}

/// Extract data chunk from first two pubkeys of a P2MS output
pub fn extract_data_chunk(pubkeys: &[String]) -> Option<Vec<u8>> {
    if pubkeys.len() < 2 {
        return None;
    }

    // Extract 31 bytes from each of the first two pubkeys (Bitcoin Stamps encoding)
    let chunk1 = PubkeyExtractor::extract_stamps_chunk(&pubkeys[0])?;
    let chunk2 = PubkeyExtractor::extract_stamps_chunk(&pubkeys[1])?;

    let mut chunk = Vec::with_capacity(encoding::DATA_BYTES_PER_OUTPUT);
    chunk.extend_from_slice(&chunk1);
    chunk.extend_from_slice(&chunk2);

    Some(chunk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_stamps_burn_key() {
        assert!(is_stamps_burn_key(
            "022222222222222222222222222222222222222222222222222222222222222222"
        ));
        assert!(is_stamps_burn_key(
            "033333333333333333333333333333333333333333333333333333333333333333"
        ));
        assert!(!is_stamps_burn_key(
            "020000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_stamps_p2ms_validation() {
        let pubkeys = vec![
            "03aaaa...".to_string(),
            "03bbbb...".to_string(),
            "022222222222222222222222222222222222222222222222222222222222222222".to_string(),
        ];
        assert!(is_stamps_p2ms(1, 3, &pubkeys));
        assert!(!is_stamps_p2ms(2, 3, &pubkeys)); // Wrong required_sigs
    }
}
