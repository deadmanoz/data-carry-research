//! Shared DataStorage helpers used by both Stage 3 classification and Stage 4 decoding.
//!
//! These functions are pure, decoder-agnostic utilities that eliminate duplication
//! between `src/processor/stage3/datastorage.rs` and `src/decoder/datastorage.rs`.

use crate::types::content_detection::{detect_image_format, ImageFormat};

/// Extract data from a pubkey hex string.
///
/// Handles various pubkey formats:
/// - 20-byte data segments (like Chancecoin)
/// - 33-byte compressed pubkeys or raw data
/// - 65-byte uncompressed pubkeys or raw data
/// - 32-byte chunks (sometimes used without prefix)
/// - Other lengths (>=10 bytes) for non-standard data
///
/// Returns `None` for data too short to be meaningful (<10 bytes for non-standard lengths).
pub fn extract_key_data(pubkey_hex: &str) -> Option<Vec<u8>> {
    let pubkey_bytes = hex::decode(pubkey_hex).ok()?;

    match pubkey_bytes.len() {
        20 => {
            // 20-byte data segment (like Chancecoin)
            // These are raw data, not pubkeys, so return as-is
            Some(pubkey_bytes)
        }
        33 => {
            // 33-byte chunks: could be compressed pubkey OR raw data
            // For DataStorage, accept ALL 33 bytes regardless of prefix
            Some(pubkey_bytes)
        }
        65 => {
            // 65-byte chunks: could be uncompressed pubkey OR raw data
            // For DataStorage, accept ALL 65 bytes regardless of prefix
            Some(pubkey_bytes)
        }
        32 => {
            // 32-byte chunks (sometimes used without prefix)
            Some(pubkey_bytes)
        }
        _ => {
            // Other lengths: accept if reasonable size (>=10 bytes)
            // This handles non-standard push sizes (e.g., PDF chunks, custom encoding)
            if pubkey_bytes.len() >= 10 {
                Some(pubkey_bytes)
            } else {
                None // Too short to be meaningful data
            }
        }
    }
}

/// Check if data represents a burn pattern.
///
/// Handles:
/// - Pure 32-byte 0xFF pattern
/// - 33-byte compressed key with prefix (0x02/0x03) + 32 bytes of 0xFF
/// - 65-byte uncompressed key with prefix (0x04) + 64 bytes of 0xFF
/// - Structured burn patterns (0305... with trailing zeros, 04cccccccd...)
///
/// # Arguments
/// * `data` - The raw data bytes
/// * `pubkey_hex` - Optional pubkey hex string for structured pattern detection
pub fn is_burn_pattern(data: &[u8], pubkey_hex: Option<&str>) -> bool {
    match data.len() {
        32 => {
            // Pure 32-byte 0xFF pattern
            data.iter().all(|&b| b == 0xFF)
        }
        33 => {
            // Compressed pubkey burn: prefix (0x02 or 0x03) + 32 bytes of 0xFF
            (data[0] == 0x02 || data[0] == 0x03) && data[1..].iter().all(|&b| b == 0xFF)
        }
        65 => {
            // Uncompressed pubkey burn: prefix (0x04) + 64 bytes of 0xFF
            data[0] == 0x04 && data[1..].iter().all(|&b| b == 0xFF)
        }
        _ => {
            // Structured burn patterns (protocol-specific)
            if let Some(hex) = pubkey_hex {
                if data.len() > 1 && hex.starts_with("0305") && data[1..].iter().all(|&b| b == 0x00)
                {
                    return true;
                }
                if hex.starts_with("04cccccccd") {
                    return true;
                }
            }
            false
        }
    }
}

/// Detect binary file type from magic numbers.
///
/// Returns the file type as a static string if a known signature is found.
/// Supports: PDF, PNG, JPEG, GIF, ZIP, RAR, 7Z, GZIP, BZIP2, ZLIB, TAR.
///
/// Note: ZLIB detection checks offset 0 (standard), offset 5, and offset 7
/// based on empirical patterns observed in blockchain data.
pub fn detect_binary_signature(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    // Archive detection FIRST - prevents ZIP/RAR with "%PDF" payload misclassification
    // This mirrors the archive-first skip in content_detection::detect_document()
    const ARCHIVE_SIGNATURES: &[(&[u8], &str)] = &[
        (&[0x50, 0x4B], "ZIP"),                        // ZIP (PK)
        (b"Rar!", "RAR"),                              // RAR
        (&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], "7Z"), // 7-Zip
    ];

    for (sig, name) in ARCHIVE_SIGNATURES {
        if data.len() >= sig.len() && data.starts_with(sig) {
            return Some(name);
        }
    }

    // PDF: %PDF (0x25 0x50 0x44 0x46)
    // Search in windows since PDF header might not be at start of chunk
    // Safe to check now - archives already handled above
    let search_len = data.len().min(1024);
    if data[..search_len].windows(4).any(|w| w == b"%PDF") {
        return Some("PDF");
    }

    // Image detection via content_detection module (offset 0 - standard case)
    // ONLY map legacy formats that datastorage_helpers previously detected (PNG/JPEG/GIF)
    // DO NOT expose new formats (TIFF, ICO, AVIF, JpegXl) to avoid classification changes
    if let Some(image_format) = detect_image_format(data) {
        match image_format {
            ImageFormat::Png => return Some("PNG"),
            ImageFormat::Jpeg => return Some("JPEG"),
            ImageFormat::Gif => return Some("GIF"),
            // New formats NOT mapped - fall through to continue with archive/compression detection
            _ => {}
        }
    }

    // Image detection at offset 1: After EC point prefix (02/03/04)
    // P2MS outputs store data in pubkey slots where byte 0 is the EC point marker.
    // Similar pattern to ZLIB multi-offset detection below.
    // Example: height 690497 has JPEG magic at offset 1 after 0x04 prefix.
    if data.len() >= 4 && matches!(data[0], 0x02 | 0x03 | 0x04) {
        // JPEG: FF D8 FF at offset 1
        if data[1..4] == [0xFF, 0xD8, 0xFF] {
            return Some("JPEG");
        }
        // PNG: 89 50 4E 47 0D 0A 1A 0A at offset 1
        if data.len() >= 9 && data[1..9] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            return Some("PNG");
        }
        // GIF: GIF87a or GIF89a at offset 1
        if data.len() >= 7 && (&data[1..7] == b"GIF87a" || &data[1..7] == b"GIF89a") {
            return Some("GIF");
        }
    }

    // Note: ZIP/RAR/7Z detection moved to top of function (archive-first pattern)

    // GZIP: 0x1f 0x8b 0x08 (most common, third byte is compression method DEFLATE)
    // Search in windows since GZIP header might not be at start of chunk
    if data.windows(3).any(|w| w == [0x1f, 0x8b, 0x08]) {
        return Some("GZIP");
    }

    // BZIP2: BZh[1-9] (0x42 0x5a 0x68 followed by block size 1-9)
    if data.len() >= 4
        && data[0] == 0x42
        && data[1] == 0x5a
        && data[2] == 0x68
        && (0x31..=0x39).contains(&data[3])
    {
        return Some("BZIP2");
    }

    // ZLIB: Check offset 0 (standard), offset 5, and offset 7 (empirical patterns)
    // Verify FLG byte checksum: (CMF * 256 + FLG) must be divisible by 31
    if data.len() >= 2 && data[0] == 0x78 {
        let cmf_flg = (data[0] as u16) * 256 + (data[1] as u16);
        if cmf_flg % 31 == 0 {
            return Some("ZLIB");
        }
    }
    if data.len() >= 7 && data[5] == 0x78 {
        let cmf_flg = (data[5] as u16) * 256 + (data[6] as u16);
        if cmf_flg % 31 == 0 {
            return Some("ZLIB");
        }
    }
    if data.len() >= 9 && data[7] == 0x78 {
        let cmf_flg = (data[7] as u16) * 256 + (data[8] as u16);
        if cmf_flg % 31 == 0 {
            return Some("ZLIB");
        }
    }

    // TAR: ustar magic at offset 257
    // POSIX standard: "ustar\0" or "ustar  " (with spaces)
    if data.len() >= 263 && &data[257..262] == b"ustar" {
        // Verify next byte is either NUL or space to distinguish from random data
        if data[262] == 0x00 || data[262] == b' ' {
            return Some("TAR");
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_key_data_33_bytes() {
        // 33-byte compressed pubkey
        let hex = "02".to_string() + &"ff".repeat(32);
        let result = extract_key_data(&hex);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 33);
    }

    #[test]
    fn test_extract_key_data_65_bytes() {
        // 65-byte uncompressed pubkey
        let hex = "04".to_string() + &"ab".repeat(64);
        let result = extract_key_data(&hex);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 65);
    }

    #[test]
    fn test_extract_key_data_20_bytes() {
        // 20-byte data segment
        let hex = "ab".repeat(20);
        let result = extract_key_data(&hex);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 20);
    }

    #[test]
    fn test_extract_key_data_too_short() {
        // Too short
        let hex = "abcd";
        let result = extract_key_data(hex);
        assert!(result.is_none());
    }

    #[test]
    fn test_is_burn_pattern_32_bytes_all_ff() {
        let data = vec![0xFF; 32];
        assert!(is_burn_pattern(&data, None));
    }

    #[test]
    fn test_is_burn_pattern_33_bytes_compressed() {
        let mut data = vec![0x02];
        data.extend(vec![0xFF; 32]);
        assert!(is_burn_pattern(&data, None));

        let mut data2 = vec![0x03];
        data2.extend(vec![0xFF; 32]);
        assert!(is_burn_pattern(&data2, None));
    }

    #[test]
    fn test_is_burn_pattern_65_bytes_uncompressed() {
        let mut data = vec![0x04];
        data.extend(vec![0xFF; 64]);
        assert!(is_burn_pattern(&data, None));
    }

    #[test]
    fn test_is_burn_pattern_not_burn() {
        let data = vec![0x02, 0x01, 0x02, 0x03];
        assert!(!is_burn_pattern(&data, None));
    }

    #[test]
    fn test_detect_binary_signature_pdf() {
        let data = b"%PDF-1.4 some content";
        assert_eq!(detect_binary_signature(data), Some("PDF"));
    }

    #[test]
    fn test_detect_binary_signature_png() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        assert_eq!(detect_binary_signature(&data), Some("PNG"));
    }

    #[test]
    fn test_detect_binary_signature_jpeg() {
        // JPEG needs 8+ bytes due to detect_image_format early-exit check
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(detect_binary_signature(&data), Some("JPEG"));
    }

    #[test]
    fn test_detect_binary_signature_gif() {
        let data = b"GIF89a some content";
        assert_eq!(detect_binary_signature(data), Some("GIF"));
    }

    #[test]
    fn test_detect_binary_signature_zip() {
        let data = [0x50, 0x4B, 0x03, 0x04];
        assert_eq!(detect_binary_signature(&data), Some("ZIP"));
    }

    #[test]
    fn test_detect_binary_signature_zlib_offset_0() {
        // ZLIB default compression: 0x78 0x9c
        let data = [0x78, 0x9c, 0x00, 0x00];
        assert_eq!(detect_binary_signature(&data), Some("ZLIB"));
    }

    #[test]
    fn test_detect_binary_signature_none() {
        let data = b"random data without signature";
        assert_eq!(detect_binary_signature(data), None);
    }

    #[test]
    fn test_detect_binary_signature_jpeg_offset_1_uncompressed() {
        // JPEG after 0x04 uncompressed pubkey prefix (e.g., height 690497)
        let data = [0x04, 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(
            detect_binary_signature(&data),
            Some("JPEG"),
            "JPEG at offset 1 after 0x04 prefix should be detected"
        );
    }

    #[test]
    fn test_detect_binary_signature_jpeg_offset_1_compressed() {
        // JPEG after 0x02 compressed pubkey prefix
        let data = [0x02, 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(
            detect_binary_signature(&data),
            Some("JPEG"),
            "JPEG at offset 1 after 0x02 prefix should be detected"
        );

        // JPEG after 0x03 compressed pubkey prefix
        let data = [0x03, 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(
            detect_binary_signature(&data),
            Some("JPEG"),
            "JPEG at offset 1 after 0x03 prefix should be detected"
        );
    }

    #[test]
    fn test_detect_binary_signature_png_offset_1() {
        // PNG after 0x04 uncompressed pubkey prefix
        let data = [0x04, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        assert_eq!(
            detect_binary_signature(&data),
            Some("PNG"),
            "PNG at offset 1 after 0x04 prefix should be detected"
        );
    }

    #[test]
    fn test_detect_binary_signature_gif_offset_1() {
        // GIF89a after 0x04 uncompressed pubkey prefix
        let mut data = vec![0x04];
        data.extend_from_slice(b"GIF89a");
        data.extend_from_slice(b"more data");
        assert_eq!(
            detect_binary_signature(&data),
            Some("GIF"),
            "GIF at offset 1 after 0x04 prefix should be detected"
        );
    }

    /// Regression test: ZIP file containing "%PDF" string should be detected as ZIP, not PDF
    #[test]
    fn test_detect_binary_signature_zip_with_pdf_payload() {
        // ZIP signature followed by data containing "%PDF"
        let mut zip_with_pdf = vec![0x50, 0x4B, 0x03, 0x04]; // ZIP magic
        zip_with_pdf.extend_from_slice(b"some ZIP content");
        zip_with_pdf.extend_from_slice(b"%PDF-1.4"); // %PDF string inside payload
        zip_with_pdf.extend_from_slice(b"more content");

        assert_eq!(
            detect_binary_signature(&zip_with_pdf),
            Some("ZIP"),
            "ZIP file with '%PDF' payload should be detected as ZIP, not PDF"
        );
    }

    /// Regression test: RAR file containing "%PDF" string should be detected as RAR, not PDF
    #[test]
    fn test_detect_binary_signature_rar_with_pdf_payload() {
        // RAR signature followed by data containing "%PDF"
        let mut rar_with_pdf = b"Rar!\x1A\x07\x00".to_vec(); // RAR magic
        rar_with_pdf.extend_from_slice(b"some RAR content");
        rar_with_pdf.extend_from_slice(b"%PDF-1.5"); // %PDF string inside payload

        assert_eq!(
            detect_binary_signature(&rar_with_pdf),
            Some("RAR"),
            "RAR file with '%PDF' payload should be detected as RAR, not PDF"
        );
    }
}
