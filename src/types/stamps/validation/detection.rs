//! Content type detection for Bitcoin Stamps
//!
//! Functions for detecting and classifying Bitcoin Stamps content types.

use super::super::variant::StampsVariant;
use super::extraction::extract_stamps_payload;
use super::helpers::{check_zlib_at_offsets, BASE64_LENIENT};
use crate::types::content_detection::{detect_image_format, ImageFormat};
use base64::Engine;

/// Detect compression format (ZLIB or GZIP only)
///
/// Checks for:
/// - ZLIB: At offsets [0, 5, 7] with CMF-FLG checksum validation
/// - GZIP: Magic bytes 0x1F 0x8B at offset 0
///
/// Returns appropriate MIME type for detected compression
pub fn detect_compression_format(data: &[u8]) -> Option<&'static str> {
    // Check ZLIB at empirical offsets [0, 5, 7]
    if check_zlib_at_offsets(data, &[0, 5, 7]) {
        return Some("application/zlib");
    }

    // Check GZIP (0x1F 0x8B magic bytes) - require at least 4 bytes
    if data.len() >= 4 && data[0] == 0x1F && data[1] == 0x8B {
        return Some("application/gzip");
    }

    None
}

/// Detect Bitcoin Stamps variant from decrypted payload
///
/// This function classifies Bitcoin Stamps content as:
/// - SRC-20: Fungible token operations (JSON)
/// - SRC-721: NFT operations (JSON)
/// - SRC-101: Domain name operations (JSON)
/// - Classic: Image/file data (PNG, GIF, JPG, WebP, SVG, BMP, PDF)
///
/// Uses the same extraction logic as the decoder for consistency.
pub fn detect_stamps_variant(decrypted_data: &[u8]) -> Option<StampsVariant> {
    // Use new function and just return the variant
    let (variant, _, _) = detect_stamps_variant_with_content(decrypted_data);
    variant
}

/// Detect Bitcoin Stamps variant with content-type and image format information
///
/// Returns a tuple of (variant, content_type, image_format) providing comprehensive
/// classification for Bitcoin Stamps content.
///
/// Detection order prioritises encoding over content:
/// 1. Extract raw data after stamp signature
/// 2. Check for compression (ZLIB, GZIP)
/// 3. Check for images (PNG, JPEG, GIF, WebP, SVG, BMP, PDF)
/// 4. Check for JSON protocols (SRC-20, SRC-721, SRC-101)
/// 5. Check for HTML documents
/// 6. Check for SVG (text-based)
/// 7. Check for XML
/// 8. Check for plain text
/// 9. Fallback to binary data or Unknown
pub fn detect_stamps_variant_with_content(
    decrypted_data: &[u8],
) -> (
    Option<StampsVariant>,
    Option<&'static str>,
    Option<ImageFormat>,
) {
    // Handle empty payloads
    if decrypted_data.is_empty() {
        return (Some(StampsVariant::Unknown), None, None);
    }

    // Use the shared extraction function (handles Pure vs Counterparty-embedded)
    let payload_bytes = match extract_stamps_payload(decrypted_data) {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => {
            // No extractable payload - signature-only or invalid format
            return (Some(StampsVariant::Unknown), None, None);
        }
    };

    // Try base64 decoding - Bitcoin Stamps payloads are base64 encoded
    let payload_vec;
    let payload: &[u8] = if let Ok(decoded) = BASE64_LENIENT.decode(&payload_bytes) {
        payload_vec = decoded;
        // Strip UTF-8 BOM if present (0xEF 0xBB 0xBF)
        payload_vec
            .strip_prefix(&[0xEF, 0xBB, 0xBF])
            .unwrap_or(&payload_vec)
    } else {
        // Base64 decode failed - use raw payload bytes
        // (This can happen for non-base64 encoded stamps)
        &payload_bytes
    };

    // Detect content type using shared helper
    detect_content_type_from_payload(payload)
}

/// Detect Bitcoin Stamps content type from decoded payload
///
/// Takes payload AFTER signature extraction and base64 decoding.
/// Returns (variant, content_type, image_format) for classification/output.
///
/// # Invariant Enforcement
/// This function ENFORCES (via debug_assert!) these guarantees:
/// - `Compressed` -> MUST return (Some(Compressed), Some(content_type), None)
/// - `Classic` (image) -> MUST return (Some(Classic), Some(content_type), Some(image_format))
/// - `Classic` (PDF) -> MUST return (Some(Classic), Some("application/pdf"), None)
/// - `SRC20/721/101` -> MUST return (Some(variant), Some("application/json"), None)
/// - `HTML` -> MUST return (Some(HTML), Some("text/html"), None)
/// - `Data` -> MUST return (Some(Data), Some(content_type), None)
/// - `Unknown` -> MUST return (Some(Unknown), None, None)
///
/// Used by Stage 3 classifier and decoder to ensure identical detection logic.
pub fn detect_content_type_from_payload(
    payload: &[u8],
) -> (
    Option<StampsVariant>,
    Option<&'static str>,
    Option<ImageFormat>,
) {
    // Empty payload check
    if payload.is_empty() {
        let result = (Some(StampsVariant::Unknown), None, None);
        debug_assert!(
            result.1.is_none() && result.2.is_none(),
            "Unknown must have NO content_type or image_format"
        );
        return result;
    }

    // COMPRESSION CHECK (ZLIB or GZIP)
    if let Some(content_type) = detect_compression_format(payload) {
        let result = (Some(StampsVariant::Compressed), Some(content_type), None);
        debug_assert!(
            result.1.is_some() && result.2.is_none(),
            "Compressed must have content_type, no image_format"
        );
        return result;
    }

    // PDF CHECK (Classic variant, but PDF is a document, not an image)
    // Search in first 1024 bytes since PDF header might not be at exact start
    let search_len = payload.len().min(1024);
    if search_len >= 4 && payload[..search_len].windows(4).any(|w| w == b"%PDF") {
        // PDF returns None for image_format - semantically correct (PDF is document, not image)
        let result = (Some(StampsVariant::Classic), Some("application/pdf"), None);
        debug_assert!(
            result.1.is_some() && result.2.is_none(),
            "Classic (PDF) must have content_type, no image_format"
        );
        return result;
    }

    // IMAGE CHECK (Classic variant) - binary image formats
    if let Some(image_format) = detect_image_format(payload) {
        let result = (
            Some(StampsVariant::Classic),
            Some(image_format.mime_type()),
            Some(image_format),
        );
        debug_assert!(
            result.1.is_some() && result.2.is_some(),
            "Classic (image) must have BOTH content_type and image_format"
        );
        return result;
    }

    // JSON CHECK (SRC protocols and generic JSON)
    if let Ok(json_str) = std::str::from_utf8(payload) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
            if let Some(obj) = json.as_object() {
                // Check protocol field for SRC variants
                // Accept both hyphenated ("src-20") and hyphenless ("src20") forms
                if let Some(protocol) = obj.get("p").and_then(|v| v.as_str()) {
                    match protocol.to_lowercase().as_str() {
                        "src-20" | "src20" => {
                            let result =
                                (Some(StampsVariant::SRC20), Some("application/json"), None);
                            debug_assert!(
                                result.1.is_some() && result.2.is_none(),
                                "SRC20 must have content_type, no image_format"
                            );
                            return result;
                        }
                        "src-721" | "src721" | "src-721r" | "src721r" => {
                            let result =
                                (Some(StampsVariant::SRC721), Some("application/json"), None);
                            debug_assert!(
                                result.1.is_some() && result.2.is_none(),
                                "SRC721 must have content_type, no image_format"
                            );
                            return result;
                        }
                        "src-101" | "src101" => {
                            let result =
                                (Some(StampsVariant::SRC101), Some("application/json"), None);
                            debug_assert!(
                                result.1.is_some() && result.2.is_none(),
                                "SRC101 must have content_type, no image_format"
                            );
                            return result;
                        }
                        _ => {}
                    }
                }
                // Generic JSON (not SRC protocol) - goes to Data variant
                let result = (Some(StampsVariant::Data), Some("application/json"), None);
                debug_assert!(
                    result.1.is_some() && result.2.is_none(),
                    "Data (JSON) must have content_type, no image_format"
                );
                return result;
            }
        }
    }

    // HTML CHECK (score-based detection with <style> tag)
    if let Ok(text) = std::str::from_utf8(payload) {
        let lower = text.to_lowercase();
        let mut html_score = 0;

        let scan_start = 200.min(lower.len());
        let scan_deep = 1000.min(lower.len());

        if let Some(start_text) = lower.get(..scan_start) {
            if start_text.contains("<!doctype html") || start_text.contains("<!doctype") {
                html_score += 2;
            }
            if start_text.contains("<html") {
                html_score += 1;
            }
            if start_text.contains("<head") {
                html_score += 1;
            }
            if start_text.contains("<meta ") || start_text.contains("<meta>") {
                html_score += 1;
            }
            if start_text.contains("<style") {
                html_score += 1;
            }
        }

        if let Some(deep_text) = lower.get(..scan_deep) {
            if deep_text.contains("<body") {
                html_score += 1;
            }
            if deep_text.contains("<script") && lower.contains("</script") {
                html_score += 1;
            }
        }

        if html_score >= 2 {
            let result = (Some(StampsVariant::HTML), Some("text/html"), None);
            debug_assert!(
                result.1.is_some() && result.2.is_none(),
                "HTML must have content_type, no image_format"
            );
            return result;
        }
    }

    // SVG TEXT CHECK (text-based SVG - Classic variant)
    if let Ok(text) = std::str::from_utf8(payload) {
        let trimmed = text.trim_start();
        if trimmed.starts_with("<svg") || (trimmed.starts_with("<?xml") && text.contains("<svg")) {
            let result = (
                Some(StampsVariant::Classic),
                Some("image/svg+xml"),
                Some(ImageFormat::Svg),
            );
            debug_assert!(
                result.1.is_some() && result.2.is_some(),
                "SVG Classic must have BOTH content_type and image_format"
            );
            return result;
        }
    }

    // XML CHECK (Data variant)
    if let Ok(text) = std::str::from_utf8(payload) {
        let trimmed = text.trim_start();
        if trimmed.starts_with("<?xml") || trimmed.starts_with("<rss") {
            let result = (Some(StampsVariant::Data), Some("application/xml"), None);
            debug_assert!(
                result.1.is_some() && result.2.is_none(),
                "Data (XML) must have content_type, no image_format"
            );
            return result;
        }
    }

    // TEXT CHECK (Data variant)
    if let Ok(text) = std::str::from_utf8(payload) {
        let printable_count = text
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count();
        let ascii_ratio = printable_count as f64 / text.len() as f64;

        if ascii_ratio >= 0.8 && text.len() >= 10 {
            let result = (Some(StampsVariant::Data), Some("text/plain"), None);
            debug_assert!(
                result.1.is_some() && result.2.is_none(),
                "Data (text) must have content_type, no image_format"
            );
            return result;
        }
    }

    // BINARY DATA (Data variant - fallback for non-empty)
    if !payload.is_empty() {
        let result = (
            Some(StampsVariant::Data),
            Some("application/octet-stream"),
            None,
        );
        debug_assert!(
            result.1.is_some() && result.2.is_none(),
            "Data (binary) must have content_type, no image_format"
        );
        return result;
    }

    // UNKNOWN (empty - should be caught above, but defensive)
    let result = (Some(StampsVariant::Unknown), None, None);
    debug_assert!(
        result.1.is_none() && result.2.is_none(),
        "Unknown must have NO content_type or image_format"
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine};

    #[test]
    fn test_detect_stamps_variant_src20() {
        let json = r#"{"p":"src-20","op":"deploy","tick":"TEST","max":"1000"}"#;
        let base64_json = general_purpose::STANDARD.encode(json.as_bytes());
        let payload = format!("stamp:{}", base64_json);

        let variant = detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::SRC20));
    }

    #[test]
    fn test_detect_stamps_variant_src721() {
        let json = r#"{"p":"src-721","op":"mint","tick":"NFTS"}"#;
        let base64_json = general_purpose::STANDARD.encode(json.as_bytes());
        let payload = format!("stamp:{}", base64_json);

        let variant = detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::SRC721));
    }

    #[test]
    fn test_detect_stamps_variant_src101() {
        let json = r#"{"p":"src-101","op":"reg","name":"example"}"#;
        let base64_json = general_purpose::STANDARD.encode(json.as_bytes());
        let payload = format!("stamp:{}", base64_json);

        let variant = detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::SRC101));
    }

    #[test]
    fn test_detect_stamps_variant_png_image() {
        // PNG magic bytes
        let png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let base64_png = general_purpose::STANDARD.encode(&png_data);
        let payload = format!("stamp:{}", base64_png);

        let variant = detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::Classic));
    }

    #[test]
    fn test_detect_stamps_variant_png_image_with_data_uri() {
        let payload = b"stamp:data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAA4BAMAAAB9BqfFAAAAJ1BMVEVIZZcqRnYNERg8Qj4gJSEiLEojOFsAAAD7AQkeGx7///+SoYxUaWqIxi3EAAABTklEQVQ4y73PsU7DMBQF0FSiA6MHilg7lA8IEhmRcCR+wIq8MpQvQE8xYxrFaVkzpBuVoAM7/B7XcRrH1EJMvapk++jd1zaaB3I6XD6GEDFOO+Uj+JqIdr0tgF0o3+bb+cI+otkB63yN0yKz5xPqyiEDA/O2/XCIYAW9aK03Xw6RS9p/a20XsNmAij439MaW5tUjM1gB2QgvMqL3I2wyJSrFfBRCNCX7jTKAEqN1CN1kNDHHlUDfIQIHCg8RU5ejnTbTbnLiY3SOpSX2eDiVmOxuYxQS6AXYiADiv/8XQ3UZ3BlGeYyNDKBoQ3X5B55xh2nTfxHng/LU/CTeB+87VHjalKIe0B6YzJ5LvuIPHmZ7oD+5SjOlfESAVKJsMY7jG3OpFK144tBwfLumIsFlwASfRBWFjgt+Dwf2KbR+Lez1gKhqjYaHWABy6NhhID/iStgdKGHcpQAAAABJRU5ErkJggg==";
        let variant = detect_stamps_variant(payload);
        assert_eq!(variant, Some(StampsVariant::Classic));
    }

    #[test]
    fn test_detect_stamps_variant_malformed_json() {
        let bad_json = r#"{"p":"src-20","op":"deploy""#;
        let base64_json = general_purpose::STANDARD.encode(bad_json.as_bytes());
        let payload = format!("stamp:{}", base64_json);

        let variant = detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::Data));
    }

    #[test]
    fn test_detect_stamps_variant_unsupported_format() {
        let random_data = vec![0xFF, 0x00, 0xAB, 0xCD, 0xEF];
        let base64_data = general_purpose::STANDARD.encode(&random_data);
        let payload = format!("stamp:{}", base64_data);

        let variant = detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::Data));
    }

    #[test]
    fn test_detect_stamps_variant_with_bom() {
        let json = r#"{"p":"src-20","op":"mint","tick":"TEST","amt":"100"}"#;
        let mut json_with_bom = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        json_with_bom.extend_from_slice(json.as_bytes());

        let base64_json = general_purpose::STANDARD.encode(&json_with_bom);
        let payload = format!("stamp:{}", base64_json);

        let variant = detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::SRC20));
    }
}
