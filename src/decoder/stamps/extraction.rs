//! Payload extraction functions for Bitcoin Stamps
//!
//! Functions for extracting and cleaning payload data from decrypted stamps.

use crate::types::stamps::signature::StampSignature;

/// Find stamp signature in decrypted data, returning offset and actual variant found
///
/// Checks for stamp/stamps signatures and returns the actual variant present in the data.
/// Detection is case-sensitive to accurately track signature usage patterns.
/// Returns: (byte_offset, signature_variant)
pub fn find_stamp_signature(decrypted_data: &[u8]) -> Option<(usize, StampSignature)> {
    // Check each variant with exact (case-sensitive) matching
    // Order: singular before plural (more common), lowercase before uppercase
    for sig_variant in StampSignature::ALL {
        if let Some(pos) = decrypted_data
            .windows(sig_variant.len())
            .position(|window| window == sig_variant.as_bytes())
        {
            return Some((pos, sig_variant));
        }
    }
    None
}

/// Strip data URI prefix from Bitcoin Stamps payload
///
/// Real-world Bitcoin Stamps payloads sometimes include data URI prefixes
/// from Electrum-Counterparty exports:
/// - `data:image/png;base64,<base64data>`
/// - `image/png;base64<base64data>`
///
/// This function extracts just the base64 portion.
/// IMPORTANT: Only processes data that looks like valid UTF-8 with data URI prefix.
/// Binary data (GZIP, ZLIB, images) is returned unchanged to avoid corruption.
pub(crate) fn strip_data_uri_prefix(data: &[u8]) -> Vec<u8> {
    // Only process if it's valid UTF-8 AND starts with "data:" or contains data URI markers
    // Binary data (GZIP magic 0x1F 0x8B, ZLIB 0x78, PNG 0x89, etc.) should pass through unchanged
    let Ok(data_str) = std::str::from_utf8(data) else {
        return data.to_vec(); // Not valid UTF-8 = binary data, return unchanged
    };

    // Check if this looks like a data URI (starts with "data:" or has "base64,")
    if !data_str.starts_with("data:")
        && !data_str.contains("base64,")
        && !data_str.contains(";base64")
    {
        return data.to_vec(); // No data URI markers, return unchanged
    }

    let mut result = data_str;

    // Remove data URI prefix (e.g., "data:image/png;base64,data" -> "data")
    if let Some(comma_pos) = result.rfind(',') {
        let after_comma = &result[comma_pos + 1..];
        // If what's after comma looks like base64, use that part
        if after_comma.len() > 10
            && after_comma
                .chars()
                .take(10)
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            result = after_comma;
        }
    }

    // Remove MIME type prefix (e.g., "image/png;base64data" -> "base64data")
    if let Some(last_semi) = result.rfind(';') {
        let after_last_semi = &result[last_semi + 1..];
        // If what's after semicolon looks like base64, use that part
        if after_last_semi.len() > 10
            && after_last_semi
                .chars()
                .take(10)
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            result = after_last_semi;
        }
    }

    result.trim().as_bytes().to_vec()
}

/// Strip data URI prefix from a string (for Counterparty-embedded stamps)
///
/// Similar to `strip_data_uri_prefix` but operates on strings after Latin-1 conversion.
/// Used in the Counterparty-embedded path where we need to strip data URI markers
/// BEFORE filtering to base64 characters.
pub(crate) fn strip_data_uri_prefix_str(data: &str) -> &str {
    // Check if this looks like a data URI (starts with "data:" or has "base64,")
    if !data.starts_with("data:") && !data.contains("base64,") && !data.contains(";base64") {
        return data; // No data URI markers, return unchanged
    }

    let mut result = data;

    // Remove data URI prefix (e.g., "data:image/png;base64,data" -> "data")
    if let Some(comma_pos) = result.rfind(',') {
        let after_comma = &result[comma_pos + 1..];
        // If what's after comma looks like base64, use that part
        if after_comma.len() > 10
            && after_comma
                .chars()
                .take(10)
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            result = after_comma;
        }
    }

    // Remove MIME type prefix (e.g., "image/png;base64data" -> "base64data")
    if let Some(last_semi) = result.rfind(';') {
        let after_last_semi = &result[last_semi + 1..];
        // If what's after semicolon looks like base64, use that part
        if after_last_semi.len() > 10
            && after_last_semi
                .chars()
                .take(10)
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            result = after_last_semi;
        }
    }

    result.trim()
}

/// Extract payload bytes from Bitcoin Stamps decrypted data
///
/// This is the CANONICAL extraction function used by both Stage 3 and decoder.
/// It handles the differences between Pure and Counterparty-embedded stamps:
///
/// **Pure Bitcoin Stamps - offset 0** (no length prefix):
/// - Format: `[stamp:][base64data]`
/// - Simple extraction, no character cleanup needed
///
/// **Pure Bitcoin Stamps - offset 2** (with length prefix):
/// - Format: `[2-byte length][stamp:][base64data]`
/// - Uses length prefix to extract exact data
/// - No character cleanup needed (already clean base64)
///
/// **Counterparty-embedded** (stamp at offsets > 2):
/// - Format: `[CNTRPRTY...][stamp:][base64data with control chars]`
/// - Converts Latin-1 to UTF-8 (Counterparty description field encoding)
/// - Filters to only valid base64 characters
/// - Handles intermediate '=' padding from concatenated segments
///
/// Returns the cleaned payload bytes ready for base64 decoding.
pub fn extract_stamps_payload(decrypted_data: &[u8]) -> Option<Vec<u8>> {
    let (stamps_offset, sig_variant) = find_stamp_signature(decrypted_data)?;

    let sig_len = sig_variant.len();
    let data_start = stamps_offset + sig_len;

    if data_start >= decrypted_data.len() {
        return None; // No data after signature
    }

    // Pure Bitcoin Stamps with NO length prefix: stamp at offset 0
    // Simple extraction - data is already clean base64
    if stamps_offset == 0 {
        let raw = &decrypted_data[data_start..];
        return Some(strip_data_uri_prefix(raw));
    }

    // Pure Bitcoin Stamps WITH length prefix: stamp at offset 2
    if stamps_offset == 2 && decrypted_data.len() >= 2 {
        let length_bytes = [decrypted_data[0], decrypted_data[1]];
        let total_length = ((length_bytes[0] as usize) << 8) | (length_bytes[1] as usize);

        // Validate and use length prefix
        if total_length >= sig_len && total_length <= decrypted_data.len() {
            let data_length = total_length - sig_len;
            let end = (data_start + data_length).min(decrypted_data.len());
            let raw = &decrypted_data[data_start..end];
            return Some(strip_data_uri_prefix(raw));
        }
        // Fallback: use all remaining data if length is invalid
        let raw = &decrypted_data[data_start..];
        return Some(strip_data_uri_prefix(raw));
    }

    // Counterparty-embedded (stamp at offset > 2): needs Latin-1 to UTF-8 conversion
    let raw_data = &decrypted_data[data_start..];

    // Step 1: Convert Latin-1 (ISO-8859-1) to UTF-8
    // Counterparty description field uses Latin-1 encoding
    // This matches Electrum's decodeURIComponent(escape(descr))
    let latin1_string: String = raw_data.iter().map(|&b| b as char).collect();

    // Step 2: Strip data-URI prefix if present (BEFORE base64 filtering)
    // e.g., "data:image/png;base64,iVBORw..." -> "iVBORw..."
    let stripped = strip_data_uri_prefix_str(&latin1_string);

    // Step 3: Filter to only base64 characters (A-Za-z0-9+/=)
    let mut data_str: String = stripped
        .chars()
        .filter(|&c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        .collect();

    if data_str.is_empty() {
        return None;
    }

    // Step 3: Handle base64 padding cleanup
    // Per Electrum-Counterparty: Base64 may have junk data after final padding
    // Also, concatenated segments may have intermediate '=' padding
    if let Some(last_equals) = data_str.rfind('=') {
        data_str.truncate(last_equals + 1);

        // Remove any intermediate '=' characters (from concatenated base64 segments)
        // Keep only the final 1-2 '=' characters for padding
        let original_len = data_str.len();
        let cleaned: String = data_str
            .chars()
            .enumerate()
            .filter(|(i, c)| *c != '=' || *i >= original_len - 2)
            .map(|(_, c)| c)
            .collect();
        data_str = cleaned;
    }

    Some(data_str.into_bytes())
}
