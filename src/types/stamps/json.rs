//! JSON data type classification for Bitcoin Stamps protocols
//!
//! This module provides JSON classification for SRC protocol variant detection.

/// JSON data type classification for Bitcoin Stamps protocols
///
/// This enum is used internally for variant detection and is separate from
/// the output decoder's JsonType to avoid circular dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonType {
    /// SRC-20 tokens (fungible tokens)
    SRC20,
    /// SRC-101 domain names
    SRC101,
    /// SRC-721 NFTs
    SRC721,
    /// SRC-721r recursive NFTs
    SRC721r,
    /// Generic JSON data
    Generic,
}

/// Classify JSON data based on protocol markers
///
/// This is a pure helper function with no decoder dependencies, used by both
/// Stage 3 classification and the decoder to maintain consistent variant detection.
pub fn classify_json_data(json_bytes: &[u8]) -> JsonType {
    // Convert to string for pattern matching
    let data_str = String::from_utf8_lossy(json_bytes);
    let data_trimmed = data_str.trim();

    // Try to parse as JSON first
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data_trimmed) {
        if let Some(obj) = parsed.as_object() {
            // Check for protocol field ("p")
            if let Some(protocol) = obj.get("p").and_then(|v| v.as_str()) {
                return match protocol.to_lowercase().as_str() {
                    "src-20" | "src20" => JsonType::SRC20, // Both with and without hyphen
                    "src-101" | "src101" => JsonType::SRC101,
                    "src-721" | "src721" => JsonType::SRC721,
                    "src-721r" | "src721r" => JsonType::SRC721r,
                    _ => JsonType::Generic,
                };
            }
        }
    }

    // Fallback: pattern matching for malformed but recognizable JSON (case-insensitive)
    let data_lower = data_trimmed.to_lowercase();
    if data_lower.contains(r#""p":"src-20""#) {
        JsonType::SRC20
    } else if data_lower.contains(r#""p":"src-101""#) {
        JsonType::SRC101
    } else if data_lower.contains(r#""p":"src-721r""#) {
        JsonType::SRC721r
    } else if data_lower.contains(r#""p":"src-721""#) {
        JsonType::SRC721
    } else {
        JsonType::Generic
    }
}
