//! Base64 detection helpers
//!
//! This module provides utilities for detecting base64-encoded data,
//! used by both Stage 3 classification and decoder.

/// Check if data appears to be base64-encoded
///
/// Uses a heuristic approach: if at least 80% of bytes are valid base64 characters
/// (alphanumeric, +, /, =), the data is considered base64-encoded.
///
/// # Arguments
/// * `data` - Binary data to check
///
/// # Returns
/// * `true` if data appears to be base64-encoded, `false` otherwise
///
/// # Example
/// ```ignore
/// let encoded = b"iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34";
/// assert!(is_base64_data(encoded));
///
/// let plain = b"Not base64 data!@#$%";
/// assert!(!is_base64_data(plain));
/// ```
pub fn is_base64_data(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Basic heuristic: check if data contains mostly base64 characters
    let valid_chars = data
        .iter()
        .filter(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        .count();

    // At least 80% should be valid base64 characters
    let ratio = valid_chars as f64 / data.len() as f64;
    ratio >= 0.8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_detection() {
        assert!(is_base64_data(
            b"iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34"
        ));
        assert!(!is_base64_data(b"Not base64 data!@#$%"));
        assert!(!is_base64_data(b""));
    }
}
