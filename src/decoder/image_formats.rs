//! Image format detection and validation
//!
//! This module re-exports image format helpers from types::stamps to maintain
//! decoder API compatibility while using shared validation logic.

#![allow(dead_code)]

// Re-export shared helpers from types::stamps
pub use crate::types::stamps::{detect_image_format, ImageFormat};

// Add extension and MIME type methods as extension trait for decoder compatibility
impl ImageFormat {
    /// Get the file extension for this image format
    pub fn extension(&self) -> &'static str {
        match self {
            ImageFormat::Png => "png",
            ImageFormat::Jpeg => "jpg",
            ImageFormat::Gif => "gif",
            ImageFormat::WebP => "webp",
            ImageFormat::Svg => "svg",
            ImageFormat::Bmp => "bmp",
            ImageFormat::Pdf => "pdf",
        }
    }

    /// Get the MIME type for this image format
    pub fn mime_type(&self) -> &'static str {
        match self {
            ImageFormat::Png => "image/png",
            ImageFormat::Jpeg => "image/jpeg",
            ImageFormat::Gif => "image/gif",
            ImageFormat::WebP => "image/webp",
            ImageFormat::Svg => "image/svg+xml",
            ImageFormat::Bmp => "image/bmp",
            ImageFormat::Pdf => "application/pdf",
        }
    }
}

// Re-export canonical extraction function from shared validation module
pub use crate::types::stamps::validation::extract_stamps_payload;

/// Check if data appears to be base64-encoded
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
    fn test_png_detection() {
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_image_format(&png_header), Some(ImageFormat::Png));
    }

    #[test]
    fn test_jpeg_detection() {
        let jpeg_header = [0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(detect_image_format(&jpeg_header), Some(ImageFormat::Jpeg));
    }

    #[test]
    fn test_gif_detection() {
        assert_eq!(detect_image_format(b"GIF87a"), Some(ImageFormat::Gif));
        assert_eq!(detect_image_format(b"GIF89a"), Some(ImageFormat::Gif));
    }

    #[test]
    fn test_svg_detection() {
        assert_eq!(
            detect_image_format(b"<?xml version="),
            Some(ImageFormat::Svg)
        );
        assert_eq!(detect_image_format(b"<svg xmlns="), Some(ImageFormat::Svg));
    }

    #[test]
    fn test_base64_detection() {
        assert!(is_base64_data(
            b"iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34"
        ));
        assert!(!is_base64_data(b"Not base64 data!@#$%"));
        assert!(!is_base64_data(b""));
    }

    #[test]
    fn test_base64_extraction_after_stamp() {
        let data = b"stamp:iVBORw0KGgoAAAANSUhEUgAAABgAAAAY=";
        let extracted = extract_stamps_payload(data);
        assert_eq!(
            extracted,
            Some(b"iVBORw0KGgoAAAANSUhEUgAAABgAAAAY=".to_vec())
        );
    }

    #[test]
    fn test_case_insensitive_stamp_extraction() {
        let data = b"STAMP:iVBORw0KGgoAAAANSUhEUgAAABgAAAAY=";
        let extracted = extract_stamps_payload(data);
        assert!(extracted.is_some());
    }
}
