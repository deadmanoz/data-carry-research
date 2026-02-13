//! Bitcoin Stamps protocol constants and type definitions
//!
//! Bitcoin Stamps embed digital art and files directly in the Bitcoin blockchain using
//! P2MS (Pay-to-Multisig) outputs with specific burn patterns and ARC4 obfuscation.
//!
//! **NOTE**: Detection, extraction and processing logic has been moved to `crate::decoder::stamps`.
//! This module now contains only type definitions and constants.

pub mod burn_pattern;
pub mod json;
pub mod signature;
pub mod src20;
pub mod variant;

// Re-export main types at module level for convenience
pub use burn_pattern::StampsBurnPattern;
pub use json::{classify_json_data, JsonType};
pub use signature::StampSignature;
pub use src20::{encoding, SRC20Operation};
pub use variant::{StampsTransport, StampsVariant};

#[cfg(test)]
mod tests {
    use crate::crypto::arc4;
    use crate::types::content_detection::{detect_image_format, ImageFormat};

    #[test]
    fn test_arc4_decrypt() {
        let data = b"hello";
        let key = hex::decode("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
            .unwrap();
        let encrypted = arc4::decrypt(data, &key).unwrap();
        let decrypted = arc4::decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, data);
    }

    // =========================================================================
    // Image Format Detection Tests
    // =========================================================================

    #[test]
    fn test_detect_image_format_png() {
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_image_format(&png_header), Some(ImageFormat::Png));

        let mut png_with_data = png_header.to_vec();
        png_with_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
        assert_eq!(detect_image_format(&png_with_data), Some(ImageFormat::Png));
    }

    #[test]
    fn test_detect_image_format_jpeg() {
        let jpeg_header = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(detect_image_format(&jpeg_header), Some(ImageFormat::Jpeg));

        let jpeg_exif = [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x00, 0x45, 0x78];
        assert_eq!(detect_image_format(&jpeg_exif), Some(ImageFormat::Jpeg));
    }

    #[test]
    fn test_detect_image_format_gif() {
        let gif87a = b"GIF87atest";
        assert_eq!(detect_image_format(gif87a), Some(ImageFormat::Gif));

        let gif89a = b"GIF89atest";
        assert_eq!(detect_image_format(gif89a), Some(ImageFormat::Gif));
    }

    #[test]
    fn test_detect_image_format_webp() {
        let webp_header = b"RIFF\x00\x00\x00\x00WEBP";
        assert_eq!(detect_image_format(webp_header), Some(ImageFormat::WebP));
    }

    #[test]
    fn test_detect_image_format_svg() {
        let svg_xml = b"<?xml version=\"1.0\"?><svg>";
        assert_eq!(detect_image_format(svg_xml), Some(ImageFormat::Svg));

        let svg_tag = b"<svg xmlns=\"http://www.w3.org/2000/svg\">";
        assert_eq!(detect_image_format(svg_tag), Some(ImageFormat::Svg));
    }

    #[test]
    fn test_detect_image_format_bmp() {
        let bmp_header = b"BM\x00\x00\x00\x00";
        assert_eq!(detect_image_format(bmp_header), Some(ImageFormat::Bmp));
    }

    #[test]
    fn test_detect_image_format_unknown() {
        let unknown = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(detect_image_format(&unknown), None);

        assert_eq!(detect_image_format(&[]), None);

        let text = b"Hello, world!";
        assert_eq!(detect_image_format(text), None);
    }

    #[test]
    fn test_detect_image_format_too_short() {
        let short_png = [0x89, 0x50, 0x4E, 0x47];
        assert_eq!(detect_image_format(&short_png), None);

        let short_jpeg = [0xFF, 0xD8];
        assert_eq!(detect_image_format(&short_jpeg), None);

        assert_eq!(detect_image_format(&[0xFF]), None);
    }

    // =========================================================================
    // ImageFormat Method Tests
    // =========================================================================

    #[test]
    fn test_image_format_extension() {
        assert_eq!(ImageFormat::Png.extension(), "png");
        assert_eq!(ImageFormat::Jpeg.extension(), "jpg");
        assert_eq!(ImageFormat::Gif.extension(), "gif");
        assert_eq!(ImageFormat::WebP.extension(), "webp");
        assert_eq!(ImageFormat::Svg.extension(), "svg");
        assert_eq!(ImageFormat::Bmp.extension(), "bmp");
    }

    #[test]
    fn test_image_format_mime_type() {
        assert_eq!(ImageFormat::Png.mime_type(), "image/png");
        assert_eq!(ImageFormat::Jpeg.mime_type(), "image/jpeg");
        assert_eq!(ImageFormat::Gif.mime_type(), "image/gif");
        assert_eq!(ImageFormat::WebP.mime_type(), "image/webp");
        assert_eq!(ImageFormat::Svg.mime_type(), "image/svg+xml");
        assert_eq!(ImageFormat::Bmp.mime_type(), "image/bmp");
    }
}
