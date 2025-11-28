//! Content Type Detection
//!
//! This module provides shared content detection logic for identifying file types
//! and data formats embedded in Bitcoin P2MS outputs. It uses conservative detection
//! heuristics to avoid false positives.
//!
//! ## Design Principles
//!
//! 1. **Conservative Detection**: Require strong signals (full magic bytes, container headers)
//!    to avoid false positives, especially for audio/video where sync words can appear in random data
//!
//! 2. **Type Safety**: Enum-based `ContentType` instead of string matching for robustness
//!
//! 3. **Shared Logic**: Single source of truth used by both Stage 3 classification and Stage 4 decoding
//!
//! 4. **MIME Type Mapping**: Every content type maps to a standard MIME type string
//!
//! ## Usage
//!
//! ```rust
//! use data_carry_research::types::content_detection::{ContentType, ImageFormat};
//!
//! let data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG magic
//! let content_type = ContentType::detect(&data);
//! assert_eq!(content_type, Some(ContentType::Image(ImageFormat::Png)));
//! assert_eq!(content_type.unwrap().mime_type(), "image/png");
//! ```

use serde::{Deserialize, Serialize};

/// Image format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageFormat {
    /// PNG image (magic: 89 50 4E 47 0D 0A 1A 0A)
    Png,
    /// JPEG image (magic: FF D8 FF)
    Jpeg,
    /// GIF image (magic: GIF87a or GIF89a)
    Gif,
    /// WebP image (magic: RIFF....WEBP)
    WebP,
    /// SVG image (XML-based, starts with <?xml or <svg)
    Svg,
    /// BMP image (magic: BM)
    Bmp,
    /// TIFF image (magic: 49 49 2A 00 or 4D 4D 00 2A)
    Tiff,
    /// ICO icon (magic: 00 00 01 00)
    Ico,
    /// AVIF image (magic: ftyp with avif brand)
    Avif,
    /// JPEG XL image (magic: FF 0A or full container)
    JpegXl,
}

/// Audio format detection (conservative - requires containers/tags)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AudioFormat {
    /// MP3 with ID3 tag (magic: ID3 or 49 44 33)
    Mp3,
    /// WAV audio (magic: RIFF....WAVE)
    Wav,
    /// OGG audio (magic: OggS)
    Ogg,
    /// FLAC audio (magic: fLaC)
    Flac,
}

/// Video format detection (conservative - requires valid containers)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoFormat {
    /// MP4 video (ftyp brand validation)
    Mp4,
    /// WebM video (EBML + doctype check)
    WebM,
    /// Matroska video (EBML + doctype check)
    Mkv,
    /// AVI video (magic: RIFF....AVI)
    Avi,
}

/// Document format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentFormat {
    /// PDF document (magic: %PDF)
    Pdf,
}

/// Archive format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveFormat {
    /// ZIP archive (magic: PK 03 04 or PK 05 06)
    Zip,
    /// RAR archive (magic: Rar!)
    Rar,
    /// 7-Zip archive (magic: 37 7A BC AF 27 1C)
    SevenZip,
    /// GZIP archive (magic: 1F 8B 08)
    Gzip,
    /// BZIP2 archive (magic: BZh)
    Bzip2,
    /// ZLIB archive (magic: 78 01, 78 5E, 78 9C, 78 DA)
    Zlib,
    /// TAR archive (magic: ustar at offset 257)
    Tar,
}

/// Text format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextFormat {
    /// Plain text (valid UTF-8/ASCII)
    PlainText,
    /// Python script (shebang or keywords)
    Python,
    /// JavaScript code (detected keywords)
    JavaScript,
}

/// Structured data format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuredFormat {
    /// JSON data
    Json,
    /// XML data
    Xml,
}

/// Burn pattern detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BurnPattern {
    /// Compressed burn (0x03 + all 0xFF)
    CompressedBurn,
    /// Uncompressed burn (0x04 + all 0xFF)
    UncompressedBurn,
}

/// Content type enum covering all detectable formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    /// Image file
    Image(ImageFormat),
    /// Audio file (conservative detection)
    Audio(AudioFormat),
    /// Video file (conservative detection)
    Video(VideoFormat),
    /// Document file
    Document(DocumentFormat),
    /// Archive/compressed file
    Archive(ArchiveFormat),
    /// Text file
    Text(TextFormat),
    /// Structured data
    Structured(StructuredFormat),
    /// Burn pattern
    Burn(BurnPattern),
    /// Binary data (no specific format detected)
    Binary,
}

impl ContentType {
    /// Detect content type from byte data
    ///
    /// Uses conservative detection heuristics to avoid false positives.
    /// Checks in order of specificity:
    /// 1. Binary file signatures (images, documents, archives)
    /// 2. Burn patterns
    /// 3. Structured data (JSON, XML)
    /// 4. Text content (Python, JavaScript, plain text)
    /// 5. Binary fallback
    pub fn detect(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        // Check binary signatures first (most specific)
        if let Some(img) = Self::detect_image(data) {
            return Some(ContentType::Image(img));
        }

        if let Some(doc) = Self::detect_document(data) {
            return Some(ContentType::Document(doc));
        }

        if let Some(archive) = Self::detect_archive(data) {
            return Some(ContentType::Archive(archive));
        }

        // Check burn patterns
        if let Some(burn) = Self::detect_burn_pattern(data) {
            return Some(ContentType::Burn(burn));
        }

        // Check audio (conservative - requires container headers)
        if let Some(audio) = Self::detect_audio_conservative(data) {
            return Some(ContentType::Audio(audio));
        }

        // Check video (conservative - requires valid containers)
        if let Some(video) = Self::detect_video_conservative(data) {
            return Some(ContentType::Video(video));
        }

        // Check structured data
        if let Some(structured) = Self::detect_structured(data) {
            return Some(ContentType::Structured(structured));
        }

        // Check text content (after binary signatures to avoid false positives)
        if let Some(text) = Self::detect_text(data) {
            return Some(ContentType::Text(text));
        }

        // Default to binary if no specific format detected
        Some(ContentType::Binary)
    }

    /// Get MIME type string for this content type
    pub fn mime_type(&self) -> &'static str {
        match self {
            ContentType::Image(fmt) => fmt.mime_type(),
            ContentType::Audio(fmt) => fmt.mime_type(),
            ContentType::Video(fmt) => fmt.mime_type(),
            ContentType::Document(fmt) => fmt.mime_type(),
            ContentType::Archive(fmt) => fmt.mime_type(),
            ContentType::Text(fmt) => fmt.mime_type(),
            ContentType::Structured(fmt) => fmt.mime_type(),
            ContentType::Burn(_) => "application/x-burn-pattern",
            ContentType::Binary => "application/octet-stream",
        }
    }

    /// Get the canonical file extension (with leading dot) when available
    pub fn file_extension(&self) -> Option<&'static str> {
        match self {
            ContentType::Image(fmt) => match fmt {
                ImageFormat::Png => Some(".png"),
                ImageFormat::Jpeg => Some(".jpg"),
                ImageFormat::Gif => Some(".gif"),
                ImageFormat::WebP => Some(".webp"),
                ImageFormat::Svg => Some(".svg"),
                ImageFormat::Bmp => Some(".bmp"),
                ImageFormat::Tiff => Some(".tiff"),
                ImageFormat::Ico => Some(".ico"),
                ImageFormat::Avif => Some(".avif"),
                ImageFormat::JpegXl => Some(".jxl"),
            },
            ContentType::Audio(fmt) => match fmt {
                AudioFormat::Mp3 => Some(".mp3"),
                AudioFormat::Wav => Some(".wav"),
                AudioFormat::Ogg => Some(".ogg"),
                AudioFormat::Flac => Some(".flac"),
            },
            ContentType::Video(fmt) => match fmt {
                VideoFormat::Mp4 => Some(".mp4"),
                VideoFormat::WebM => Some(".webm"),
                VideoFormat::Mkv => Some(".mkv"),
                VideoFormat::Avi => Some(".avi"),
            },
            ContentType::Document(fmt) => match fmt {
                DocumentFormat::Pdf => Some(".pdf"),
            },
            ContentType::Archive(fmt) => match fmt {
                ArchiveFormat::Zip => Some(".zip"),
                ArchiveFormat::Rar => Some(".rar"),
                ArchiveFormat::SevenZip => Some(".7z"),
                ArchiveFormat::Gzip => Some(".gz"),
                ArchiveFormat::Bzip2 => Some(".bz2"),
                ArchiveFormat::Zlib => Some(".zlib"),
                ArchiveFormat::Tar => Some(".tar"),
            },
            ContentType::Text(fmt) => match fmt {
                TextFormat::PlainText => Some(".txt"),
                TextFormat::Python => Some(".py"),
                TextFormat::JavaScript => Some(".js"),
            },
            ContentType::Structured(fmt) => match fmt {
                StructuredFormat::Json => Some(".json"),
                StructuredFormat::Xml => Some(".xml"),
            },
            ContentType::Burn(_) | ContentType::Binary => None,
        }
    }

    /// Return the high-level category string for this content type
    pub fn category(&self) -> &'static str {
        match self {
            ContentType::Image(_) => "Images",
            ContentType::Audio(_) => "Audio",
            ContentType::Video(_) => "Video",
            ContentType::Document(_) => "Documents",
            ContentType::Archive(_) => "Archives",
            ContentType::Text(_) => "Text",
            ContentType::Structured(_) => "Structured Data",
            ContentType::Burn(_) | ContentType::Binary => "Other",
        }
    }

    /// Reconstruct a content type from a stored MIME string
    pub fn from_mime_type(mime_type: &str) -> Option<Self> {
        match mime_type {
            "image/png" => Some(ContentType::Image(ImageFormat::Png)),
            "image/jpeg" => Some(ContentType::Image(ImageFormat::Jpeg)),
            "image/gif" => Some(ContentType::Image(ImageFormat::Gif)),
            "image/webp" => Some(ContentType::Image(ImageFormat::WebP)),
            "image/svg+xml" => Some(ContentType::Image(ImageFormat::Svg)),
            "image/bmp" => Some(ContentType::Image(ImageFormat::Bmp)),
            "image/tiff" => Some(ContentType::Image(ImageFormat::Tiff)),
            "image/x-icon" => Some(ContentType::Image(ImageFormat::Ico)),
            "image/avif" => Some(ContentType::Image(ImageFormat::Avif)),
            "image/jxl" => Some(ContentType::Image(ImageFormat::JpegXl)),
            "audio/mpeg" => Some(ContentType::Audio(AudioFormat::Mp3)),
            "audio/wav" => Some(ContentType::Audio(AudioFormat::Wav)),
            "audio/ogg" => Some(ContentType::Audio(AudioFormat::Ogg)),
            "audio/flac" => Some(ContentType::Audio(AudioFormat::Flac)),
            "video/mp4" => Some(ContentType::Video(VideoFormat::Mp4)),
            "video/webm" => Some(ContentType::Video(VideoFormat::WebM)),
            "video/x-matroska" => Some(ContentType::Video(VideoFormat::Mkv)),
            "video/x-msvideo" => Some(ContentType::Video(VideoFormat::Avi)),
            "application/pdf" => Some(ContentType::Document(DocumentFormat::Pdf)),
            "application/zip" => Some(ContentType::Archive(ArchiveFormat::Zip)),
            "application/x-rar-compressed" => Some(ContentType::Archive(ArchiveFormat::Rar)),
            "application/x-7z-compressed" => Some(ContentType::Archive(ArchiveFormat::SevenZip)),
            "application/gzip" => Some(ContentType::Archive(ArchiveFormat::Gzip)),
            "application/x-bzip2" => Some(ContentType::Archive(ArchiveFormat::Bzip2)),
            "application/zlib" => Some(ContentType::Archive(ArchiveFormat::Zlib)),
            "application/x-tar" => Some(ContentType::Archive(ArchiveFormat::Tar)),
            "text/plain" => Some(ContentType::Text(TextFormat::PlainText)),
            "text/x-python" => Some(ContentType::Text(TextFormat::Python)),
            "text/javascript" => Some(ContentType::Text(TextFormat::JavaScript)),
            "application/json" => Some(ContentType::Structured(StructuredFormat::Json)),
            "application/xml" => Some(ContentType::Structured(StructuredFormat::Xml)),
            "application/x-burn-pattern" => Some(ContentType::Burn(BurnPattern::CompressedBurn)),
            "application/octet-stream" => Some(ContentType::Binary),
            _ => None,
        }
    }

    /// Detect image formats (delegates to standalone detect_image_format function)
    fn detect_image(data: &[u8]) -> Option<ImageFormat> {
        detect_image_format(data)
    }

    /// Detect document formats
    ///
    /// Skips known archive signatures to prevent misclassification (e.g., ZIP with "%PDF" payload).
    /// Uses window search in first 1024 bytes to match stamps.rs behaviour.
    fn detect_document(data: &[u8]) -> Option<DocumentFormat> {
        // Skip PDF detection for known archive formats
        // This prevents ZIP files containing "%PDF" in their payload from misclassifying
        const ARCHIVE_SIGNATURES: &[&[u8]] = &[
            &[0x50, 0x4B],             // ZIP (PK)
            &[0x52, 0x61, 0x72, 0x21], // RAR (Rar!)
            &[0x37, 0x7A, 0xBC, 0xAF], // 7Z
            &[0x1F, 0x8B],             // GZIP
            &[0x42, 0x5A],             // BZIP2 (BZ)
        ];

        // Check archive signatures first - let detect_archive() handle these
        for sig in ARCHIVE_SIGNATURES {
            if data.starts_with(sig) {
                return None;
            }
        }

        // PDF: Search in first 1024 bytes for %PDF header
        // This matches stamps.rs behaviour where PDF header might not be at exact start
        let search_len = data.len().min(1024);
        if search_len >= 4 && data[..search_len].windows(4).any(|w| w == b"%PDF") {
            return Some(DocumentFormat::Pdf);
        }

        None
    }

    /// Detect archive formats
    fn detect_archive(data: &[u8]) -> Option<ArchiveFormat> {
        if data.len() < 4 {
            return None;
        }

        // ZIP: PK 03 04 or PK 05 06 (central directory)
        if data.starts_with(&[0x50, 0x4B, 0x03, 0x04])
            || data.starts_with(&[0x50, 0x4B, 0x05, 0x06])
        {
            return Some(ArchiveFormat::Zip);
        }

        // RAR: Rar! (52 61 72 21)
        if data.starts_with(b"Rar!") {
            return Some(ArchiveFormat::Rar);
        }

        // 7-Zip: 37 7A BC AF 27 1C
        if data.len() >= 6 && data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
            return Some(ArchiveFormat::SevenZip);
        }

        // GZIP: 1F 8B 08
        if data.starts_with(&[0x1F, 0x8B, 0x08]) {
            return Some(ArchiveFormat::Gzip);
        }

        // BZIP2: BZh (42 5A 68)
        if data.starts_with(b"BZh") {
            return Some(ArchiveFormat::Bzip2);
        }

        // ZLIB: 78 01 (no compression), 78 5E (moderate), 78 9C (default), 78 DA (best)
        // Validate CMF/FLG checksum: (CMF * 256 + FLG) % 31 == 0
        if data.len() >= 2 && data[0] == 0x78 {
            let cmf = data[0] as u16;
            let flg = data[1] as u16;
            if (cmf * 256 + flg) % 31 == 0 {
                return Some(ArchiveFormat::Zlib);
            }
        }

        // TAR: "ustar\0" or "ustar  " at offset 257
        if data.len() >= 263 {
            let magic = &data[257..263];
            if magic == b"ustar\0" || magic == b"ustar " {
                return Some(ArchiveFormat::Tar);
            }
        }

        None
    }

    /// Detect burn patterns
    ///
    /// Mirrors existing Stage 3 DataStorage::is_proof_of_burn logic to avoid regression.
    /// Handles three canonical forms:
    /// 1. Pure 32 bytes of 0xFF (no prefix)
    /// 2. Compressed: 0x02 OR 0x03 prefix + 32 bytes of 0xFF (33 bytes total)
    /// 3. Uncompressed: 0x04 prefix + 64 bytes of 0xFF (65 bytes total)
    fn detect_burn_pattern(data: &[u8]) -> Option<BurnPattern> {
        match data.len() {
            32 => {
                // Pure 32-byte 0xFF pattern (no prefix)
                if data.iter().all(|&b| b == 0xFF) {
                    return Some(BurnPattern::CompressedBurn);
                }
            }
            33 => {
                // Compressed pubkey: prefix (0x02 or 0x03) + 32 bytes of 0xFF
                if (data[0] == 0x02 || data[0] == 0x03) && data[1..].iter().all(|&b| b == 0xFF) {
                    return Some(BurnPattern::CompressedBurn);
                }
            }
            65 => {
                // Uncompressed pubkey: prefix (0x04) + 64 bytes of 0xFF
                if data[0] == 0x04 && data[1..].iter().all(|&b| b == 0xFF) {
                    return Some(BurnPattern::UncompressedBurn);
                }
            }
            _ => {}
        }

        None
    }

    /// Detect audio formats (conservative - requires container headers/tags)
    fn detect_audio_conservative(data: &[u8]) -> Option<AudioFormat> {
        if data.len() < 12 {
            return None;
        }

        // MP3: Only accept if it has ID3 tag (ID3 or 49 44 33)
        // This avoids false positives from MPEG sync words (FF F?) in random data
        if data.starts_with(b"ID3") || data.starts_with(&[0x49, 0x44, 0x33]) {
            return Some(AudioFormat::Mp3);
        }

        // WAV: RIFF....WAVE
        if data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WAVE" {
            return Some(AudioFormat::Wav);
        }

        // OGG: OggS
        if data.starts_with(b"OggS") {
            return Some(AudioFormat::Ogg);
        }

        // FLAC: fLaC
        if data.starts_with(b"fLaC") {
            return Some(AudioFormat::Flac);
        }

        None
    }

    /// Detect video formats (conservative - requires valid container headers)
    fn detect_video_conservative(data: &[u8]) -> Option<VideoFormat> {
        if data.len() < 12 {
            return None;
        }

        // MP4: ftyp with brand validation (avoid DOCX/EPUB false positives)
        if &data[4..8] == b"ftyp" && data.len() >= 12 {
            let brand = &data[8..12];
            // Common MP4 brands (not M4A audio)
            if brand == b"isom"
                || brand == b"mp42"
                || brand == b"mp41"
                || brand == b"avc1"
                || brand == b"iso2"
            {
                return Some(VideoFormat::Mp4);
            }
        }

        // WebM/MKV: EBML header with doctype validation
        if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
            // Look for doctype in next 100 bytes
            if let Some(pos) = data.windows(4).position(|w| w == b"webm") {
                if pos < 100 {
                    return Some(VideoFormat::WebM);
                }
            }
            if let Some(pos) = data.windows(8).position(|w| w == b"matroska") {
                if pos < 100 {
                    return Some(VideoFormat::Mkv);
                }
            }
        }

        // AVI: RIFF....AVI
        if data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"AVI " {
            return Some(VideoFormat::Avi);
        }

        None
    }

    /// Detect structured data formats
    fn detect_structured(data: &[u8]) -> Option<StructuredFormat> {
        // Require valid UTF-8 for structured formats
        if let Ok(text) = std::str::from_utf8(data) {
            let trimmed = text.trim_start();

            // JSON: starts with { or [
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                return Some(StructuredFormat::Json);
            }

            // XML: starts with <?xml or <
            if trimmed.starts_with("<?xml")
                || (trimmed.starts_with('<') && !trimmed.starts_with("<!"))
            {
                return Some(StructuredFormat::Xml);
            }
        }

        None
    }

    /// Detect text formats
    fn detect_text(data: &[u8]) -> Option<TextFormat> {
        // Use lossy UTF-8 conversion to handle data with binary prefixes/suffixes
        // This allows detection of text content even when embedded in binary wrappers
        let text = String::from_utf8_lossy(data);

        // Python: shebang or keywords
        if text.starts_with("#!/usr/bin/python") || text.starts_with("#!/usr/bin/env python") {
            return Some(TextFormat::Python);
        }

        // Also check for shebang anywhere in first 100 characters (may have binary prefix)
        if data.len() > 20 {
            // Use char_indices to get a safe slice (respects UTF-8 boundaries)
            let search_text = if text.len() > 100 {
                match text.char_indices().nth(100) {
                    Some((idx, _)) => &text[..idx],
                    None => &text[..],
                }
            } else {
                &text[..]
            };
            if search_text.contains("#!/usr/bin/python")
                || search_text.contains("#!/usr/bin/env python")
            {
                return Some(TextFormat::Python);
            }
        }

        // Check for Python keywords (requires significant text)
        if text.len() > 50 {
            let python_keywords = ["import ", "def ", "class ", "from ", "print("];
            let keyword_count = python_keywords
                .iter()
                .filter(|&&kw| text.contains(kw))
                .count();
            if keyword_count >= 2 {
                return Some(TextFormat::Python);
            }
        }

        // JavaScript: keywords
        if text.len() > 50 {
            let js_keywords = ["function ", "const ", "let ", "var ", "=>"];
            let keyword_count = js_keywords.iter().filter(|&&kw| text.contains(kw)).count();
            if keyword_count >= 2 {
                return Some(TextFormat::JavaScript);
            }
        }

        // Plain text: valid ASCII/UTF-8 with printable characters
        // Require minimum 10 bytes to avoid false positives on short binary signatures
        // Also require strict UTF-8 for plain text (no lossy conversion)
        if data.len() >= 10 {
            if let Ok(strict_text) = std::str::from_utf8(data) {
                if strict_text
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
                    .count()
                    > strict_text.len() / 2
                {
                    return Some(TextFormat::PlainText);
                }
            }
        }

        None
    }
}

// MIME type implementations for each format

impl ImageFormat {
    /// Get the file extension without leading dot (for decoder compatibility)
    ///
    /// This method returns extensions without a leading dot (e.g., "png" not ".png")
    /// to maintain compatibility with decoder code that constructs filenames.
    pub fn extension(&self) -> &'static str {
        match self {
            ImageFormat::Png => "png",
            ImageFormat::Jpeg => "jpg",
            ImageFormat::Gif => "gif",
            ImageFormat::WebP => "webp",
            ImageFormat::Svg => "svg",
            ImageFormat::Bmp => "bmp",
            ImageFormat::Tiff => "tiff",
            ImageFormat::Ico => "ico",
            ImageFormat::Avif => "avif",
            ImageFormat::JpegXl => "jxl",
        }
    }

    pub fn mime_type(&self) -> &'static str {
        match self {
            ImageFormat::Png => "image/png",
            ImageFormat::Jpeg => "image/jpeg",
            ImageFormat::Gif => "image/gif",
            ImageFormat::WebP => "image/webp",
            ImageFormat::Svg => "image/svg+xml",
            ImageFormat::Bmp => "image/bmp",
            ImageFormat::Tiff => "image/tiff",
            ImageFormat::Ico => "image/x-icon",
            ImageFormat::Avif => "image/avif",
            ImageFormat::JpegXl => "image/jxl",
        }
    }
}

/// Detect image format from binary data using magic bytes
///
/// This is a standalone public function for detecting image formats, used by both
/// Stage 3 classification and the decoder to maintain consistent detection.
///
/// # Returns
///
/// - `Some(ImageFormat)` if a known image format is detected
/// - `None` if no image format is detected
pub fn detect_image_format(data: &[u8]) -> Option<ImageFormat> {
    if data.is_empty() {
        return None;
    }

    // GIF: GIF87a or GIF89a (check early - only 6 bytes)
    if data.len() >= 6 && (data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        return Some(ImageFormat::Gif);
    }

    // BMP: BM (check early - only 2 bytes)
    if data.len() >= 2 && data.starts_with(b"BM") {
        return Some(ImageFormat::Bmp);
    }

    // TIFF: 49 49 2A 00 (little-endian) or 4D 4D 00 2A (big-endian) - 4 bytes
    if data.len() >= 4
        && (data.starts_with(&[0x49, 0x49, 0x2A, 0x00])
            || data.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]))
    {
        return Some(ImageFormat::Tiff);
    }

    // ICO: 00 00 01 00 - 4 bytes
    if data.len() >= 4 && data.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Some(ImageFormat::Ico);
    }

    // Minimum 8 bytes for most other formats
    if data.len() < 8 {
        return None;
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(ImageFormat::Png);
    }

    // JPEG: FF D8 FF
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(ImageFormat::Jpeg);
    }

    // WebP: RIFF....WEBP
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Some(ImageFormat::WebP);
    }

    // SVG: <?xml or <svg (handle UTF-8 BOM and leading whitespace)
    if let Ok(text) = std::str::from_utf8(data) {
        // Strip UTF-8 BOM (0xEF 0xBB 0xBF) if present
        let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
        // Trim leading whitespace
        let trimmed = text.trim_start();
        if trimmed.starts_with("<?xml") || trimmed.starts_with("<svg") {
            return Some(ImageFormat::Svg);
        }
    }

    // AVIF: Check for ftyp with avif brand
    if data.len() >= 12
        && &data[4..8] == b"ftyp"
        && (&data[8..12] == b"avif" || &data[8..12] == b"avis")
    {
        return Some(ImageFormat::Avif);
    }

    // JPEG XL: Require full 12-byte container header to avoid 0xFF 0x0A false positives
    // Container: 00 00 00 0C 4A 58 4C 20 0D 0A 87 0A
    if data.len() >= 12
        && data[0..4] == [0x00, 0x00, 0x00, 0x0C]
        && &data[4..8] == b"JXL "
        && data[8..12] == [0x0D, 0x0A, 0x87, 0x0A]
    {
        return Some(ImageFormat::JpegXl);
    }

    None
}

impl AudioFormat {
    pub fn mime_type(&self) -> &'static str {
        match self {
            AudioFormat::Mp3 => "audio/mpeg",
            AudioFormat::Wav => "audio/wav",
            AudioFormat::Ogg => "audio/ogg",
            AudioFormat::Flac => "audio/flac",
        }
    }
}

impl VideoFormat {
    pub fn mime_type(&self) -> &'static str {
        match self {
            VideoFormat::Mp4 => "video/mp4",
            VideoFormat::WebM => "video/webm",
            VideoFormat::Mkv => "video/x-matroska",
            VideoFormat::Avi => "video/x-msvideo",
        }
    }
}

impl DocumentFormat {
    pub fn mime_type(&self) -> &'static str {
        match self {
            DocumentFormat::Pdf => "application/pdf",
        }
    }
}

impl ArchiveFormat {
    pub fn mime_type(&self) -> &'static str {
        match self {
            ArchiveFormat::Zip => "application/zip",
            ArchiveFormat::Rar => "application/x-rar-compressed",
            ArchiveFormat::SevenZip => "application/x-7z-compressed",
            ArchiveFormat::Gzip => "application/gzip",
            ArchiveFormat::Bzip2 => "application/x-bzip2",
            ArchiveFormat::Zlib => "application/zlib",
            ArchiveFormat::Tar => "application/x-tar",
        }
    }
}

impl TextFormat {
    pub fn mime_type(&self) -> &'static str {
        match self {
            TextFormat::PlainText => "text/plain",
            TextFormat::Python => "text/x-python",
            TextFormat::JavaScript => "text/javascript",
        }
    }
}

impl StructuredFormat {
    pub fn mime_type(&self) -> &'static str {
        match self {
            StructuredFormat::Json => "application/json",
            StructuredFormat::Xml => "application/xml",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_png_detection() {
        let png_magic = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let ct = ContentType::detect(&png_magic).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::Png));
        assert_eq!(ct.mime_type(), "image/png");
    }

    #[test]
    fn test_jpeg_detection() {
        // JPEG needs at least 8 bytes for detection logic
        let jpeg_magic = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        let ct = ContentType::detect(&jpeg_magic).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::Jpeg));
        assert_eq!(ct.mime_type(), "image/jpeg");
    }

    #[test]
    fn test_gzip_detection() {
        let gzip_magic = vec![0x1F, 0x8B, 0x08, 0x00];
        let ct = ContentType::detect(&gzip_magic).unwrap();
        assert_eq!(ct, ContentType::Archive(ArchiveFormat::Gzip));
        assert_eq!(ct.mime_type(), "application/gzip");
    }

    #[test]
    fn test_pdf_detection() {
        let pdf_magic = b"%PDF-1.4\n".to_vec();
        let ct = ContentType::detect(&pdf_magic).unwrap();
        assert_eq!(ct, ContentType::Document(DocumentFormat::Pdf));
        assert_eq!(ct.mime_type(), "application/pdf");
    }

    #[test]
    fn test_burn_pattern_compressed() {
        let mut burn = vec![0x03];
        burn.extend(vec![0xFF; 32]);
        let ct = ContentType::detect(&burn).unwrap();
        assert_eq!(ct, ContentType::Burn(BurnPattern::CompressedBurn));
    }

    #[test]
    fn test_burn_pattern_raw_32_bytes() {
        // Pure 32 bytes of 0xFF (no prefix) - regression test
        let burn = vec![0xFF; 32];
        let ct = ContentType::detect(&burn).unwrap();
        assert_eq!(ct, ContentType::Burn(BurnPattern::CompressedBurn));
    }

    #[test]
    fn test_burn_pattern_compressed_0x02_prefix() {
        // 0x02 prefix + 32 bytes 0xFF - regression test
        let mut burn = vec![0x02];
        burn.extend(vec![0xFF; 32]);
        let ct = ContentType::detect(&burn).unwrap();
        assert_eq!(ct, ContentType::Burn(BurnPattern::CompressedBurn));
    }

    #[test]
    fn test_burn_pattern_uncompressed() {
        // 0x04 prefix + 64 bytes 0xFF
        let mut burn = vec![0x04];
        burn.extend(vec![0xFF; 64]);
        let ct = ContentType::detect(&burn).unwrap();
        assert_eq!(ct, ContentType::Burn(BurnPattern::UncompressedBurn));
    }

    #[test]
    fn test_svg_with_utf8_bom() {
        // SVG with UTF-8 BOM (0xEF 0xBB 0xBF) - regression test
        let svg_with_bom = b"\xEF\xBB\xBF<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
        let ct = ContentType::detect(svg_with_bom).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::Svg));
        assert_eq!(ct.mime_type(), "image/svg+xml");
    }

    #[test]
    fn test_svg_with_leading_whitespace() {
        // SVG with leading whitespace - regression test
        let svg_with_whitespace = b"  \n\t<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
        let ct = ContentType::detect(svg_with_whitespace).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::Svg));
        assert_eq!(ct.mime_type(), "image/svg+xml");
    }

    #[test]
    fn test_svg_with_bom_and_whitespace() {
        // SVG with both UTF-8 BOM and leading whitespace - regression test
        let svg_complex = b"\xEF\xBB\xBF  \n<?xml version=\"1.0\"?>\n<svg></svg>";
        let ct = ContentType::detect(svg_complex).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::Svg));
        assert_eq!(ct.mime_type(), "image/svg+xml");
    }

    #[test]
    fn test_mp3_with_id3_detection() {
        // MP3 with ID3v2 header - needs at least 12 bytes
        let id3_header = b"ID3\x03\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        let ct = ContentType::detect(&id3_header).unwrap();
        assert_eq!(ct, ContentType::Audio(AudioFormat::Mp3));
        assert_eq!(ct.mime_type(), "audio/mpeg");
    }

    #[test]
    fn test_python_script_detection() {
        let python = b"#!/usr/bin/python3\nimport os\ndef main():\n    print('hello')";
        let ct = ContentType::detect(python).unwrap();
        assert_eq!(ct, ContentType::Text(TextFormat::Python));
        assert_eq!(ct.mime_type(), "text/x-python");
    }

    #[test]
    fn test_json_detection() {
        let json = br#"{"key": "value", "number": 123}"#;
        let ct = ContentType::detect(json).unwrap();
        assert_eq!(ct, ContentType::Structured(StructuredFormat::Json));
        assert_eq!(ct.mime_type(), "application/json");
    }

    /// Verify image format parity between Stamps and DataStorage
    #[test]
    fn test_image_format_parity() {
        // All image formats that Bitcoin Stamps currently detects
        let test_cases = vec![
            (
                vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
                ImageFormat::Png,
                "image/png",
            ),
            (
                vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46],
                ImageFormat::Jpeg,
                "image/jpeg",
            ),
            (b"GIF89a".to_vec(), ImageFormat::Gif, "image/gif"),
            // WebP: RIFF....WEBP
            (
                {
                    let mut webp = b"RIFF".to_vec();
                    webp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                    webp.extend_from_slice(b"WEBP");
                    webp
                },
                ImageFormat::WebP,
                "image/webp",
            ),
            (
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".to_vec(),
                ImageFormat::Svg,
                "image/svg+xml",
            ),
            (b"BM".to_vec(), ImageFormat::Bmp, "image/bmp"),
        ];

        for (data, expected_format, expected_mime) in test_cases {
            let ct = ContentType::detect(&data).unwrap();
            assert_eq!(
                ct,
                ContentType::Image(expected_format),
                "Failed to detect {:?} from data: {:?}",
                expected_format,
                &data[..data.len().min(20)]
            );
            assert_eq!(ct.mime_type(), expected_mime);
        }
    }

    /// Verify additional image formats beyond Stamps (TIFF, ICO, AVIF, JPEG XL)
    #[test]
    fn test_extended_image_formats() {
        // TIFF (little-endian)
        let tiff_le = vec![0x49, 0x49, 0x2A, 0x00];
        let ct = ContentType::detect(&tiff_le).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::Tiff));
        assert_eq!(ct.mime_type(), "image/tiff");

        // ICO
        let ico = vec![0x00, 0x00, 0x01, 0x00];
        let ct = ContentType::detect(&ico).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::Ico));
        assert_eq!(ct.mime_type(), "image/x-icon");

        // AVIF
        let mut avif = vec![0x00, 0x00, 0x00, 0x18];
        avif.extend_from_slice(b"ftyp");
        avif.extend_from_slice(b"avif");
        let ct = ContentType::detect(&avif).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::Avif));
        assert_eq!(ct.mime_type(), "image/avif");

        // JPEG XL (full container)
        let jxl = vec![
            0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
        ];
        let ct = ContentType::detect(&jxl).unwrap();
        assert_eq!(ct, ContentType::Image(ImageFormat::JpegXl));
        assert_eq!(ct.mime_type(), "image/jxl");
    }

    #[test]
    fn test_file_extension_and_category_helpers() {
        let png = ContentType::Image(ImageFormat::Png);
        assert_eq!(png.file_extension(), Some(".png"));
        assert_eq!(png.category(), "Images");

        let json = ContentType::Structured(StructuredFormat::Json);
        assert_eq!(json.file_extension(), Some(".json"));
        assert_eq!(json.category(), "Structured Data");
    }

    #[test]
    fn test_unknown_extension_defaults() {
        let binary = ContentType::Binary;
        assert_eq!(binary.file_extension(), None);
        assert_eq!(binary.category(), "Other");

        let burn = ContentType::Burn(BurnPattern::CompressedBurn);
        assert_eq!(burn.file_extension(), None);
        assert_eq!(burn.category(), "Other");
    }

    #[test]
    fn test_from_mime_type_roundtrip() {
        let ct = ContentType::from_mime_type("application/pdf").unwrap();
        assert_eq!(ct, ContentType::Document(DocumentFormat::Pdf));
        assert_eq!(ct.file_extension(), Some(".pdf"));
        assert_eq!(ct.category(), "Documents");

        // Unknown MIME types should return None
        assert!(ContentType::from_mime_type("application/unknown").is_none());
    }

    /// Test standalone detect_image_format() function
    #[test]
    fn test_detect_image_format_standalone() {
        // PNG (8 bytes minimum)
        let png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_image_format(&png), Some(ImageFormat::Png));

        // JPEG (needs 8 bytes minimum due to early-exit check in detect_image_format)
        let jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(detect_image_format(&jpeg), Some(ImageFormat::Jpeg));

        // GIF (6 bytes minimum)
        assert_eq!(detect_image_format(b"GIF89a"), Some(ImageFormat::Gif));
        assert_eq!(detect_image_format(b"GIF87a"), Some(ImageFormat::Gif));

        // WebP (12 bytes minimum)
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        webp.extend_from_slice(b"WEBP");
        assert_eq!(detect_image_format(&webp), Some(ImageFormat::WebP));

        // SVG (text-based, parsed)
        assert_eq!(
            detect_image_format(b"<svg xmlns=\"test\">"),
            Some(ImageFormat::Svg)
        );

        // BMP (2 bytes minimum)
        assert_eq!(detect_image_format(b"BM\x00\x00"), Some(ImageFormat::Bmp));

        // Empty/unknown returns None
        assert_eq!(detect_image_format(&[]), None);
        assert_eq!(detect_image_format(b"unknown data"), None);
    }

    /// Test ImageFormat::extension() returns extension WITHOUT leading dot (decoder compat)
    #[test]
    fn test_image_format_extension_no_dot() {
        // Verify extension() returns WITHOUT leading dot (for decoder compatibility)
        assert_eq!(ImageFormat::Png.extension(), "png");
        assert_eq!(ImageFormat::Jpeg.extension(), "jpg");
        assert_eq!(ImageFormat::Gif.extension(), "gif");
        assert_eq!(ImageFormat::WebP.extension(), "webp");
        assert_eq!(ImageFormat::Svg.extension(), "svg");
        assert_eq!(ImageFormat::Bmp.extension(), "bmp");
        assert_eq!(ImageFormat::Tiff.extension(), "tiff");
        assert_eq!(ImageFormat::Ico.extension(), "ico");
        assert_eq!(ImageFormat::Avif.extension(), "avif");
        assert_eq!(ImageFormat::JpegXl.extension(), "jxl");

        // Verify ContentType::file_extension() returns WITH leading dot (existing API)
        let png_ct = ContentType::Image(ImageFormat::Png);
        let jpeg_ct = ContentType::Image(ImageFormat::Jpeg);
        assert_eq!(png_ct.file_extension(), Some(".png"));
        assert_eq!(jpeg_ct.file_extension(), Some(".jpg"));
    }

    /// Test PDF detection uses window search in first 1024 bytes
    #[test]
    fn test_pdf_window_search_detection() {
        // PDF at start
        let pdf_start = b"%PDF-1.4\nsome content";
        let ct = ContentType::detect(pdf_start).unwrap();
        assert_eq!(ct, ContentType::Document(DocumentFormat::Pdf));

        // PDF not at exact start (within 1024 bytes)
        let mut pdf_offset = vec![0x00; 100];
        pdf_offset.extend_from_slice(b"%PDF-1.7\ntest");
        let ct = ContentType::detect(&pdf_offset).unwrap();
        assert_eq!(ct, ContentType::Document(DocumentFormat::Pdf));
    }

    /// Regression test: ZIP file containing "%PDF" string should NOT be detected as PDF
    #[test]
    fn test_zip_with_pdf_string_not_misclassified() {
        // ZIP signature (PK) followed by some data that happens to contain "%PDF"
        let mut zip_with_pdf = vec![0x50, 0x4B, 0x03, 0x04]; // ZIP magic
        zip_with_pdf.extend_from_slice(b"some ZIP content here");
        zip_with_pdf.extend_from_slice(b"%PDF-1.4"); // %PDF string inside ZIP
        zip_with_pdf.extend_from_slice(b"more content");

        let ct = ContentType::detect(&zip_with_pdf).unwrap();
        // Should detect as ZIP, NOT as PDF
        assert_eq!(
            ct,
            ContentType::Archive(ArchiveFormat::Zip),
            "ZIP file with '%PDF' payload should be detected as ZIP, not PDF"
        );
    }

    /// Regression test: RAR file containing "%PDF" string should NOT be detected as PDF
    #[test]
    fn test_rar_with_pdf_string_not_misclassified() {
        // RAR signature followed by data containing "%PDF"
        let mut rar_with_pdf = b"Rar!\x1A\x07\x00".to_vec(); // RAR magic
        rar_with_pdf.extend_from_slice(b"some RAR content");
        rar_with_pdf.extend_from_slice(b"%PDF-1.5");

        let ct = ContentType::detect(&rar_with_pdf).unwrap();
        assert_eq!(
            ct,
            ContentType::Archive(ArchiveFormat::Rar),
            "RAR file with '%PDF' payload should be detected as RAR, not PDF"
        );
    }
}
