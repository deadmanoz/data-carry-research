use super::burn_patterns::STAMPS_BURN_KEYS;
use super::ProtocolVariant;
use crate::crypto::arc4;
use crate::processor::stage3::PubkeyExtractor;
use base64::{
    alphabet,
    engine::{self, general_purpose::GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use serde::{Deserialize, Serialize};

/// Bitcoin Stamps protocol constants and type definitions
///
/// Bitcoin Stamps embed digital art and files directly in the Bitcoin blockchain using
/// P2MS (Pay-to-Multisig) outputs with specific burn patterns and ARC4 obfuscation.
/// Bitcoin Stamps signature variants found in real transactions
///
/// The Bitcoin Stamps protocol uses "stamp:" or "stamps:" signatures (case-insensitive)
/// in ARC4-decrypted P2MS data. This enum tracks all observed variants for population statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampSignature {
    /// "stamp:" - lowercase singular (most common, canonical per protocol spec)
    StampLower,
    /// "STAMP:" - uppercase singular (used in Counterparty-embedded stamps)
    StampUpper,
    /// "stamps:" - lowercase plural (rare variant observed in wild)
    StampsLower,
    /// "STAMPS:" - uppercase plural (theoretical, for completeness)
    StampsUpper,
}

impl StampSignature {
    /// Get the byte string for this signature variant
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::StampLower => b"stamp:",
            Self::StampUpper => b"STAMP:",
            Self::StampsLower => b"stamps:",
            Self::StampsUpper => b"STAMPS:",
        }
    }

    /// Get the length of this signature in bytes
    pub const fn len(&self) -> usize {
        match self {
            Self::StampLower | Self::StampUpper => 6,
            Self::StampsLower | Self::StampsUpper => 7,
        }
    }

    /// Check if this signature is empty (always false for enum variants)
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Check if this is a plural variant
    pub const fn is_plural(&self) -> bool {
        matches!(self, Self::StampsLower | Self::StampsUpper)
    }

    /// Check if this is an uppercase variant
    pub const fn is_uppercase(&self) -> bool {
        matches!(self, Self::StampUpper | Self::StampsUpper)
    }

    /// All possible signature variants (ordered by likelihood: singular before plural, lower before upper)
    pub const ALL: [StampSignature; 4] = [
        Self::StampLower,  // Most common
        Self::StampUpper,  // Counterparty-embedded
        Self::StampsLower, // Rare
        Self::StampsUpper, // Theoretical
    ];
}

impl std::fmt::Display for StampSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", std::str::from_utf8(self.as_bytes()).unwrap())
    }
}

impl std::str::FromStr for StampSignature {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Literal tokens (for database storage)
            "stamp:" => Ok(Self::StampLower),
            "STAMP:" => Ok(Self::StampUpper),
            "stamps:" => Ok(Self::StampsLower),
            "STAMPS:" => Ok(Self::StampsUpper),
            // Enum names (for backfills/fixtures tolerance)
            "StampLower" => Ok(Self::StampLower),
            "StampUpper" => Ok(Self::StampUpper),
            "StampsLower" => Ok(Self::StampsLower),
            "StampsUpper" => Ok(Self::StampsUpper),
            _ => Err(format!("Unknown stamp signature: {}", s)),
        }
    }
}

/// Bitcoin Stamps burn pattern types
/// These correspond to the specific burn keys used in P2MS outputs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampsBurnPattern {
    /// 022222... pattern (most common)
    Stamps22,
    /// 033333... pattern
    Stamps33,
    /// 020202... alternating pattern
    Stamps0202,
    /// 030303... alternating pattern (two variants)
    Stamps0303,
}

#[allow(dead_code)]
impl StampsBurnPattern {
    /// Get the burn key hex string for this pattern
    pub fn burn_key(&self) -> &'static str {
        match self {
            StampsBurnPattern::Stamps22 => STAMPS_BURN_KEYS[0],
            StampsBurnPattern::Stamps33 => STAMPS_BURN_KEYS[1],
            StampsBurnPattern::Stamps0202 => STAMPS_BURN_KEYS[2],
            StampsBurnPattern::Stamps0303 => STAMPS_BURN_KEYS[3], // Default to first variant
        }
    }

    /// Check if a pubkey hex matches this burn pattern
    pub fn matches_pubkey(&self, pubkey_hex: &str) -> bool {
        match self {
            StampsBurnPattern::Stamps22 => pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[0]),
            StampsBurnPattern::Stamps33 => pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[1]),
            StampsBurnPattern::Stamps0202 => pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[2]),
            StampsBurnPattern::Stamps0303 => {
                pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[3])
                    || pubkey_hex.eq_ignore_ascii_case(STAMPS_BURN_KEYS[4])
            }
        }
    }

    /// Parse a pubkey hex to determine the burn pattern type
    pub fn from_pubkey(pubkey_hex: &str) -> Option<Self> {
        [
            Self::Stamps22,
            Self::Stamps33,
            Self::Stamps0202,
            Self::Stamps0303,
        ]
        .into_iter()
        .find(|pattern| pattern.matches_pubkey(pubkey_hex))
    }
}

/// Bitcoin Stamps protocol variants
/// Different types of data that can be embedded using the Stamps protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampsVariant {
    /// Classic Bitcoin Stamps - embedded images and files
    Classic,
    /// SRC-20 fungible tokens
    SRC20,
    /// SRC-721 non-fungible tokens (NFTs)
    SRC721,
    /// SRC-101 domain names
    SRC101,
    /// HTML documents and JavaScript applications
    HTML,
    /// Compressed data (ZLIB, GZIP)
    Compressed,
    /// Generic data (XML, non-SRC JSON, binary data)
    Data,
    /// Unknown - Unrecognisable content or burn-pattern-only detection
    Unknown,
}

impl From<StampsVariant> for ProtocolVariant {
    fn from(variant: StampsVariant) -> Self {
        match variant {
            StampsVariant::Classic => ProtocolVariant::StampsClassic,
            StampsVariant::SRC20 => ProtocolVariant::StampsSRC20,
            StampsVariant::SRC721 => ProtocolVariant::StampsSRC721,
            StampsVariant::SRC101 => ProtocolVariant::StampsSRC101,
            StampsVariant::HTML => ProtocolVariant::StampsHTML,
            StampsVariant::Compressed => ProtocolVariant::StampsCompressed,
            StampsVariant::Data => ProtocolVariant::StampsData,
            StampsVariant::Unknown => ProtocolVariant::StampsUnknown,
        }
    }
}

/// Bitcoin Stamps transport mechanism
///
/// This enum distinguishes between Pure Bitcoin Stamps (which always use burn keys)
/// and Counterparty-transported Stamps (which may use real signing keys).
///
/// ## Spendability Rules
///
/// - **Pure**: Always uses burn keys → Always unspendable
/// - **Counterparty**: May use real keys OR burn keys → Check key composition:
///   - If burn keys present → Unspendable (even if real keys also present)
///   - If NO burn keys (only real keys) → Spendable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StampsTransport {
    /// Pure Bitcoin Stamps - ALWAYS use burn keys (always unspendable)
    Pure,
    /// Counterparty transport - MAY use real pubkeys (check for burn keys to determine spendability)
    Counterparty,
}

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

/// Image format classification for Bitcoin Stamps
///
/// Used for variant detection to identify image-based Classic stamps
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Gif,
    WebP,
    Svg,
    Bmp,
    Pdf,
}

/// Detect image format from binary data using magic bytes
///
/// This is a pure helper function with no decoder dependencies, used by both
/// Stage 3 classification and the decoder to maintain consistent variant detection.
pub fn detect_image_format(data: &[u8]) -> Option<ImageFormat> {
    if data.is_empty() {
        return None;
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A (‰PNG\r\n\x1a\n)
    if data.len() >= 8 && data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(ImageFormat::Png);
    }

    // JPEG: FF D8 FF
    if data.len() >= 3 && data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(ImageFormat::Jpeg);
    }

    // GIF: "GIF87a" or "GIF89a"
    if data.len() >= 6 && (data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        return Some(ImageFormat::Gif);
    }

    // WebP: "RIFF" + 4 bytes + "WEBP"
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Some(ImageFormat::WebP);
    }

    // SVG: Look for XML declaration or SVG tag (text-based)
    if data.len() >= 5 {
        let data_str = String::from_utf8_lossy(data);
        let lower = data_str.to_lowercase();
        if lower.starts_with("<?xml") || lower.starts_with("<svg") {
            return Some(ImageFormat::Svg);
        }
    }

    // BMP: "BM" signature
    if data.len() >= 2 && data.starts_with(b"BM") {
        return Some(ImageFormat::Bmp);
    }

    // PDF: %PDF (0x25 0x50 0x44 0x46)
    // Search in first 1024 bytes since PDF header might not be at exact start
    let search_len = data.len().min(1024);
    if data[..search_len].windows(4).any(|w| w == b"%PDF") {
        return Some(ImageFormat::Pdf);
    }

    None
}

/// Detect compression format (ZLIB or GZIP only)
///
/// Checks for:
/// - ZLIB: At offsets [0, 5, 7] with CMF-FLG checksum validation
/// - GZIP: Magic bytes 0x1F 0x8B at offset 0
///
/// Returns appropriate MIME type for detected compression
pub(crate) fn detect_compression_format(data: &[u8]) -> Option<&'static str> {
    // Check ZLIB at empirical offsets [0, 5, 7]
    if validation::check_zlib_at_offsets(data, &[0, 5, 7]) {
        return Some("application/zlib");
    }

    // Check GZIP (0x1F 0x8B magic bytes) - require at least 4 bytes
    if data.len() >= 4 && data[0] == 0x1F && data[1] == 0x8B {
        return Some("application/gzip");
    }

    None
}

/// SRC-20 token operation types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SRC20Operation {
    /// Deploy a new SRC-20 token
    Deploy,
    /// Mint tokens to an address
    Mint,
    /// Transfer tokens between addresses
    Transfer,
}

/// P2MS encoding specifications for Bitcoin Stamps
pub mod encoding {
    /// Standard P2MS pattern for Bitcoin Stamps: 1-of-3 multisig
    pub const REQUIRED_SIGS: u8 = 1;
    pub const TOTAL_PUBKEYS: u8 = 3;

    /// Data capacity per P2MS output (first two 33-byte pubkeys, minus prefix/suffix bytes)
    pub const DATA_BYTES_PER_OUTPUT: usize = 62; // 31 bytes per pubkey * 2 pubkeys

    /// Pubkey structure: 33 bytes total, data in bytes 1-31 (excluding first and last byte)
    pub const PUBKEY_TOTAL_BYTES: usize = 33;
    pub const PUBKEY_DATA_START: usize = 1;
    pub const PUBKEY_DATA_END: usize = 32;
}

/// Helper functions for Bitcoin Stamps protocol detection and validation
pub mod validation {
    use super::*;

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
                    if ((cmf as u16) * 256 + (flg as u16)) % 31 == 0 {
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

    /// Find stamp signature in decrypted data, returning offset and variant
    ///
    /// Checks all signature variants (case-insensitive) and returns the first match found.
    /// Returns: (byte_offset, signature_variant)
    pub fn find_stamp_signature(decrypted_data: &[u8]) -> Option<(usize, StampSignature)> {
        for sig_variant in StampSignature::ALL {
            if let Some(pos) = decrypted_data
                .windows(sig_variant.len())
                .position(|window| window.eq_ignore_ascii_case(sig_variant.as_bytes()))
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
    fn strip_data_uri_prefix(data: &[u8]) -> Vec<u8> {
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
    fn strip_data_uri_prefix_str(data: &str) -> &str {
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
    /// This is the CANONICAL extraction function used by both Stage 3 and Stage 4.
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

    /// Process multiple P2MS outputs for Bitcoin Stamps - tries both processing methods
    ///
    /// Bitcoin Stamps has two main variants:
    /// 1. Counterparty-Embedded: Complex length-based extraction with CNTRPRTY + STAMP signatures
    /// 2. Pure Bitcoin Stamps: Simple concatenation → ARC4 decrypt → 'stamp:' signature only
    ///
    /// We try Counterparty-embedded first since it has more specific requirements.
    pub fn process_multioutput_stamps<'a>(
        p2ms_outputs: &'a [crate::types::TransactionOutput],
        arc4_key: &[u8],
    ) -> Option<StampsProcessingResult<'a>> {
        if p2ms_outputs.is_empty() || arc4_key.is_empty() {
            return None;
        }

        // Try Counterparty-embedded processing first (more specific requirements)
        if let Some(result) = process_counterparty_embedded_stamps(p2ms_outputs, arc4_key) {
            return Some(result);
        }

        // Fallback to pure Bitcoin Stamps processing
        process_pure_stamps(p2ms_outputs, arc4_key)
    }

    /// Process pure Bitcoin Stamps using simple concatenation + ARC4 decryption
    ///
    /// This handles the majority of Bitcoin Stamps transactions:
    /// - Concatenate all data chunks from P2MS outputs
    /// - Single ARC4 decrypt of the concatenated data
    /// - Look for 'stamp:' signature (but NOT CNTRPRTY to avoid false positives)
    pub fn process_pure_stamps<'a>(
        p2ms_outputs: &'a [crate::types::TransactionOutput],
        arc4_key: &[u8],
    ) -> Option<StampsProcessingResult<'a>> {
        if p2ms_outputs.is_empty() || arc4_key.is_empty() {
            return None;
        }

        // Sort outputs by vout for sequential processing
        let mut sorted_outputs: Vec<_> = p2ms_outputs.iter().collect();
        sorted_outputs.sort_by_key(|output| output.vout);

        // Extract and concatenate all data chunks
        let mut concatenated_data = Vec::new();
        let mut valid_outputs = Vec::new();

        for output in sorted_outputs.iter() {
            if let Some(info) = output.multisig_info() {
                if is_stamps_p2ms(
                    info.required_sigs as u8,
                    info.total_pubkeys as u8,
                    &info.pubkeys,
                ) {
                    if let Some(chunk) = extract_data_chunk(&info.pubkeys) {
                        concatenated_data.extend(chunk);
                        valid_outputs.push(*output);
                    }
                }
            }
        }

        if concatenated_data.is_empty() || valid_outputs.is_empty() {
            return None;
        }

        // Single ARC4 decrypt of all concatenated data
        let decrypted_data = arc4::decrypt(&concatenated_data, arc4_key)?;

        // Check that this is pure Stamps (has STAMP but NOT CNTRPRTY)
        let has_cntrprty = decrypted_data
            .windows(crate::types::counterparty::COUNTERPARTY_PREFIX.len())
            .any(|window| window == crate::types::counterparty::COUNTERPARTY_PREFIX);

        if has_cntrprty {
            // This should be handled by Counterparty-embedded path, not pure path
            return None;
        }

        // Look for stamp signature in pure Stamps data
        let (stamp_offset, variant) = find_stamp_signature(&decrypted_data)?;

        Some(StampsProcessingResult {
            valid_outputs,
            concatenated_data_size: concatenated_data.len(),
            decrypted_data,
            stamp_signature_offset: stamp_offset,
            stamp_signature_variant: variant,
        })
    }

    /// Process Counterparty-embedded Bitcoin Stamps using length-based extraction
    ///
    /// This handles complex multi-packet Stamps that use Counterparty transport:
    /// - Per-output ARC4 decrypt → length-based extraction → reassemble
    /// - Requires BOTH CNTRPRTY and STAMP signatures for validation
    /// - Handles CNTRPRTY prefix logic like Electrum-Counterparty
    pub fn process_counterparty_embedded_stamps<'a>(
        p2ms_outputs: &'a [crate::types::TransactionOutput],
        arc4_key: &[u8],
    ) -> Option<StampsProcessingResult<'a>> {
        if p2ms_outputs.is_empty() || arc4_key.is_empty() {
            return None;
        }

        // Sort outputs by vout for sequential processing
        let mut sorted_outputs: Vec<_> = p2ms_outputs.iter().collect();
        sorted_outputs.sort_by_key(|output| output.vout);

        // Process each output individually with length-based extraction (like Electrum-Counterparty)
        let mut valid_outputs = Vec::new();
        let mut cp_msg = String::new();
        let mut total_raw_data_size = 0;

        for (i, output) in sorted_outputs.iter().enumerate() {
            if let Some(info) = output.multisig_info() {
                if is_stamps_p2ms(
                    info.required_sigs as u8,
                    info.total_pubkeys as u8,
                    &info.pubkeys,
                ) {
                    if let Some(chunk) = extract_data_chunk(&info.pubkeys) {
                        total_raw_data_size += chunk.len();

                        // ARC4 decrypt this specific chunk (key difference from regular Counterparty)
                        if let Some(raw_decrypted) = arc4::decrypt(&chunk, arc4_key) {
                            let raw_hex = hex::encode(&raw_decrypted);

                            if raw_hex.len() >= 2 {
                                // Extract length from first byte (2 hex chars)
                                if let Ok(len) = u8::from_str_radix(&raw_hex[0..2], 16) {
                                    let len_chars = (len as usize) * 2; // Convert bytes to hex chars

                                    if raw_hex.len() >= 2 + len_chars {
                                        let mut raw = raw_hex[2..2 + len_chars].to_string();

                                        // Handle CNTRPRTY prefix logic like Electrum-Counterparty
                                        if raw.len() >= 16 && &raw[0..16] == "434e545250525459" {
                                            // "CNTRPRTY"
                                            if i == 0
                                                || (cp_msg.len() >= 16
                                                    && &cp_msg[0..16] != "434e545250525459")
                                            {
                                                // First message or cp_msg doesn't start with CNTRPRTY, keep prefix
                                            } else {
                                                // Subsequent message with CNTRPRTY, remove duplicate prefix
                                                raw = raw[16..].to_string();
                                            }
                                        } else if raw.is_empty() {
                                            continue; // Skip empty chunks
                                        }

                                        valid_outputs.push(*output);
                                        cp_msg.push_str(&raw);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if valid_outputs.is_empty() || cp_msg.is_empty() {
            return None;
        }

        // Convert final hex message back to bytes
        let final_decoded_bytes = hex::decode(&cp_msg).ok()?;

        // Require BOTH CNTRPRTY and STAMP signatures for Counterparty-embedded
        let has_cntrprty = final_decoded_bytes
            .windows(crate::types::counterparty::COUNTERPARTY_PREFIX.len())
            .any(|window| window == crate::types::counterparty::COUNTERPARTY_PREFIX);

        let stamp_result = find_stamp_signature(&final_decoded_bytes);

        // Must have both signatures to qualify as Counterparty-embedded
        if has_cntrprty && stamp_result.is_some() {
            let (stamp_offset, variant) = stamp_result.unwrap();
            Some(StampsProcessingResult {
                valid_outputs,
                concatenated_data_size: total_raw_data_size,
                decrypted_data: final_decoded_bytes,
                stamp_signature_offset: stamp_offset,
                stamp_signature_variant: variant,
            })
        } else {
            None
        }
    }

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
    /// - Stage 4 decoder (decoder/mod.rs) - image extraction
    /// - Variant detection (stamps.rs validation) - format identification
    pub const BASE64_LENIENT: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(engine::DecodePaddingMode::Indifferent),
    );

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
    /// - `Compressed` → MUST return (Some(Compressed), Some(content_type), None)
    /// - `Classic` → MUST return (Some(Classic), Some(content_type), Some(image_format))
    /// - `SRC20/721/101` → MUST return (Some(variant), Some("application/json"), None)
    /// - `HTML` → MUST return (Some(HTML), Some("text/html"), None)
    /// - `Data` → MUST return (Some(Data), Some(content_type), None)
    /// - `Unknown` → MUST return (Some(Unknown), None, None)
    ///
    /// Used by Stage 3 classifier and Stage 4 decoder to ensure identical detection logic.
    pub(crate) fn detect_content_type_from_payload(
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

        // IMAGE CHECK (Classic variant) - includes binary image formats
        if let Some(image_format) = detect_image_format(payload) {
            let content_type = match image_format {
                ImageFormat::Png => "image/png",
                ImageFormat::Jpeg => "image/jpeg",
                ImageFormat::Gif => "image/gif",
                ImageFormat::WebP => "image/webp",
                ImageFormat::Svg => "image/svg+xml",
                ImageFormat::Bmp => "image/bmp",
                ImageFormat::Pdf => "application/pdf",
            };
            let result = (
                Some(StampsVariant::Classic),
                Some(content_type),
                Some(image_format),
            );
            debug_assert!(
                result.1.is_some() && result.2.is_some(),
                "Classic must have BOTH content_type and image_format"
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
            if trimmed.starts_with("<svg")
                || (trimmed.starts_with("<?xml") && text.contains("<svg"))
            {
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

    /// Result of processing multiple P2MS outputs for Bitcoin Stamps
    #[derive(Debug, Clone)]
    pub struct StampsProcessingResult<'a> {
        pub valid_outputs: Vec<&'a crate::types::TransactionOutput>,
        pub concatenated_data_size: usize,
        pub decrypted_data: Vec<u8>,
        pub stamp_signature_offset: usize,
        pub stamp_signature_variant: StampSignature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burn_pattern_matching() {
        let stamps22_key = "022222222222222222222222222222222222222222222222222222222222222222";
        assert_eq!(
            StampsBurnPattern::from_pubkey(stamps22_key),
            Some(StampsBurnPattern::Stamps22)
        );
        assert!(StampsBurnPattern::Stamps22.matches_pubkey(stamps22_key));
    }

    #[test]
    fn test_is_stamps_burn_key() {
        assert!(validation::is_stamps_burn_key(
            "022222222222222222222222222222222222222222222222222222222222222222"
        ));
        assert!(validation::is_stamps_burn_key(
            "033333333333333333333333333333333333333333333333333333333333333333"
        ));
        assert!(!validation::is_stamps_burn_key(
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
        assert!(validation::is_stamps_p2ms(1, 3, &pubkeys));
        assert!(!validation::is_stamps_p2ms(2, 3, &pubkeys)); // Wrong required_sigs
    }

    #[test]
    fn test_arc4_decrypt() {
        let data = b"hello";
        let key = b"key";
        let encrypted = arc4::decrypt(data, key).unwrap();
        let decrypted = arc4::decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_stamp_signature_display_fromstr_roundtrip() {
        // Test all signature variants can round-trip through Display/FromStr
        for variant in StampSignature::ALL {
            let display_str = variant.to_string();
            let parsed: StampSignature = display_str.parse().unwrap();
            assert_eq!(variant, parsed, "Failed round-trip for {:?}", variant);
        }
    }

    #[test]
    fn test_stamp_signature_display_outputs_literal() {
        // Verify Display produces the literal token, not the enum name
        assert_eq!(StampSignature::StampLower.to_string(), "stamp:");
        assert_eq!(StampSignature::StampUpper.to_string(), "STAMP:");
        assert_eq!(StampSignature::StampsLower.to_string(), "stamps:");
        assert_eq!(StampSignature::StampsUpper.to_string(), "STAMPS:");
    }

    #[test]
    fn test_stamp_signature_fromstr_literal_tokens() {
        // Test parsing literal tokens
        assert_eq!("stamp:".parse(), Ok(StampSignature::StampLower));
        assert_eq!("STAMP:".parse(), Ok(StampSignature::StampUpper));
        assert_eq!("stamps:".parse(), Ok(StampSignature::StampsLower));
        assert_eq!("STAMPS:".parse(), Ok(StampSignature::StampsUpper));
    }

    #[test]
    fn test_stamp_signature_fromstr_enum_names() {
        // Test parsing enum names (for backfills/fixtures tolerance)
        assert_eq!("StampLower".parse(), Ok(StampSignature::StampLower));
        assert_eq!("StampUpper".parse(), Ok(StampSignature::StampUpper));
        assert_eq!("StampsLower".parse(), Ok(StampSignature::StampsLower));
        assert_eq!("StampsUpper".parse(), Ok(StampSignature::StampsUpper));
    }

    #[test]
    fn test_stamp_signature_fromstr_invalid() {
        // Test that invalid strings return an error
        let result: Result<StampSignature, _> = "invalid".parse();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown stamp signature"));
    }

    #[test]
    fn test_signature_variant_survives_database_roundtrip() {
        // Test that signature variant survives serialization through the same
        // serde_json::json! code path used in production (stamps.rs)
        let variant = StampSignature::StampUpper;
        let signature_str = variant.to_string();

        // Use SAME code path as production (serde_json::json! macro)
        let meta = serde_json::json!({
            "transport_protocol": "Counterparty",
            "stamp_signature_variant": signature_str.clone(),
            "outputs": [],
            "total_outputs": 2,
            "concatenated_data_size": 1024,
            "stamp_signature_offset": 42,
            "has_dual_signature": true,
            "encoding_format": "Counterparty embedded"
        })
        .to_string();

        // Parse and extract (simulating database read)
        let parsed: serde_json::Value = serde_json::from_str(&meta).unwrap();
        let extracted = parsed["stamp_signature_variant"].as_str().unwrap();

        // Verify exact string match
        assert_eq!(extracted, "STAMP:");

        // Recover via FromStr (simulating analysis)
        let recovered: StampSignature = extracted.parse().unwrap();
        assert_eq!(variant, recovered);
    }

    #[test]
    fn test_signature_variant_roundtrip_all_variants() {
        // Test all variants survive the database roundtrip
        for variant in StampSignature::ALL {
            let signature_str = variant.to_string();

            let meta = serde_json::json!({
                "transport_protocol": "Pure Bitcoin Stamps",
                "stamp_signature_variant": signature_str,
                "outputs": [],
            })
            .to_string();

            let parsed: serde_json::Value = serde_json::from_str(&meta).unwrap();
            let extracted = parsed["stamp_signature_variant"].as_str().unwrap();
            let recovered: StampSignature = extracted.parse().unwrap();

            assert_eq!(
                variant, recovered,
                "Failed database roundtrip for {:?}",
                variant
            );
        }
    }

    #[test]
    fn test_detect_stamps_variant_src20() {
        use base64::{engine::general_purpose, Engine};
        // Create a valid SRC-20 JSON payload
        let json = r#"{"p":"src-20","op":"deploy","tick":"TEST","max":"1000"}"#;
        let base64_json = general_purpose::STANDARD.encode(json.as_bytes());
        let payload = format!("stamp:{}", base64_json);

        let variant = validation::detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::SRC20));
    }

    #[test]
    fn test_detect_stamps_variant_src721() {
        use base64::{engine::general_purpose, Engine};
        let json = r#"{"p":"src-721","op":"mint","tick":"NFTS"}"#;
        let base64_json = general_purpose::STANDARD.encode(json.as_bytes());
        let payload = format!("stamp:{}", base64_json);

        let variant = validation::detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::SRC721));
    }

    #[test]
    fn test_detect_stamps_variant_src101() {
        use base64::{engine::general_purpose, Engine};
        let json = r#"{"p":"src-101","op":"reg","name":"example"}"#;
        let base64_json = general_purpose::STANDARD.encode(json.as_bytes());
        let payload = format!("stamp:{}", base64_json);

        let variant = validation::detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::SRC101));
    }

    #[test]
    fn test_detect_stamps_variant_png_image() {
        use base64::{engine::general_purpose, Engine};
        // PNG magic bytes
        let png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let base64_png = general_purpose::STANDARD.encode(&png_data);
        let payload = format!("stamp:{}", base64_png);

        let variant = validation::detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::Classic));
    }

    #[test]
    fn test_detect_stamps_variant_png_image_with_data_uri() {
        // Real-world payloads sometimes carry data URI prefixes from Electrum-Counterparty exports
        let payload = b"stamp:data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACgAAAA4BAMAAAB9BqfFAAAAJ1BMVEVIZZcqRnYNERg8Qj4gJSEiLEojOFsAAAD7AQkeGx7///+SoYxUaWqIxi3EAAABTklEQVQ4y73PsU7DMBQF0FSiA6MHilg7lA8IEhmRcCR+wIq8MpQvQE8xYxrFaVkzpBuVoAM7/B7XcRrH1EJMvapk++jd1zaaB3I6XD6GEDFOO+Uj+JqIdr0tgF0o3+bb+cI+otkB63yN0yKz5xPqyiEDA/O2/XCIYAW9aK03Xw6RS9p/a20XsNmAij439MaW5tUjM1gB2QgvMqL3I2wyJSrFfBRCNCX7jTKAEqN1CN1kNDHHlUDfIQIHCg8RU5ejnTbTbnLiY3SOpSX2eDiVmOxuYxQS6AXYiADiv/8XQ3UZ3BlGeYyNDKBoQ3X5B55xh2nTfxHng/LU/CTeB+87VHjalKIe0B6YzJ5LvuIPHmZ7oD+5SjOlfESAVKJsMY7jG3OpFK144tBwfLumIsFlwASfRBWFjgt+Dwf2KbR+Lez1gKhqjYaHWABy6NhhID/iStgdKGHcpQAAAABJRU5ErkJggg==";
        let variant = validation::detect_stamps_variant(payload);
        assert_eq!(variant, Some(StampsVariant::Classic));
    }

    #[test]
    fn test_detect_stamps_variant_malformed_json() {
        use base64::{engine::general_purpose, Engine};
        // Malformed JSON (missing closing brace)
        let bad_json = r#"{"p":"src-20","op":"deploy""#;
        let base64_json = general_purpose::STANDARD.encode(bad_json.as_bytes());
        let payload = format!("stamp:{}", base64_json);

        let variant = validation::detect_stamps_variant(payload.as_bytes());
        // Malformed JSON is detected as Data (text/plain) since it's valid UTF-8
        assert_eq!(variant, Some(StampsVariant::Data));
    }

    #[test]
    fn test_detect_stamps_variant_unsupported_format() {
        use base64::{engine::general_purpose, Engine};
        // Random binary data that's not JSON or image
        let random_data = vec![0xFF, 0x00, 0xAB, 0xCD, 0xEF];
        let base64_data = general_purpose::STANDARD.encode(&random_data);
        let payload = format!("stamp:{}", base64_data);

        let variant = validation::detect_stamps_variant(payload.as_bytes());
        // Binary data is detected as Data (application/octet-stream)
        assert_eq!(variant, Some(StampsVariant::Data));
    }

    #[test]
    fn test_detect_stamps_variant_with_bom() {
        use base64::{engine::general_purpose, Engine};
        // JSON with UTF-8 BOM
        let json = r#"{"p":"src-20","op":"mint","tick":"TEST","amt":"100"}"#;
        let mut json_with_bom = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        json_with_bom.extend_from_slice(json.as_bytes());

        let base64_json = general_purpose::STANDARD.encode(&json_with_bom);
        let payload = format!("stamp:{}", base64_json);

        let variant = validation::detect_stamps_variant(payload.as_bytes());
        assert_eq!(variant, Some(StampsVariant::SRC20));
    }
}
