#![allow(dead_code)]

use super::image_formats::ImageFormat;
use std::fs;
use std::path::{Path, PathBuf};

/// Result type for output operations
pub type OutputResult<T> = Result<T, OutputError>;

/// Output-specific error types
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid file path: {0}")]
    InvalidPath(String),
}

// Re-export JsonType from types::stamps for consistency with Stage 3
pub use crate::types::stamps::JsonType;

impl JsonType {
    /// Get a human-readable description of the JSON type
    pub fn description(&self) -> &'static str {
        match self {
            JsonType::SRC20 => "SRC-20 token",
            JsonType::SRC101 => "SRC-101 domain",
            JsonType::SRC721 => "SRC-721 NFT",
            JsonType::SRC721r => "SRC-721r recursive",
            JsonType::Generic => "Generic JSON",
        }
    }
}

/// Unified output manager for all decoded Bitcoin Stamps data types
///
/// Handles file output for images, JSON, and future file formats (PDF, video, etc.)
/// with proper directory structure and naming conventions.
pub struct OutputManager {
    base_dir: PathBuf,
}

impl OutputManager {
    /// Create a new OutputManager with the specified base directory
    pub fn new(base_dir: PathBuf) -> OutputResult<Self> {
        Ok(Self { base_dir })
    }

    /// Get the output directory path
    pub fn output_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    /// Write image data to the bitcoin_stamps/images subdirectory
    /// Creates: <base_dir>/bitcoin_stamps/images/<txid>.<ext>
    pub fn write_image(
        &self,
        txid: &str,
        image_data: &[u8],
        format: ImageFormat,
    ) -> OutputResult<PathBuf> {
        let image_dir = self.base_dir.join("bitcoin_stamps").join("images");
        self.ensure_directory_exists(&image_dir)?;

        let filename = format!("{}.{}", txid, format.extension());
        let filepath = image_dir.join(filename);

        fs::write(&filepath, image_data)?;
        Ok(filepath)
    }

    /// Write JSON data to the bitcoin_stamps/json subdirectory
    /// Creates: <base_dir>/bitcoin_stamps/json/<txid>.json
    pub fn write_json(
        &self,
        txid: &str,
        json_data: &[u8],
        _json_type: JsonType,
    ) -> OutputResult<PathBuf> {
        let json_dir = self.base_dir.join("bitcoin_stamps").join("json");
        self.ensure_directory_exists(&json_dir)?;

        let filename = format!("{}.json", txid);
        let filepath = json_dir.join(filename);

        fs::write(&filepath, json_data)?;
        Ok(filepath)
    }

    /// Write HTML document to the bitcoin_stamps/html subdirectory
    /// Creates: <base_dir>/bitcoin_stamps/html/<txid>.html
    pub fn write_html(&self, txid: &str, data: &[u8]) -> OutputResult<PathBuf> {
        let html_dir = self.base_dir.join("bitcoin_stamps").join("html");
        self.ensure_directory_exists(&html_dir)?;

        let filename = format!("{}.html", txid);
        let filepath = html_dir.join(filename);

        fs::write(&filepath, data)?;
        Ok(filepath)
    }

    /// Write compressed data to the bitcoin_stamps/compressed subdirectory
    /// Creates: <base_dir>/bitcoin_stamps/compressed/<txid>.<ext>
    pub fn write_compressed(
        &self,
        txid: &str,
        data: &[u8],
        content_type: &str,
    ) -> OutputResult<PathBuf> {
        let compressed_dir = self.base_dir.join("bitcoin_stamps").join("compressed");
        self.ensure_directory_exists(&compressed_dir)?;

        let ext = match content_type {
            "application/gzip" => "gz",
            "application/zlib" => "zlib",
            _ => "compressed",
        };
        let filename = format!("{}.{}", txid, ext);
        let filepath = compressed_dir.join(filename);

        fs::write(&filepath, data)?;
        Ok(filepath)
    }

    /// Write generic data to the bitcoin_stamps/data subdirectory
    /// Creates: <base_dir>/bitcoin_stamps/data/<txid>.<ext>
    pub fn write_data(
        &self,
        txid: &str,
        data: &[u8],
        content_type: Option<&str>,
    ) -> OutputResult<PathBuf> {
        let data_dir = self.base_dir.join("bitcoin_stamps").join("data");
        self.ensure_directory_exists(&data_dir)?;

        let ext = match content_type {
            Some("application/json") => "json",
            Some("application/xml") => "xml",
            Some("text/plain") => "txt",
            _ => "dat",
        };
        let filename = format!("{}.{}", txid, ext);
        let filepath = data_dir.join(filename);

        fs::write(&filepath, data)?;
        Ok(filepath)
    }

    /// Write Counterparty data to the counterparty subdirectory
    /// Creates: <base_dir>/counterparty/<txid>.json
    pub fn write_counterparty_data(
        &self,
        txid: &str,
        counterparty_data: &[u8],
    ) -> OutputResult<PathBuf> {
        let counterparty_dir = self.base_dir.join("counterparty");
        self.ensure_directory_exists(&counterparty_dir)?;

        let filename = format!("{}.json", txid);
        let filepath = counterparty_dir.join(filename);

        fs::write(&filepath, counterparty_data)?;
        Ok(filepath)
    }

    /// Write structured Counterparty JSON data to the counterparty directory
    /// Creates: <base_dir>/counterparty/<txid>.json
    pub fn write_counterparty_json(
        &self,
        txid: &str,
        message_type: &crate::types::counterparty::CounterpartyMessageType,
        raw_payload: &[u8],
        parsed_message: &Option<serde_json::Value>,
    ) -> OutputResult<PathBuf> {
        use serde_json::json;

        // Use counterparty subdirectory in base_dir
        let counterparty_dir = self.base_dir.join("counterparty");
        self.ensure_directory_exists(&counterparty_dir)?;

        // Create comprehensive JSON structure
        let json_data = json!({
            "txid": txid,
            "protocol": "Counterparty",
            "message_type": format!("{:?}", message_type),
            "message_type_id": *message_type as u32,
            "raw_payload_hex": hex::encode(raw_payload),
            "raw_payload_size": raw_payload.len(),
            "parsed_data": parsed_message,
            "decode_timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let filename = format!("{}.json", txid);
        let filepath = counterparty_dir.join(filename);

        let json_string = serde_json::to_string_pretty(&json_data)
            .map_err(|e| OutputError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        fs::write(&filepath, json_string)?;
        Ok(filepath)
    }

    /// Check if an image file already exists
    pub fn image_file_exists(&self, txid: &str, format: ImageFormat) -> bool {
        let image_dir = self.base_dir.join("bitcoin_stamps").join("images");
        let filename = format!("{}.{}", txid, format.extension());
        let filepath = image_dir.join(filename);
        filepath.exists()
    }

    /// Check if a JSON file already exists
    pub fn json_file_exists(&self, txid: &str) -> bool {
        let json_dir = self.base_dir.join("bitcoin_stamps").join("json");
        let filename = format!("{}.json", txid);
        let filepath = json_dir.join(filename);
        filepath.exists()
    }

    /// Write Omni Layer data to the omni subdirectory
    /// Creates: <base_dir>/omni/<txid>.json
    pub fn write_omni_json(
        &self,
        txid: &str,
        message_type: &crate::types::omni::OmniMessageType,
        sender_address: &str,
        deobfuscated_payload: &[u8],
        packet_count: u8,
        parsed_data: Option<serde_json::Value>,
    ) -> OutputResult<PathBuf> {
        use serde_json::json;

        // Create omni subdirectory in base_dir
        let omni_dir = self.base_dir.join("omni");
        self.ensure_directory_exists(&omni_dir)?;

        // Create comprehensive JSON structure
        let mut json_data = json!({
            "txid": txid,
            "protocol": "Omni Layer",
            "message_type": format!("{:?}", message_type),
            "message_type_id": *message_type as u32,
            "sender_address": sender_address,
            "deobfuscated_payload_hex": hex::encode(deobfuscated_payload),
            "deobfuscated_payload_size": deobfuscated_payload.len(),
            "packet_count": packet_count,
            "decode_timestamp": chrono::Utc::now().to_rfc3339(),
        });

        // Add parsed data if available
        if let Some(parsed) = parsed_data {
            json_data["parsed"] = parsed;
        }

        let filename = format!("{}.json", txid);
        let filepath = omni_dir.join(filename);

        let json_string = serde_json::to_string_pretty(&json_data)
            .map_err(|e| OutputError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        fs::write(&filepath, json_string)?;
        Ok(filepath)
    }

    /// Get the base output directory path
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Create Chancecoin output file
    /// Creates: <base_dir>/chancecoin/<txid>.json
    pub fn create_chancecoin_output(
        &self,
        txid: &str,
        message: &crate::types::chancecoin::ChancecoinMessage,
    ) -> OutputResult<PathBuf> {
        use serde_json::json;

        let chancecoin_dir = self.base_dir.join("chancecoin");
        self.ensure_directory_exists(&chancecoin_dir)?;

        // Create structured JSON output
        let output_json = json!({
            "txid": txid,
            "protocol": "Chancecoin",
            "message_type": message.message_type.description(),
            "data": {
                "hex": hex::encode(&message.data),
                "length": message.data.len(),
            },
            "raw_data": {
                "hex": hex::encode(&message.raw_data),
                "length": message.raw_data.len(),
            },
            "summary": message.summary(),
        });

        let filename = format!("{}.json", txid);
        let filepath = chancecoin_dir.join(filename);

        let json_string = serde_json::to_string_pretty(&output_json)
            .map_err(|e| OutputError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        fs::write(&filepath, json_string)?;

        Ok(filepath)
    }

    /// Ensure a directory exists, creating it if necessary
    fn ensure_directory_exists(&self, dir: &Path) -> OutputResult<()> {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }
}

// Re-export classify_json_data from types::stamps for consistency with Stage 3
pub use crate::types::stamps::classify_json_data;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_classify_json_data() {
        // Test SRC-20 deploy
        let src20_deploy = br#"{"p":"src-20","op":"deploy","tick":"TEST","max":"1000"}"#;
        assert_eq!(classify_json_data(src20_deploy), JsonType::SRC20);

        // Test SRC-101 domain
        let src101 = br#"{"p":"src-101","op":"reg","name":"example"}"#;
        assert_eq!(classify_json_data(src101), JsonType::SRC101);

        // Test SRC-721 NFT
        let src721 = br#"{"p":"src-721","op":"mint","tick":"NFTS"}"#;
        assert_eq!(classify_json_data(src721), JsonType::SRC721);

        // Test SRC-721r recursive
        let src721r = br#"{"p":"src-721r","op":"mint","tick":"RECURSIVE"}"#;
        assert_eq!(classify_json_data(src721r), JsonType::SRC721r);

        // Test generic JSON
        let generic = br#"{"name":"test","value":123}"#;
        assert_eq!(classify_json_data(generic), JsonType::Generic);

        // Test malformed but recognizable
        let malformed_src20 = br#"{"p":"src-20","op":"deploy"}"#;
        assert_eq!(classify_json_data(malformed_src20), JsonType::SRC20);
    }

    #[test]
    fn test_classify_json_data_case_insensitive() {
        // Test uppercase SRC-20
        let uppercase_src20 = br#"{"p":"SRC-20","op":"TRANSFER","tick":"LUFFY","amt":100000}"#;
        assert_eq!(classify_json_data(uppercase_src20), JsonType::SRC20);

        // Test mixed case SRC-721
        let mixed_src721 = br#"{"p":"Src-721","op":"mint","symbol":"TEST"}"#;
        assert_eq!(classify_json_data(mixed_src721), JsonType::SRC721);

        // Test uppercase SRC-721r
        let uppercase_src721r = br#"{"p":"SRC-721R","op":"deploy","name":"Test"}"#;
        assert_eq!(classify_json_data(uppercase_src721r), JsonType::SRC721r);

        // Test uppercase SRC-101
        let uppercase_src101 = br#"{"p":"SRC-101","op":"reg","name":"example"}"#;
        assert_eq!(classify_json_data(uppercase_src101), JsonType::SRC101);
    }

    #[test]
    fn test_json_type_description() {
        assert_eq!(JsonType::SRC20.description(), "SRC-20 token");
        assert_eq!(JsonType::SRC101.description(), "SRC-101 domain");
        assert_eq!(JsonType::SRC721.description(), "SRC-721 NFT");
        assert_eq!(JsonType::SRC721r.description(), "SRC-721r recursive");
        assert_eq!(JsonType::Generic.description(), "Generic JSON");
    }

    #[test]
    fn test_output_manager_image_write() {
        let temp_dir = TempDir::new().unwrap();
        let manager = OutputManager::new(temp_dir.path().to_path_buf()).unwrap();

        let test_data = b"fake image data";
        let result = manager.write_image("test123", test_data, ImageFormat::Png);

        assert!(result.is_ok());
        let filepath = result.unwrap();
        assert!(filepath.exists());
        assert_eq!(filepath.file_name().unwrap(), "test123.png");

        let written_data = std::fs::read(&filepath).unwrap();
        assert_eq!(written_data, test_data);
    }

    #[test]
    fn test_output_manager_json_write() {
        let temp_dir = TempDir::new().unwrap();
        let manager = OutputManager::new(temp_dir.path().to_path_buf()).unwrap();

        let test_json = br#"{"p":"src-20","op":"deploy"}"#;
        let result = manager.write_json("test456", test_json, JsonType::SRC20);

        assert!(result.is_ok());
        let filepath = result.unwrap();
        assert!(filepath.exists());
        assert_eq!(filepath.file_name().unwrap(), "test456.json");

        let written_data = std::fs::read(&filepath).unwrap();
        assert_eq!(written_data, test_json);
    }

    #[test]
    fn test_file_exists_checks() {
        let temp_dir = TempDir::new().unwrap();
        let manager = OutputManager::new(temp_dir.path().to_path_buf()).unwrap();

        // Test non-existent files
        assert!(!manager.image_file_exists("nonexistent", ImageFormat::Png));
        assert!(!manager.json_file_exists("nonexistent"));

        // Create files and test existence
        manager
            .write_image("exists", b"data", ImageFormat::Png)
            .unwrap();
        manager
            .write_json("exists", b"{}", JsonType::Generic)
            .unwrap();

        assert!(manager.image_file_exists("exists", ImageFormat::Png));
        assert!(manager.json_file_exists("exists"));
    }
}
