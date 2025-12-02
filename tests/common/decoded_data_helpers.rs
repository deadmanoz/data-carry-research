//! Assertion Helpers for DecodedData Variants
//!
//! This module provides helper functions to unwrap specific DecodedData variants
//! in tests, eliminating the need for exhaustive match arms in every test.
//!
//! # Example
//! ```rust,ignore
//! use crate::common::decoded_data_helpers::unwrap_stamps_image;
//!
//! let result = decoder.decode_txid(txid).await?;
//! let image = unwrap_stamps_image(result);
//! assert_eq!(image.txid, txid);
//! ```

use data_carry_research::decoder::{
    BitcoinStampsData, ChancecoinData, CounterpartyData, DataStorageData, DecodedData,
    LikelyDataStorageData, OmniData, PPkData,
};
use data_carry_research::decoder::{
    DecodedCompressed, DecodedDocument, DecodedGenericData, DecodedHtml, DecodedImage, DecodedJson,
};

/// Helper to format DecodedData variant name for error messages
fn variant_name(data: &Option<DecodedData>) -> &'static str {
    match data {
        None => "None",
        Some(DecodedData::BitcoinStamps { data }) => match data {
            BitcoinStampsData::Image(_) => "BitcoinStamps::Image",
            BitcoinStampsData::Document(_) => "BitcoinStamps::Document",
            BitcoinStampsData::Json(_) => "BitcoinStamps::Json",
            BitcoinStampsData::Html(_) => "BitcoinStamps::Html",
            BitcoinStampsData::Compressed(_) => "BitcoinStamps::Compressed",
            BitcoinStampsData::Data(_) => "BitcoinStamps::Data",
        },
        Some(DecodedData::Counterparty { .. }) => "Counterparty",
        Some(DecodedData::Omni { .. }) => "Omni",
        Some(DecodedData::Chancecoin { .. }) => "Chancecoin",
        Some(DecodedData::PPk { .. }) => "PPk",
        Some(DecodedData::DataStorage(_)) => "DataStorage",
        Some(DecodedData::LikelyDataStorage(_)) => "LikelyDataStorage",
    }
}

// =============================================================================
// BITCOIN STAMPS HELPERS
// =============================================================================

/// Unwrap a BitcoinStamps::Image variant, panicking with a clear message if wrong type
pub fn unwrap_stamps_image(result: Option<DecodedData>) -> DecodedImage {
    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Image(img),
        }) => img,
        other => panic!(
            "Expected BitcoinStamps::Image, got {}",
            variant_name(&other)
        ),
    }
}

/// Unwrap a BitcoinStamps::Json variant, panicking with a clear message if wrong type
pub fn unwrap_stamps_json(result: Option<DecodedData>) -> DecodedJson {
    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Json(json),
        }) => json,
        other => panic!("Expected BitcoinStamps::Json, got {}", variant_name(&other)),
    }
}

/// Unwrap a BitcoinStamps::Html variant, panicking with a clear message if wrong type
pub fn unwrap_stamps_html(result: Option<DecodedData>) -> DecodedHtml {
    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Html(html),
        }) => html,
        other => panic!("Expected BitcoinStamps::Html, got {}", variant_name(&other)),
    }
}

/// Unwrap a BitcoinStamps::Document variant, panicking with a clear message if wrong type
pub fn unwrap_stamps_document(result: Option<DecodedData>) -> DecodedDocument {
    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Document(doc),
        }) => doc,
        other => panic!(
            "Expected BitcoinStamps::Document, got {}",
            variant_name(&other)
        ),
    }
}

/// Unwrap a BitcoinStamps::Compressed variant, panicking with a clear message if wrong type
pub fn unwrap_stamps_compressed(result: Option<DecodedData>) -> DecodedCompressed {
    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Compressed(comp),
        }) => comp,
        other => panic!(
            "Expected BitcoinStamps::Compressed, got {}",
            variant_name(&other)
        ),
    }
}

/// Unwrap a BitcoinStamps::Data (generic) variant, panicking with a clear message if wrong type
pub fn unwrap_stamps_data(result: Option<DecodedData>) -> DecodedGenericData {
    match result {
        Some(DecodedData::BitcoinStamps {
            data: BitcoinStampsData::Data(data),
        }) => data,
        other => panic!("Expected BitcoinStamps::Data, got {}", variant_name(&other)),
    }
}

/// Unwrap any BitcoinStamps variant, panicking with a clear message if wrong type
pub fn unwrap_stamps(result: Option<DecodedData>) -> BitcoinStampsData {
    match result {
        Some(DecodedData::BitcoinStamps { data }) => data,
        other => panic!("Expected BitcoinStamps, got {}", variant_name(&other)),
    }
}

/// Get the txid from any BitcoinStampsData variant
pub fn stamps_txid(data: &BitcoinStampsData) -> &str {
    match data {
        BitcoinStampsData::Image(img) => &img.txid,
        BitcoinStampsData::Document(doc) => &doc.txid,
        BitcoinStampsData::Json(json) => &json.txid,
        BitcoinStampsData::Html(html) => &html.txid,
        BitcoinStampsData::Compressed(comp) => &comp.txid,
        BitcoinStampsData::Data(data) => &data.txid,
    }
}

/// Get the file_path from any BitcoinStampsData variant
pub fn stamps_file_path(data: &BitcoinStampsData) -> &std::path::Path {
    match data {
        BitcoinStampsData::Image(img) => &img.file_path,
        BitcoinStampsData::Document(doc) => &doc.file_path,
        BitcoinStampsData::Json(json) => &json.file_path,
        BitcoinStampsData::Html(html) => &html.file_path,
        BitcoinStampsData::Compressed(comp) => &comp.file_path,
        BitcoinStampsData::Data(data) => &data.file_path,
    }
}

/// Get the expected subdirectory name for a BitcoinStampsData variant
pub fn stamps_subdir(data: &BitcoinStampsData) -> &'static str {
    match data {
        BitcoinStampsData::Image(_) => "images",
        BitcoinStampsData::Document(_) => "documents",
        BitcoinStampsData::Json(_) => "json",
        BitcoinStampsData::Html(_) => "html",
        BitcoinStampsData::Compressed(_) => "compressed",
        BitcoinStampsData::Data(_) => "data",
    }
}

// =============================================================================
// COUNTERPARTY HELPERS
// =============================================================================

/// Unwrap a Counterparty variant, panicking with a clear message if wrong type
pub fn unwrap_counterparty(result: Option<DecodedData>) -> CounterpartyData {
    match result {
        Some(DecodedData::Counterparty { data }) => data,
        other => panic!("Expected Counterparty, got {}", variant_name(&other)),
    }
}

// =============================================================================
// OMNI LAYER HELPERS
// =============================================================================

/// Unwrap an Omni variant, panicking with a clear message if wrong type
pub fn unwrap_omni(result: Option<DecodedData>) -> OmniData {
    match result {
        Some(DecodedData::Omni { data }) => data,
        other => panic!("Expected Omni, got {}", variant_name(&other)),
    }
}

// =============================================================================
// CHANCECOIN HELPERS
// =============================================================================

/// Unwrap a Chancecoin variant, panicking with a clear message if wrong type
pub fn unwrap_chancecoin(result: Option<DecodedData>) -> ChancecoinData {
    match result {
        Some(DecodedData::Chancecoin { data }) => data,
        other => panic!("Expected Chancecoin, got {}", variant_name(&other)),
    }
}

// =============================================================================
// PPK HELPERS
// =============================================================================

/// Unwrap a PPk variant, panicking with a clear message if wrong type
pub fn unwrap_ppk(result: Option<DecodedData>) -> PPkData {
    match result {
        Some(DecodedData::PPk { data }) => data,
        other => panic!("Expected PPk, got {}", variant_name(&other)),
    }
}

// =============================================================================
// DATASTORAGE HELPERS
// =============================================================================

/// Unwrap a DataStorage variant, panicking with a clear message if wrong type
pub fn unwrap_datastorage(result: Option<DecodedData>) -> DataStorageData {
    match result {
        Some(DecodedData::DataStorage(data)) => data,
        other => panic!("Expected DataStorage, got {}", variant_name(&other)),
    }
}

/// Unwrap a LikelyDataStorage variant, panicking with a clear message if wrong type
pub fn unwrap_likely_datastorage(result: Option<DecodedData>) -> LikelyDataStorageData {
    match result {
        Some(DecodedData::LikelyDataStorage(data)) => data,
        other => panic!("Expected LikelyDataStorage, got {}", variant_name(&other)),
    }
}

// =============================================================================
// ASSERTION HELPERS
// =============================================================================

/// Assert that the result is None
pub fn assert_none(result: Option<DecodedData>) {
    if let Some(_) = result {
        panic!("Expected None, got {}", variant_name(&result));
    }
}

/// Assert that the result is Some (any variant)
pub fn assert_some(result: &Option<DecodedData>) {
    if result.is_none() {
        panic!("Expected Some(DecodedData), got None");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_name_none() {
        assert_eq!(variant_name(&None), "None");
    }

    #[test]
    #[should_panic(expected = "Expected BitcoinStamps::Image, got None")]
    fn test_unwrap_stamps_image_fails_on_none() {
        unwrap_stamps_image(None);
    }

    #[test]
    #[should_panic(expected = "Expected Counterparty, got None")]
    fn test_unwrap_counterparty_fails_on_none() {
        unwrap_counterparty(None);
    }

    #[test]
    #[should_panic(expected = "Expected Omni, got None")]
    fn test_unwrap_omni_fails_on_none() {
        unwrap_omni(None);
    }

    #[test]
    #[should_panic(expected = "Expected DataStorage, got None")]
    fn test_unwrap_datastorage_fails_on_none() {
        unwrap_datastorage(None);
    }
}
