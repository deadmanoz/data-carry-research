//! Bitcoin Stamps validation and processing module
//!
//! Helper functions for Bitcoin Stamps protocol detection and validation.

pub mod detection;
pub mod extraction;
pub mod helpers;
pub mod processing;

// Re-export commonly used items at the validation level for convenience
pub use detection::{
    detect_compression_format, detect_content_type_from_payload, detect_stamps_variant,
    detect_stamps_variant_with_content,
};
pub use extraction::{extract_stamps_payload, find_stamp_signature};
pub use helpers::{
    check_zlib_at_offsets, extract_data_chunk, is_stamps_burn_key, is_stamps_p2ms, BASE64_LENIENT,
};
pub use processing::{
    process_counterparty_embedded_stamps, process_multioutput_stamps, process_pure_stamps,
    StampsProcessingResult,
};
