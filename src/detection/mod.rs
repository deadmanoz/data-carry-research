//! Shared protocol detection logic
//!
//! This module contains reusable protocol detection code that can be used by both
//! Stage 3 (classification from database) and Stage 4 (decoding from RPC).
//!
//! The detection logic is database-agnostic and operates purely on TransactionOutput data.

pub mod likely_data_storage;

// Re-export for convenience
pub use likely_data_storage::{
    detect as detect_likely_data_storage, DetectionResult as LikelyDataStorageDetectionResult,
    LikelyDataStorageVariant,
};
