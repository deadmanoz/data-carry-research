//! Shared helpers used across multiple pipeline stages.
//!
//! This module contains pure, decoder-agnostic utility functions that are shared
//! between Stage 3 (classification) and Stage 4 (decoding) to eliminate duplication.

pub mod base64_helpers;
pub mod datastorage_helpers;
pub mod multisig_patterns;
pub mod pubkey_extraction;
pub mod signature_detection;

// Re-export commonly used types for convenience
pub use base64_helpers::is_base64_data;
pub use multisig_patterns::MultisigPatternMatcher;
pub use pubkey_extraction::PubkeyExtractor;
pub use signature_detection::SignatureDetector;
