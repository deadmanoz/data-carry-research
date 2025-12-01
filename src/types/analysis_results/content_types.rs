//! Content type (MIME type) analysis types

use serde::{Deserialize, Serialize};

/// Content type (MIME type) analysis report
///
/// Provides comprehensive breakdown of content types across all classified unspent P2MS outputs.
/// Distinguishes between data-carrying outputs (with content types) and valid None cases
/// (LikelyDataStorage, LikelyLegitimateMultisig, StampsUnknown, OmniFailedDeobfuscation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeAnalysisReport {
    pub total_outputs: usize,
    pub outputs_with_content_type: usize,
    pub outputs_without_content_type: usize,
    pub content_type_percentage: f64,
    pub content_type_breakdown: Vec<ContentTypeStats>,
    pub category_breakdown: Vec<ContentTypeCategoryStats>,
    pub protocol_breakdown: Vec<ContentTypeProtocolStats>,
    pub valid_none_stats: ValidNoneStats,
    pub invalid_none_stats: Vec<ContentTypeProtocolStats>,
}

/// Statistics for a specific MIME type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeStats {
    pub mime_type: String,
    pub count: usize,
    pub percentage: f64,
}

/// MIME category statistics (image/*, text/*, application/*)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeCategoryStats {
    pub category: String,
    pub count: usize,
    pub percentage: f64,
    pub specific_types: Vec<ContentTypeStats>,
}

/// Protocol-specific content type statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeProtocolStats {
    pub protocol: String,
    pub total_outputs: usize,
    pub with_content_type: usize,
    pub without_content_type: usize,
    pub coverage_percentage: f64,
    pub content_types: Vec<ContentTypeStats>,
}

/// Statistics for valid None cases (architecturally correct)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidNoneStats {
    pub total_valid_none: usize,
    pub likely_data_storage: usize,
    pub likely_legitimate_multisig: usize,
    pub stamps_unknown: usize,
    pub omni_failed_deobfuscation: usize,
}
