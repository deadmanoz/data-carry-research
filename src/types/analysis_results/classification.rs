//! Protocol classification analysis types

use crate::types::ProtocolType;
use serde::{Deserialize, Serialize};

/// Protocol classification statistics report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClassificationStatsReport {
    pub total_classified: usize,
    pub protocol_breakdown: ProtocolBreakdown,
    pub signature_detection_rates: SignatureDetectionStats,
    pub sample_classifications: Vec<ClassificationSample>,
}

/// Breakdown of classifications by protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolBreakdown {
    pub bitcoin_stamps: ProtocolStats,
    pub counterparty: ProtocolStats,
    pub ascii_identifier_protocols: ProtocolStats,
    pub omni_layer: ProtocolStats,
    pub chancecoin: ProtocolStats,
    pub ppk: ProtocolStats,
    pub opreturn_signalled: ProtocolStats,
    pub data_storage: ProtocolStats,
    pub likely_data_storage: ProtocolStats,
    pub likely_legitimate: ProtocolStats,
    pub unknown: ProtocolStats,
}

/// Statistics for a specific protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtocolStats {
    pub count: usize,
    pub percentage: f64,
    pub variants: Vec<VariantStats>,
}

/// Statistics for protocol variants
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VariantStats {
    pub variant: String,
    pub count: usize,
    pub classification_method: String,
}

/// Signature detection statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignatureDetectionStats {
    pub definitive_signatures: usize,
    pub signature_percentage: f64,
    pub method_breakdown: Vec<MethodStats>,
}

/// Statistics for classification methods
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MethodStats {
    pub method: String,
    pub count: usize,
    pub percentage: f64,
}

/// Sample classification result
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClassificationSample {
    pub protocol: ProtocolType,
    pub variant: String,
    pub classification_method: String,
    pub count: usize,
}
