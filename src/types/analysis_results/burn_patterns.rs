//! Burn pattern analysis types

use serde::{Deserialize, Serialize};

/// Comprehensive burn pattern analysis results
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BurnPatternAnalysis {
    pub total_patterns: usize,
    pub pattern_breakdown: Vec<PatternTypeStats>,
    pub sample_patterns: Vec<BurnPatternSample>,
}

/// Statistics for a specific burn pattern type
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PatternTypeStats {
    pub pattern_type: String,
    pub count: usize,
    pub percentage: f64,
}

/// Sample burn pattern with transaction context
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BurnPatternSample {
    pub txid: String,
    pub pattern_type: String,
    pub pattern_data: String,
    pub vout: u32,
    pub pubkey_index: usize,
}
