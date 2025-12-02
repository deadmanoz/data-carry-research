//! Signature analysis types

use super::classification::MethodStats;
use crate::types::ProtocolType;
use serde::{Deserialize, Serialize};

/// Signature analysis comprehensive report
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignatureAnalysisReport {
    pub classification_methods: Vec<MethodStats>,
    pub burn_pattern_analysis: BurnPatternCorrelation,
}

/// Correlation between burn patterns and protocol classifications
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BurnPatternCorrelation {
    pub correlations: Vec<PatternProtocolCorrelation>,
}

/// Correlation data between pattern and protocol
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PatternProtocolCorrelation {
    pub protocol: ProtocolType,
    pub burn_patterns_count: usize,
    pub transactions: usize,
}
