//! Data size analysis types

use crate::types::ProtocolType;
use serde::{Deserialize, Serialize};

/// Protocol-level data size report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDataSizeReport {
    pub total_bytes: u64,
    pub total_outputs: usize,
    pub total_transactions: usize,
    pub protocols: Vec<ProtocolDataSize>,
}

/// Per-protocol data size statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDataSize {
    pub protocol: ProtocolType,
    pub variant: Option<String>,
    pub output_count: usize,
    pub transaction_count: usize,
    pub total_bytes: u64,
    pub average_bytes: f64,
    pub min_bytes: u64,
    pub max_bytes: u64,
    pub percentage_of_total: f64,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
    pub spendable_percentage: f64,
}

/// Spendability-focused data size report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendabilityDataSizeReport {
    pub overall: SpendabilityDataMetrics,
    pub by_protocol: Vec<ProtocolSpendabilityData>,
    pub by_reason: Vec<ReasonSpendabilityData>,
}

/// Overall spendability data metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendabilityDataMetrics {
    pub total_bytes: u64,
    pub total_transactions: usize,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
    pub spendable_percentage: f64,
    pub spendable_output_count: usize,
    pub unspendable_output_count: usize,
}

/// Per-protocol spendability data breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSpendabilityData {
    pub protocol: ProtocolType,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
    pub spendable_output_count: usize,
    pub unspendable_output_count: usize,
}

/// Per-reason spendability data statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonSpendabilityData {
    pub reason: String,
    pub output_count: usize,
    pub total_bytes: u64,
    pub percentage_of_total: f64,
}

/// Content type with spendability cross-analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeSpendabilityReport {
    pub total_bytes: u64,
    pub total_transactions: usize,
    pub categories: Vec<CategorySpendabilityData>,
}

/// Category-level spendability data aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySpendabilityData {
    pub category: String,
    pub content_types: Vec<ContentTypeData>,
    pub category_totals: CategoryDataMetrics,
}

/// Per-content-type data with spendability metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeData {
    pub mime_type: String,
    pub extension: String,
    pub transaction_count: usize,
    pub output_count: usize,
    pub total_bytes: u64,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
    pub spendable_percentage: f64,
}

/// Category-level aggregated metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryDataMetrics {
    pub transaction_count: usize,
    pub output_count: usize,
    pub total_bytes: u64,
    pub spendable_bytes: u64,
    pub unspendable_bytes: u64,
}

/// Comprehensive data size report combining all dimensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveDataSizeReport {
    pub overall_summary: OverallDataSummary,
    pub protocol_breakdown: ProtocolDataSizeReport,
    pub spendability_breakdown: SpendabilityDataSizeReport,
    pub content_type_breakdown: ContentTypeSpendabilityReport,
}

/// Overall data size summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallDataSummary {
    pub total_p2ms_bytes: u64,
    pub total_outputs: usize,
    pub total_transactions: usize,
    pub average_bytes_per_output: f64,
    pub spendable_percentage: f64,
}
