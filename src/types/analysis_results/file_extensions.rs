//! File extension analysis types

use serde::{Deserialize, Serialize};

/// File extension analysis report summarizing stored payload formats
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FileExtensionReport {
    pub total_transactions: usize,
    pub total_outputs: usize,
    pub total_bytes: u64,
    pub categories: Vec<CategoryBreakdown>,
}

/// Aggregated statistics for a single content category (Images, Documents, ...)
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CategoryBreakdown {
    pub category: String,
    pub extensions: Vec<ExtensionStats>,
    pub category_totals: CategoryTotals,
}

/// Statistics for a specific file extension within a category
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ExtensionStats {
    pub extension: String,
    pub transaction_count: usize,
    pub output_count: usize,
    pub total_bytes: u64,
    pub transaction_percentage: f64,
    pub output_percentage: f64,
    pub byte_percentage: f64,
}

/// Totals for a content category used for percentage calculations
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CategoryTotals {
    pub transaction_count: usize,
    pub output_count: usize,
    pub total_bytes: u64,
    pub transaction_percentage: f64,
    pub output_percentage: f64,
    pub byte_percentage: f64,
}
