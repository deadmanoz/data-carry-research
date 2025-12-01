//! Common distribution types for analysis
//!
//! Generic histogram bucket types used across multiple analysis modules.

use crate::utils::math::{safe_percentage, safe_percentage_u64};
use serde::{Deserialize, Serialize};

/// Generic histogram bucket for distribution analysis
///
/// Bucket semantics: [range_min, range_max) - inclusive min, exclusive max.
/// Last bucket is open-ended: [range_min, ∞) when range_max == T::MAX.
///
/// The `value` field always represents satoshis:
/// - For ValueBucket: total output value in satoshis
/// - For TxSizeBucket: total transaction fees in satoshis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionBucket<T: Copy> {
    /// Lower bound of bucket range (inclusive)
    pub range_min: T,
    /// Upper bound of bucket range (exclusive, except last bucket)
    pub range_max: T,
    /// Number of items in this bucket
    pub count: usize,
    /// Aggregate satoshis (output values for ValueBucket, fees for TxSizeBucket)
    pub value: u64,
    /// Percentage of total count
    pub pct_count: f64,
    /// Percentage of total value
    pub pct_value: f64,
}

impl<T: Copy> DistributionBucket<T> {
    /// Create a new bucket with computed percentages
    ///
    /// Percentages are computed using `safe_percentage*` which returns 0.0
    /// when totals are zero (no NaN or division-by-zero).
    pub fn new(
        range_min: T,
        range_max: T,
        count: usize,
        value: u64,
        total_count: usize,
        total_value: u64,
    ) -> Self {
        Self {
            range_min,
            range_max,
            count,
            value,
            pct_count: safe_percentage(count, total_count),
            pct_value: safe_percentage_u64(value, total_value),
        }
    }

    /// Create a zeroed bucket for streaming aggregation
    ///
    /// Use when accumulating counts/values before totals are known.
    /// Call `compute_percentages()` after aggregation is complete.
    pub fn new_zeroed(range_min: T, range_max: T) -> Self {
        Self {
            range_min,
            range_max,
            count: 0,
            value: 0,
            pct_count: 0.0,
            pct_value: 0.0,
        }
    }

    /// Compute percentages after streaming aggregation
    pub fn compute_percentages(&mut self, total_count: usize, total_value: u64) {
        self.pct_count = safe_percentage(self.count, total_count);
        self.pct_value = safe_percentage_u64(self.value, total_value);
    }
}

/// Type alias for satoshi value distributions (range bounds in satoshis)
pub type ValueBucket = DistributionBucket<u64>;

/// Type alias for transaction size distributions (range bounds in bytes)
pub type TxSizeBucket = DistributionBucket<u32>;

/// Type alias for output count distribution buckets (range bounds in output counts)
pub type OutputCountBucket = DistributionBucket<u32>;
