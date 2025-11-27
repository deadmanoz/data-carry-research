//! Mathematical utility functions for statistical analysis
//!
//! This module provides standardised percentage and ratio calculation utilities
//! with proper zero-division handling for use across the analysis module.

/// Calculate percentage safely for usize values, returning 0.0 if total is zero.
///
/// # Arguments
/// * `part` - The numerator (portion of the total)
/// * `total` - The denominator (total count)
///
/// # Returns
/// Percentage as a float (0.0 to 100.0), or 0.0 if total is zero.
///
/// # Examples
/// ```
/// use data_carry_research::utils::math::safe_percentage;
///
/// assert_eq!(safe_percentage(50, 100), 50.0);
/// assert_eq!(safe_percentage(1, 4), 25.0);
/// assert_eq!(safe_percentage(0, 100), 0.0);
/// assert_eq!(safe_percentage(50, 0), 0.0);  // Zero-division guard
/// ```
#[inline]
pub fn safe_percentage(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

/// Calculate percentage safely for u64 values, returning 0.0 if total is zero.
///
/// **Precision Note**: Large u64 values (>2^53) may lose precision when cast to f64.
/// This is acceptable for percentage display purposes where sub-percentage precision
/// is not critical.
///
/// # Arguments
/// * `part` - The numerator (portion of the total)
/// * `total` - The denominator (total value)
///
/// # Returns
/// Percentage as a float (0.0 to 100.0), or 0.0 if total is zero.
///
/// # Examples
/// ```
/// use data_carry_research::utils::math::safe_percentage_u64;
///
/// assert_eq!(safe_percentage_u64(50, 100), 50.0);
/// assert_eq!(safe_percentage_u64(1_000_000_000, 2_000_000_000), 50.0);
/// assert_eq!(safe_percentage_u64(0, 100), 0.0);
/// assert_eq!(safe_percentage_u64(50, 0), 0.0);  // Zero-division guard
/// ```
#[inline]
pub fn safe_percentage_u64(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

/// Calculate percentage safely for i64 values, returning 0.0 if total is zero or negative.
///
/// Primarily used for SQL query results where `COUNT(*)` returns `i64`.
/// Returns 0.0 for negative values (which shouldn't occur in count contexts).
///
/// # Arguments
/// * `part` - The numerator (portion of the total)
/// * `total` - The denominator (total count)
///
/// # Returns
/// Percentage as a float (0.0 to 100.0), or 0.0 if total is zero or negative.
///
/// # Examples
/// ```
/// use data_carry_research::utils::math::safe_percentage_i64;
///
/// assert_eq!(safe_percentage_i64(50, 100), 50.0);
/// assert_eq!(safe_percentage_i64(25, 100), 25.0);
/// assert_eq!(safe_percentage_i64(0, 100), 0.0);
/// assert_eq!(safe_percentage_i64(50, 0), 0.0);   // Zero-division guard
/// assert_eq!(safe_percentage_i64(50, -1), 0.0);  // Negative guard
/// ```
#[inline]
pub fn safe_percentage_i64(part: i64, total: i64) -> f64 {
    if total <= 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

/// Calculate ratio safely for usize values, returning 0.0 if denominator is zero.
///
/// Use this for averages and ratios (not percentages). For percentages, use
/// [`safe_percentage`] instead.
///
/// # Arguments
/// * `numerator` - The numerator value
/// * `denominator` - The denominator value
///
/// # Returns
/// Ratio as a float, or 0.0 if denominator is zero.
///
/// # Examples
/// ```
/// use data_carry_research::utils::math::safe_ratio;
///
/// assert_eq!(safe_ratio(100, 4), 25.0);      // 100 / 4 = 25
/// assert_eq!(safe_ratio(10, 3), 10.0 / 3.0); // ~3.333...
/// assert_eq!(safe_ratio(0, 100), 0.0);
/// assert_eq!(safe_ratio(50, 0), 0.0);        // Zero-division guard
/// ```
#[inline]
pub fn safe_ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Calculate ratio safely for u64 values, returning 0.0 if denominator is zero.
///
/// Use this for averages and ratios with u64 values (not percentages).
/// For percentages, use [`safe_percentage_u64`] instead.
///
/// **Precision Note**: Large u64 values (>2^53) may lose precision when cast to f64.
/// This is acceptable for ratio display purposes where sub-unit precision is not critical.
///
/// # Arguments
/// * `numerator` - The numerator value
/// * `denominator` - The denominator value
///
/// # Returns
/// Ratio as a float, or 0.0 if denominator is zero.
///
/// # Examples
/// ```
/// use data_carry_research::utils::math::safe_ratio_u64;
///
/// assert_eq!(safe_ratio_u64(100, 4), 25.0);
/// assert_eq!(safe_ratio_u64(1_000_000, 100), 10_000.0);
/// assert_eq!(safe_ratio_u64(0, 100), 0.0);
/// assert_eq!(safe_ratio_u64(50, 0), 0.0);    // Zero-division guard
/// ```
#[inline]
pub fn safe_ratio_u64(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_percentage_normal() {
        assert_eq!(safe_percentage(50, 100), 50.0);
        assert_eq!(safe_percentage(25, 100), 25.0);
        assert_eq!(safe_percentage(1, 4), 25.0);
        assert_eq!(safe_percentage(3, 4), 75.0);
    }

    #[test]
    fn test_safe_percentage_zero_total() {
        assert_eq!(safe_percentage(50, 0), 0.0);
        assert_eq!(safe_percentage(0, 0), 0.0);
        assert_eq!(safe_percentage(1000, 0), 0.0);
    }

    #[test]
    fn test_safe_percentage_zero_part() {
        assert_eq!(safe_percentage(0, 100), 0.0);
        assert_eq!(safe_percentage(0, 1), 0.0);
    }

    #[test]
    fn test_safe_percentage_full() {
        assert_eq!(safe_percentage(100, 100), 100.0);
        assert_eq!(safe_percentage(5000, 5000), 100.0);
    }

    #[test]
    fn test_safe_percentage_u64_normal() {
        assert_eq!(safe_percentage_u64(50, 100), 50.0);
        assert_eq!(safe_percentage_u64(1_000_000_000, 2_000_000_000), 50.0);
    }

    #[test]
    fn test_safe_percentage_u64_zero_total() {
        assert_eq!(safe_percentage_u64(50, 0), 0.0);
        assert_eq!(safe_percentage_u64(0, 0), 0.0);
    }

    #[test]
    fn test_safe_percentage_u64_zero_part() {
        assert_eq!(safe_percentage_u64(0, 100), 0.0);
    }

    #[test]
    fn test_safe_percentage_u64_large_values() {
        // Test with values that approach but don't exceed f64 precision limits
        // 2^53 = 9_007_199_254_740_992 is the max integer precisely representable in f64
        let large_total: u64 = 9_000_000_000_000_000;
        let half: u64 = 4_500_000_000_000_000;
        let result = safe_percentage_u64(half, large_total);

        // Should be approximately 50%, allowing for minor floating-point variance
        assert!((result - 50.0).abs() < 0.0001);
    }

    #[test]
    fn test_safe_percentage_i64_normal() {
        assert_eq!(safe_percentage_i64(50, 100), 50.0);
        assert_eq!(safe_percentage_i64(25, 100), 25.0);
        // Use epsilon comparison for floating-point
        let epsilon = 1e-10;
        assert!((safe_percentage_i64(1, 3) - 100.0 / 3.0).abs() < epsilon);
    }

    #[test]
    fn test_safe_percentage_i64_zero_total() {
        assert_eq!(safe_percentage_i64(50, 0), 0.0);
        assert_eq!(safe_percentage_i64(0, 0), 0.0);
    }

    #[test]
    fn test_safe_percentage_i64_negative_total() {
        // Negative totals should return 0.0 (shouldn't happen with COUNT(*))
        assert_eq!(safe_percentage_i64(50, -1), 0.0);
        assert_eq!(safe_percentage_i64(50, -100), 0.0);
    }

    #[test]
    fn test_safe_percentage_i64_zero_part() {
        assert_eq!(safe_percentage_i64(0, 100), 0.0);
    }

    #[test]
    fn test_safe_percentage_precision() {
        // Test that precision is maintained for typical use cases
        // Use epsilon comparison for floating-point (arithmetic order can affect precision)
        let epsilon = 1e-10;
        assert!((safe_percentage(1, 3) - 100.0 / 3.0).abs() < epsilon);
        assert!((safe_percentage(2, 3) - 200.0 / 3.0).abs() < epsilon);

        // Verify consistent results across implementations
        assert_eq!(safe_percentage(50, 100), safe_percentage_u64(50, 100));
    }

    #[test]
    fn test_safe_ratio_normal() {
        assert_eq!(safe_ratio(100, 4), 25.0);
        assert_eq!(safe_ratio(10, 2), 5.0);
        assert_eq!(safe_ratio(7, 2), 3.5);
    }

    #[test]
    fn test_safe_ratio_zero_denominator() {
        assert_eq!(safe_ratio(50, 0), 0.0);
        assert_eq!(safe_ratio(0, 0), 0.0);
        assert_eq!(safe_ratio(1000, 0), 0.0);
    }

    #[test]
    fn test_safe_ratio_zero_numerator() {
        assert_eq!(safe_ratio(0, 100), 0.0);
        assert_eq!(safe_ratio(0, 1), 0.0);
    }

    #[test]
    fn test_safe_ratio_u64_normal() {
        assert_eq!(safe_ratio_u64(100, 4), 25.0);
        assert_eq!(safe_ratio_u64(1_000_000, 100), 10_000.0);
    }

    #[test]
    fn test_safe_ratio_u64_zero_denominator() {
        assert_eq!(safe_ratio_u64(50, 0), 0.0);
        assert_eq!(safe_ratio_u64(0, 0), 0.0);
    }

    #[test]
    fn test_safe_ratio_precision() {
        let epsilon = 1e-10;
        assert!((safe_ratio(1, 3) - 1.0 / 3.0).abs() < epsilon);
        assert!((safe_ratio(2, 3) - 2.0 / 3.0).abs() < epsilon);

        // Verify consistent results across implementations
        assert_eq!(safe_ratio(50, 100), safe_ratio_u64(50, 100));
    }
}
