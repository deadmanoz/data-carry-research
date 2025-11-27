//! Mathematical utility functions for statistical analysis
//!
//! This module provides standardised percentage calculation utilities
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
    fn test_safe_percentage_precision() {
        // Test that precision is maintained for typical use cases
        // Use epsilon comparison for floating-point (arithmetic order can affect precision)
        let epsilon = 1e-10;
        assert!((safe_percentage(1, 3) - 100.0 / 3.0).abs() < epsilon);
        assert!((safe_percentage(2, 3) - 200.0 / 3.0).abs() < epsilon);

        // Verify consistent results across implementations
        assert_eq!(safe_percentage(50, 100), safe_percentage_u64(50, 100));
    }
}
