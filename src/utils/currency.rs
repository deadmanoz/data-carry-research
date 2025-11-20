//! Currency formatting utilities for Bitcoin and satoshi values
//!
//! This module provides standardised formatting for displaying Bitcoin amounts
//! in both BTC and satoshi units for better readability and precision.

/// Satoshis per Bitcoin
const SATS_PER_BTC: f64 = 100_000_000.0;

/// Format a satoshi amount as dual BTC + sats display
///
/// # Examples
/// ```
/// use data_carry_research::utils::currency::format_sats_as_btc;
///
/// assert_eq!(
///     format_sats_as_btc(28125351850),
///     "281.25351850 BTC (28125351850 sats)"
/// );
/// assert_eq!(
///     format_sats_as_btc(5471),
///     "0.00005471 BTC (5471 sats)"
/// );
/// ```
pub fn format_sats_as_btc(sats: u64) -> String {
    let btc = sats as f64 / SATS_PER_BTC;
    format!("{:.8} BTC ({} sats)", btc, sats)
}

/// Format a floating-point satoshi amount as dual BTC + sats display
///
/// Used for averages and calculated values that may have fractional satoshis.
///
/// # Examples
/// ```
/// use data_carry_research::utils::currency::format_sats_as_btc_f64;
///
/// assert_eq!(
///     format_sats_as_btc_f64(22198.38),
///     "0.00022198 BTC (22198.38 sats)"
/// );
/// ```
pub fn format_sats_as_btc_f64(sats: f64) -> String {
    let btc = sats / SATS_PER_BTC;
    format!("{:.8} BTC ({:.2} sats)", btc, sats)
}

/// Format sat/byte or sat/vbyte rates as dual BTC/byte + sat/byte display
///
/// # Examples
/// ```
/// use data_carry_research::utils::currency::format_rate_as_btc;
///
/// assert_eq!(
///     format_rate_as_btc(150.0, "byte"),
///     "0.00000150 BTC/byte (150.00 sat/byte)"
/// );
/// ```
pub fn format_rate_as_btc(sats_per_unit: f64, unit: &str) -> String {
    let btc_per_unit = sats_per_unit / SATS_PER_BTC;
    format!(
        "{:.8} BTC/{} ({:.2} sat/{})",
        btc_per_unit, unit, sats_per_unit, unit
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_sats_as_btc() {
        assert_eq!(
            format_sats_as_btc(100_000_000),
            "1.00000000 BTC (100000000 sats)"
        );
        assert_eq!(
            format_sats_as_btc(28125351850),
            "281.25351850 BTC (28125351850 sats)"
        );
        assert_eq!(format_sats_as_btc(5471), "0.00005471 BTC (5471 sats)");
        assert_eq!(format_sats_as_btc(0), "0.00000000 BTC (0 sats)");
    }

    #[test]
    fn test_format_sats_as_btc_f64() {
        assert_eq!(
            format_sats_as_btc_f64(22198.38),
            "0.00022198 BTC (22198.38 sats)"
        );
        assert_eq!(
            format_sats_as_btc_f64(5471.63),
            "0.00005472 BTC (5471.63 sats)"
        );
        assert_eq!(format_sats_as_btc_f64(0.0), "0.00000000 BTC (0.00 sats)");
    }

    #[test]
    fn test_format_rate_as_btc() {
        assert_eq!(
            format_rate_as_btc(150.0, "byte"),
            "0.00000150 BTC/byte (150.00 sat/byte)"
        );
        assert_eq!(
            format_rate_as_btc(250.5, "vbyte"),
            "0.00000251 BTC/vbyte (250.50 sat/vbyte)"
        );
    }

    #[test]
    fn test_precision() {
        // Test that we maintain 8 decimal places for BTC (satoshi precision)
        let result = format_sats_as_btc(1);
        assert!(result.starts_with("0.00000001 BTC"));

        // Test large values
        let result = format_sats_as_btc(2_100_000_000_000_000);
        assert!(result.contains("21000000.00000000 BTC"));
    }
}
