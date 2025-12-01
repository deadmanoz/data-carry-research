//! Utility functions for report formatting
//!
//! Provides shared formatting helpers used across all report formatters.

use crate::errors::AppResult;
use serde::Serialize;

/// Format number with thousand separators for console output
///
/// # Arguments
///
/// * `n` - Number to format
///
/// # Returns
///
/// String with comma separators (e.g., "1,234,567")
///
/// # Examples
///
/// ```
/// # use data_carry_research::analysis::reports::utils::format_number;
/// assert_eq!(format_number(1234), "1,234");
/// assert_eq!(format_number(1234567), "1,234,567");
/// assert_eq!(format_number(904233), "904,233");
/// ```
pub fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(*c);
    }

    result
}

/// Format byte counts using conventional units (KB, MB, GB)
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes == 0 {
        "0 B".to_string()
    } else if bytes as f64 >= GB {
        format!("{:.2} GB", bytes as f64 / GB)
    } else if bytes as f64 >= MB {
        format!("{:.2} MB", bytes as f64 / MB)
    } else if bytes as f64 >= KB {
        format!("{:.2} KB", bytes as f64 / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// Export data as JSON for programmatic use
pub fn export_json<T: Serialize>(data: &T) -> AppResult<String> {
    serde_json::to_string_pretty(data)
        .map_err(|e| crate::errors::AppError::Config(format!("JSON export failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        // Small numbers
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(99), "99");
        assert_eq!(format_number(123), "123");

        // Thousands
        assert_eq!(format_number(1_000), "1,000");
        assert_eq!(format_number(1_234), "1,234");
        assert_eq!(format_number(9_999), "9,999");

        // Ten thousands
        assert_eq!(format_number(10_000), "10,000");
        assert_eq!(format_number(12_345), "12,345");
        assert_eq!(format_number(99_999), "99,999");

        // Hundreds of thousands
        assert_eq!(format_number(100_000), "100,000");
        assert_eq!(format_number(123_456), "123,456");
        assert_eq!(format_number(999_999), "999,999");

        // Millions
        assert_eq!(format_number(1_000_000), "1,000,000");
        assert_eq!(format_number(1_234_567), "1,234,567");
        assert_eq!(format_number(12_345_678), "12,345,678");

        // Real-world examples from Bitcoin Stamps data
        assert_eq!(format_number(904_233), "904,233");
        assert_eq!(format_number(78_263), "78,263");
        assert_eq!(format_number(825_899), "825,899");
        assert_eq!(format_number(2_700_000), "2,700,000");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_024), "1.00 KB");
        assert_eq!(format_bytes(5_242_880), "5.00 MB");
        assert_eq!(format_bytes(3_221_225_472), "3.00 GB");
    }
}
