//! Time utilities for temporal analysis
//!
//! Shared utilities for weekly time bucket analysis across temporal analysers.

use chrono::{TimeZone, Utc};

/// Seconds in a week (7 × 24 × 60 × 60 = 604800)
pub const SECONDS_PER_WEEK: i64 = 604_800;

/// Convert Unix timestamp to ISO 8601 date string (YYYY-MM-DD)
///
/// Returns "1970-01-01" for invalid timestamps.
///
/// # Examples
/// ```
/// use data_carry_research::utils::time::timestamp_to_iso;
/// assert_eq!(timestamp_to_iso(0), "1970-01-01");
/// assert_eq!(timestamp_to_iso(1704067200), "2024-01-01");
/// ```
pub fn timestamp_to_iso(timestamp: i64) -> String {
    Utc.timestamp_opt(timestamp, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "1970-01-01".to_string())
}

/// Calculate week bucket dates from a week start timestamp
///
/// Returns (week_start_iso, week_end_iso) tuple.
///
/// # Arguments
/// * `week_start_ts` - Unix timestamp of week start (should be aligned to SECONDS_PER_WEEK)
///
/// # Examples
/// ```
/// use data_carry_research::utils::time::week_bucket_dates;
/// let (start, end) = week_bucket_dates(0);
/// assert_eq!(start, "1970-01-01");
/// assert_eq!(end, "1970-01-07");
/// ```
pub fn week_bucket_dates(week_start_ts: i64) -> (String, String) {
    let start = timestamp_to_iso(week_start_ts);
    let end = timestamp_to_iso(week_start_ts + SECONDS_PER_WEEK - 1);
    (start, end)
}

/// Extract date portion from datetime string
///
/// Handles SQLite datetime() output format ("YYYY-MM-DD HH:MM:SS").
/// Returns just the date part ("YYYY-MM-DD").
///
/// # Examples
/// ```
/// use data_carry_research::utils::time::extract_date_from_datetime;
/// assert_eq!(extract_date_from_datetime("2023-01-01 00:00:00"), "2023-01-01");
/// assert_eq!(extract_date_from_datetime("2023-12-31"), "2023-12-31");
/// ```
pub fn extract_date_from_datetime(datetime_str: &str) -> String {
    datetime_str
        .split(' ')
        .next()
        .unwrap_or(datetime_str)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_to_iso_epoch() {
        assert_eq!(timestamp_to_iso(0), "1970-01-01");
    }

    #[test]
    fn test_timestamp_to_iso_2024() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(timestamp_to_iso(1704067200), "2024-01-01");
    }

    #[test]
    fn test_timestamp_to_iso_2023() {
        // 2023-01-01 00:00:00 UTC = 1672531200
        assert_eq!(timestamp_to_iso(1672531200), "2023-01-01");
    }

    #[test]
    fn test_week_bucket_dates_epoch() {
        let (start, end) = week_bucket_dates(0);
        assert_eq!(start, "1970-01-01");
        assert_eq!(end, "1970-01-07");
    }

    #[test]
    fn test_seconds_per_week() {
        assert_eq!(SECONDS_PER_WEEK, 7 * 24 * 60 * 60);
    }

    #[test]
    fn test_extract_date_from_datetime() {
        assert_eq!(
            extract_date_from_datetime("2023-01-01 00:00:00"),
            "2023-01-01"
        );
        assert_eq!(extract_date_from_datetime("2023-12-31"), "2023-12-31");
    }
}
