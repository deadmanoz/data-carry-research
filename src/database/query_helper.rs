//! Query helper utilities for common database patterns
//!
//! This module consolidates repeated query patterns across analysis modules:
//! - Single aggregate queries (COUNT, SUM, AVG, MIN, MAX)
//! - Multi-row grouped queries with automatic percentage calculation
//! - Optional value handling with defaults
//! - Query collection with mapping
//!
//! ## Design Goals
//!
//! - **Reduce boilerplate**: Replace 3-8 line patterns with single calls
//! - **Type safety**: Generic implementations with proper error handling
//! - **Consistency**: Uniform query patterns across all analysis modules
//! - **Performance**: Zero-cost abstractions, no overhead vs manual queries

use crate::errors::AppResult;
use crate::utils::math::safe_percentage_i64;
use rusqlite::{Connection, Row};

/// Helper trait for common database query patterns
///
/// Implemented for `rusqlite::Connection` to provide ergonomic helpers
/// for the most common query patterns in analysis code.
///
/// ## Usage Examples
///
/// ```ignore
/// use crate::database::QueryHelper;
///
/// // Count rows
/// let total = conn.count_rows("burn_patterns", None)?;
/// let filtered = conn.count_rows("burn_patterns", Some("pattern_type = 'OP_RETURN'"))?;
///
/// // Safe aggregates (NULL becomes default)
/// let total_fees = conn.safe_aggregate::<i64>(
///     "SELECT SUM(transaction_fee) FROM enriched_transactions",
///     0i64
/// )?;
///
/// // Collect multiple rows
/// let patterns = conn.query_collect(
///     "SELECT pattern_type, COUNT(*) FROM burn_patterns GROUP BY pattern_type",
///     |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
/// )?;
///
/// // Grouped queries with automatic percentages
/// let stats = conn.query_grouped_percentages(
///     "SELECT protocol, COUNT(*) FROM transaction_classifications GROUP BY protocol"
/// )?;
/// ```
pub trait QueryHelper {
    // ============================================================
    // PATTERN 1: Row Counting
    // ============================================================

    /// Query a COUNT(*) result for any table
    ///
    /// # Arguments
    /// * `table` - Table name (e.g., "burn_patterns")
    /// * `where_clause` - Optional WHERE condition (e.g., Some("is_coinbase = 1"))
    ///
    /// # Returns
    /// * `i64` - Row count
    ///
    /// # Examples
    /// ```ignore
    /// let total = conn.count_rows("burn_patterns", None)?;
    /// let coinbase = conn.count_rows("enriched_transactions", Some("is_coinbase = 1"))?;
    /// ```
    fn count_rows(&self, table: &str, where_clause: Option<&str>) -> AppResult<i64>;

    // ============================================================
    // PATTERN 2: Safe Aggregates with Defaults
    // ============================================================

    /// Execute aggregate query returning optional value, with automatic NULL → default conversion
    ///
    /// Perfect for SUM, AVG that return NULL on empty result sets.
    ///
    /// # Arguments
    /// * `sql` - Full SQL query
    /// * `default` - Value to use if query returns NULL
    ///
    /// # Returns
    /// * `T` - Result or default value
    ///
    /// # Examples
    /// ```ignore
    /// let total = conn.safe_aggregate::<i64>(
    ///     "SELECT SUM(transaction_fee) FROM enriched_transactions",
    ///     0i64
    /// )?;
    /// let avg = conn.safe_aggregate::<f64>(
    ///     "SELECT AVG(fee_per_byte) FROM enriched_transactions WHERE fee_per_byte > 0",
    ///     0.0f64
    /// )?;
    /// ```
    fn safe_aggregate<T>(&self, sql: &str, default: T) -> AppResult<T>
    where
        T: rusqlite::types::FromSql + Copy;

    // ============================================================
    // PATTERN 3: Multi-Row Collection with Mapping
    // ============================================================

    /// Execute query returning multiple rows, collecting into Vec
    ///
    /// Handles the prepare() + query_map() + collect() pattern in one call.
    ///
    /// # Arguments
    /// * `sql` - SQL query string
    /// * `mapper` - Closure that maps Row to T
    ///
    /// # Returns
    /// * `Vec<T>` - Collected results
    ///
    /// # Examples
    /// ```ignore
    /// let counts: Vec<(String, i64)> = conn.query_collect(
    ///     "SELECT pattern_type, COUNT(*) FROM burn_patterns GROUP BY pattern_type",
    ///     |row| Ok((row.get(0)?, row.get(1)?))
    /// )?;
    /// ```
    fn query_collect<T, F>(&self, sql: &str, mapper: F) -> AppResult<Vec<T>>
    where
        F: FnMut(&Row) -> rusqlite::Result<T>;

    // ============================================================
    // PATTERN 4: Grouped Queries with Automatic Percentages
    // ============================================================

    /// Execute grouped query with automatic percentage calculation
    ///
    /// Assumes query returns (String, i64) pairs - category and count.
    /// Automatically calculates percentages based on total.
    ///
    /// # Arguments
    /// * `sql` - SQL query returning (category, count)
    ///
    /// # Returns
    /// * `Vec<(String, usize, f64)>` - (category, count, percentage)
    ///
    /// # Examples
    /// ```ignore
    /// let stats = conn.query_grouped_percentages(
    ///     "SELECT pattern_type, COUNT(*) FROM burn_patterns GROUP BY pattern_type ORDER BY COUNT(*) DESC"
    /// )?;
    /// // Returns: vec![("pattern1", 100, 50.0), ("pattern2", 100, 50.0)]
    /// ```
    fn query_grouped_percentages(&self, sql: &str) -> AppResult<Vec<(String, usize, f64)>>;
}

/// Implementation of QueryHelper for rusqlite::Connection
impl QueryHelper for Connection {
    fn count_rows(&self, table: &str, where_clause: Option<&str>) -> AppResult<i64> {
        let sql = if let Some(where_part) = where_clause {
            format!("SELECT COUNT(*) FROM {} WHERE {}", table, where_part)
        } else {
            format!("SELECT COUNT(*) FROM {}", table)
        };

        self.query_row(&sql, [], |row| row.get(0))
            .map_err(Into::into)
    }

    fn safe_aggregate<T>(&self, sql: &str, default: T) -> AppResult<T>
    where
        T: rusqlite::types::FromSql + Copy,
    {
        let result: Option<T> = self.query_row(sql, [], |row| row.get(0))?;
        Ok(result.unwrap_or(default))
    }

    fn query_collect<T, F>(&self, sql: &str, mut mapper: F) -> AppResult<Vec<T>>
    where
        F: FnMut(&Row) -> rusqlite::Result<T>,
    {
        let mut stmt = self.prepare(sql)?;
        let results = stmt
            .query_map([], &mut mapper)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(results)
    }

    fn query_grouped_percentages(&self, sql: &str) -> AppResult<Vec<(String, usize, f64)>> {
        // First pass: collect all rows and calculate total
        let mut stmt = self.prepare(sql)?;
        let rows: Vec<(String, i64)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let total: i64 = rows.iter().map(|(_, count)| count).sum();

        // Second pass: convert to results with percentages
        let results = rows
            .into_iter()
            .map(|(category, count)| {
                let percentage = safe_percentage_i64(count, total);
                (category, count as usize, percentage)
            })
            .collect();

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();

        // Create test table
        conn.execute(
            "CREATE TABLE test_data (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL,
                amount INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        // Insert test data
        conn.execute(
            "INSERT INTO test_data (category, amount) VALUES ('A', 100)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO test_data (category, amount) VALUES ('A', 200)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO test_data (category, amount) VALUES ('B', 150)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO test_data (category, amount) VALUES ('B', 250)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO test_data (category, amount) VALUES ('C', 300)",
            [],
        )
        .unwrap();

        conn
    }

    #[test]
    fn test_count_rows_without_where() {
        let conn = setup_test_db();
        let count = conn.count_rows("test_data", None).unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_count_rows_with_where() {
        let conn = setup_test_db();
        let count = conn
            .count_rows("test_data", Some("category = 'A'"))
            .unwrap();
        assert_eq!(count, 2);

        let count = conn.count_rows("test_data", Some("amount > 200")).unwrap();
        assert_eq!(count, 2); // B:250 and C:300
    }

    #[test]
    fn test_safe_aggregate_with_data() {
        let conn = setup_test_db();

        let total = conn
            .safe_aggregate::<i64>("SELECT SUM(amount) FROM test_data", 0i64)
            .unwrap();
        assert_eq!(total, 1000); // 100+200+150+250+300

        let avg = conn
            .safe_aggregate::<f64>("SELECT AVG(amount) FROM test_data", 0.0)
            .unwrap();
        assert_eq!(avg, 200.0); // 1000/5
    }

    #[test]
    fn test_safe_aggregate_empty_result() {
        let conn = setup_test_db();

        // Query that returns NULL (no matching rows)
        let total = conn
            .safe_aggregate::<i64>(
                "SELECT SUM(amount) FROM test_data WHERE category = 'NONEXISTENT'",
                999i64,
            )
            .unwrap();
        assert_eq!(total, 999); // Should return default

        let avg = conn
            .safe_aggregate::<f64>(
                "SELECT AVG(amount) FROM test_data WHERE category = 'NONEXISTENT'",
                123.45,
            )
            .unwrap();
        assert_eq!(avg, 123.45); // Should return default
    }

    #[test]
    fn test_query_collect() {
        let conn = setup_test_db();

        let results: Vec<(String, i64)> = conn
            .query_collect(
                "SELECT category, SUM(amount) FROM test_data GROUP BY category ORDER BY category",
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0], ("A".to_string(), 300)); // 100+200
        assert_eq!(results[1], ("B".to_string(), 400)); // 150+250
        assert_eq!(results[2], ("C".to_string(), 300));
    }

    #[test]
    fn test_query_grouped_percentages() {
        let conn = setup_test_db();

        let results = conn
            .query_grouped_percentages(
                "SELECT category, COUNT(*) FROM test_data GROUP BY category ORDER BY category",
            )
            .unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "A");
        assert_eq!(results[0].1, 2); // count
        assert_eq!(results[0].2, 40.0); // percentage: 2/5 * 100

        assert_eq!(results[1].0, "B");
        assert_eq!(results[1].1, 2);
        assert_eq!(results[1].2, 40.0);

        assert_eq!(results[2].0, "C");
        assert_eq!(results[2].1, 1);
        assert_eq!(results[2].2, 20.0); // percentage: 1/5 * 100
    }
}
