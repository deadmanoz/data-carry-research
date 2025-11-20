//! Shared database helper functions to reduce code duplication
//!
//! This module contains commonly-used patterns extracted from stage operations
//! to ensure consistency and reduce maintenance burden.

use crate::errors::AppResult;
use crate::types::{EnrichedTransaction, TransactionOutput};
use rusqlite::{params, Row, Transaction};
use tracing::debug;

/// Ensure stub blocks exist for given heights
///
/// Inserts stub blocks (height-only rows) into the blocks table to satisfy
/// foreign key constraints when inserting transaction outputs or classifications.
/// Uses INSERT OR IGNORE to safely handle duplicate heights.
///
/// This is critical for Schema V2's FK enforcement - child rows (transaction_outputs,
/// burn_patterns, classifications) reference the blocks table.
///
/// # Arguments
/// * `tx` - Active database transaction
/// * `heights` - Block heights to ensure exist
///
/// # Returns
/// * `AppResult<()>` - Success or database error
pub fn ensure_blocks_exist(tx: &Transaction, heights: &[u32]) -> AppResult<()> {
    let mut stmt = tx
        .prepare_cached("INSERT OR IGNORE INTO blocks (height) VALUES (?1)")
        .map_err(crate::errors::AppError::Database)?;

    for height in heights {
        stmt.execute(params![height])
            .map_err(crate::errors::AppError::Database)?;
    }

    debug!("Ensured {} stub blocks exist", heights.len());
    Ok(())
}

/// Construct a TransactionOutput from a database row
///
/// Standard row mapping for transaction_outputs table queries.
/// Expects columns in this order:
/// 0. txid (TEXT)
/// 1. vout (INTEGER)
/// 2. height (INTEGER)
/// 3. amount (INTEGER)
/// 4. script_hex (TEXT)
/// 5. script_type (TEXT)
/// 6. is_coinbase (BOOLEAN)
/// 7. script_size (INTEGER)
/// 8. metadata_json (TEXT, optional)
/// 9. address (TEXT, optional)
///
/// # Arguments
/// * `row` - Database row from query result
///
/// # Returns
/// * `rusqlite::Result<TransactionOutput>` - Constructed output or database error
pub fn transaction_output_from_row(row: &Row) -> rusqlite::Result<TransactionOutput> {
    Ok(TransactionOutput {
        txid: row.get(0)?,
        vout: row.get(1)?,
        height: row.get::<_, i64>(2)? as u32,
        amount: row.get::<_, i64>(3)? as u64,
        script_hex: row.get(4)?,
        script_type: row.get(5)?,
        is_coinbase: row.get(6)?,
        script_size: row.get::<_, i64>(7)? as usize,
        metadata: row
            .get::<_, Option<String>>(8)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        address: row.get(9)?,
    })
}

/// Standard SELECT columns for EnrichedTransaction queries
///
/// Use this constant when building queries to ensure consistent column order
/// with `enriched_transaction_from_row()`.
pub const ENRICHED_TX_SELECT_COLUMNS: &str = "et.txid, et.height, et.total_input_value, \
    et.total_output_value, et.transaction_fee, et.fee_per_byte, et.transaction_size_bytes, \
    et.fee_per_kb, et.total_p2ms_amount, et.data_storage_fee_rate, et.p2ms_outputs_count, \
    et.input_count, et.output_count, et.is_coinbase";

/// Construct an EnrichedTransaction from a database row
///
/// Standard row mapping for enriched_transactions table queries.
/// Expects columns in order defined by `ENRICHED_TX_SELECT_COLUMNS`.
///
/// Returns an EnrichedTransaction with empty vectors for `outputs` and
/// `burn_patterns_detected` - caller must populate these if needed.
///
/// # Arguments
/// * `row` - Database row from query result
///
/// # Returns
/// * `rusqlite::Result<EnrichedTransaction>` - Constructed transaction or database error
pub fn enriched_transaction_from_row(row: &Row) -> rusqlite::Result<EnrichedTransaction> {
    Ok(EnrichedTransaction {
        txid: row.get(0)?,
        height: row.get(1)?,
        total_input_value: row.get::<_, i64>(2)? as u64,
        total_output_value: row.get::<_, i64>(3)? as u64,
        transaction_fee: row.get::<_, i64>(4)? as u64,
        fee_per_byte: row.get(5)?,
        transaction_size_bytes: row.get(6)?,
        fee_per_kb: row.get(7)?,
        total_p2ms_amount: row.get::<_, i64>(8)? as u64,
        data_storage_fee_rate: row.get(9)?,
        p2ms_outputs_count: row.get(10)?,
        input_count: row.get(11)?,
        output_count: row.get(12)?,
        is_coinbase: row.get(13)?,
        outputs: Vec::new(),
        burn_patterns_detected: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use rusqlite::Connection;

    #[test]
    fn test_ensure_blocks_exist() {
        // Use a separate connection for testing (need mutability)
        let mut conn = Connection::open(":memory:").unwrap();
        crate::database::schema_v2::setup_schema_v2(&conn).unwrap();

        let tx = conn.transaction().unwrap();
        let heights = vec![100000, 100001, 100002];

        // Should succeed
        ensure_blocks_exist(&tx, &heights).unwrap();

        // Verify blocks were created
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE height IN (100000, 100001, 100002)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);

        // Should be idempotent (INSERT OR IGNORE)
        ensure_blocks_exist(&tx, &heights).unwrap();
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_transaction_output_from_row_construction() {
        // This test verifies the helper constructs outputs correctly
        // Full integration testing happens in stage operations tests
        let db = Database::new_v2(":memory:").unwrap();
        let conn = db.connection();

        // Insert a test output
        conn.execute("INSERT INTO blocks (height) VALUES (?1)", params![100000])
            .unwrap();

        conn.execute(
            "INSERT INTO transaction_outputs (txid, vout, height, amount, script_hex, script_type, \
             is_coinbase, script_size, metadata_json, address, is_spent) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                "test_txid",
                0,
                100000,
                1000,
                "76a914...",
                "multisig",
                false,
                25,
                r#"{"m":2,"n":3}"#,
                Some("1Address..."),
                0
            ],
        )
        .unwrap();

        // Query and construct using helper
        let output = conn
            .query_row(
                "SELECT txid, vout, height, amount, script_hex, script_type, is_coinbase, \
                 script_size, metadata_json, address FROM transaction_outputs WHERE txid = ?1",
                params!["test_txid"],
                transaction_output_from_row,
            )
            .unwrap();

        assert_eq!(output.txid, "test_txid");
        assert_eq!(output.vout, 0);
        assert_eq!(output.height, 100000);
        assert_eq!(output.amount, 1000);
        assert_eq!(output.script_type, "multisig");
    }
}
