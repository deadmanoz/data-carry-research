//! Shared test setup utilities for analysis module unit tests.
//!
//! This module provides FK-safe database seeding helpers that follow the mandatory
//! insertion order defined in `.claude/CORE_TYPES_REFERENCE.md`:
//!
//! 1. `blocks` (stub entries)
//! 2. `transaction_outputs` (with `script_type='multisig'`)
//! 3. `p2ms_outputs` (FK to transaction_outputs)
//! 4. `enriched_transactions` (FK to blocks)
//! 5. `transaction_classifications` (FK to enriched_transactions)
//! 6. `p2ms_output_classifications` (FK to transaction_classifications + transaction_outputs)
//!
//! **IMPORTANT**: Always follow this order when seeding test data to avoid FK constraint violations.

use data_carry_research::database::Database;
use data_carry_research::errors::AppResult;

/// Create an in-memory test database.
///
/// This is the standard way to create a test database for analysis tests.
/// Uses `:memory:` for fast, isolated tests.
pub fn create_analysis_test_db() -> AppResult<Database> {
    Database::new(":memory:")
}

/// Seed stub block entries for FK constraints.
///
/// # Arguments
/// * `db` - The test database
/// * `heights` - Slice of block heights to create
///
/// # Example
/// ```ignore
/// seed_analysis_blocks(&db, &[100000, 100001, 100002])?;
/// ```
pub fn seed_analysis_blocks(db: &Database, heights: &[i64]) -> AppResult<()> {
    let conn = db.connection();
    for height in heights {
        conn.execute("INSERT INTO blocks (height) VALUES (?1)", [height])?;
    }
    Ok(())
}

/// Parameters for inserting a test transaction output.
#[derive(Debug, Clone)]
pub struct TestOutputParams {
    pub txid: String,
    pub vout: i64,
    pub height: i64,
    pub amount: i64,
    pub script_hex: String,
    pub script_type: String,
    pub script_size: i64,
    pub is_spent: bool,
    pub metadata_json: String,
}

impl TestOutputParams {
    /// Create a standard P2MS output with minimal required fields.
    pub fn multisig(txid: &str, vout: i64, height: i64, amount: i64, script_size: i64) -> Self {
        Self {
            txid: txid.to_string(),
            vout,
            height,
            amount,
            script_hex: "aabbcc".to_string(),
            script_type: "multisig".to_string(),
            script_size,
            is_spent: false,
            metadata_json: "{}".to_string(),
        }
    }

    /// Builder method to set the output as spent.
    #[allow(dead_code)]
    pub fn spent(mut self) -> Self {
        self.is_spent = true;
        self
    }

    /// Builder method to set custom metadata.
    #[allow(dead_code)]
    pub fn with_metadata(mut self, json: &str) -> Self {
        self.metadata_json = json.to_string();
        self
    }
}

/// Insert a test transaction output into the database.
///
/// This inserts into `transaction_outputs` table only. For P2MS outputs,
/// you must also call `insert_test_p2ms_output()` afterwards.
///
/// # FK Order
/// Call `seed_analysis_blocks()` BEFORE calling this function.
pub fn insert_test_output(db: &Database, params: &TestOutputParams) -> AppResult<()> {
    let conn = db.connection();
    conn.execute(
        "INSERT INTO transaction_outputs (
            txid, vout, height, amount, script_hex, script_type,
            is_coinbase, script_size, metadata_json, is_spent
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9)",
        rusqlite::params![
            params.txid,
            params.vout,
            params.height,
            params.amount,
            params.script_hex,
            params.script_type,
            params.script_size,
            params.metadata_json,
            params.is_spent as i32,
        ],
    )?;
    Ok(())
}

/// Parameters for inserting a P2MS output entry.
#[derive(Debug, Clone)]
pub struct TestP2msOutputParams {
    pub txid: String,
    pub vout: i64,
    pub required_sigs: i64,
    pub total_pubkeys: i64,
    pub pubkeys_json: String,
}

impl TestP2msOutputParams {
    /// Create a standard 1-of-3 P2MS output.
    pub fn standard(txid: &str, vout: i64) -> Self {
        Self {
            txid: txid.to_string(),
            vout,
            required_sigs: 1,
            total_pubkeys: 3,
            pubkeys_json: "[]".to_string(),
        }
    }

    /// Builder method to set custom M-of-N configuration.
    #[allow(dead_code)]
    pub fn with_config(mut self, required_sigs: i64, total_pubkeys: i64) -> Self {
        self.required_sigs = required_sigs;
        self.total_pubkeys = total_pubkeys;
        self
    }
}

/// Insert a P2MS output entry.
///
/// # FK Order
/// Call `insert_test_output()` BEFORE calling this function.
pub fn insert_test_p2ms_output(db: &Database, params: &TestP2msOutputParams) -> AppResult<()> {
    let conn = db.connection();
    conn.execute(
        "INSERT INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            params.txid,
            params.vout,
            params.required_sigs,
            params.total_pubkeys,
            params.pubkeys_json,
        ],
    )?;
    Ok(())
}

/// Parameters for inserting a transaction classification.
#[derive(Debug, Clone)]
pub struct TestClassificationParams {
    pub txid: String,
    pub protocol: String,
    pub variant: Option<String>,
    pub content_type: Option<String>,
    pub protocol_signature_found: bool,
}

impl TestClassificationParams {
    /// Create a basic classification with protocol only.
    pub fn new(txid: &str, protocol: &str) -> Self {
        Self {
            txid: txid.to_string(),
            protocol: protocol.to_string(),
            variant: None,
            content_type: Some("application/octet-stream".to_string()),
            protocol_signature_found: true,
        }
    }

    /// Builder method to set variant.
    #[allow(dead_code)]
    pub fn with_variant(mut self, variant: &str) -> Self {
        self.variant = Some(variant.to_string());
        self
    }

    /// Builder method to set content type.
    #[allow(dead_code)]
    pub fn with_content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(content_type.to_string());
        self
    }

    /// Builder method to set content type to NULL.
    #[allow(dead_code)]
    pub fn without_content_type(mut self) -> Self {
        self.content_type = None;
        self
    }

    /// Builder method to set protocol_signature_found to false.
    #[allow(dead_code)]
    pub fn without_protocol_signature(mut self) -> Self {
        self.protocol_signature_found = false;
        self
    }
}

/// Insert an enriched transaction entry (required for classifications).
///
/// # FK Order
/// Call `seed_analysis_blocks()` BEFORE calling this function.
pub fn insert_test_enriched_transaction(db: &Database, txid: &str, height: i64) -> AppResult<()> {
    let conn = db.connection();
    conn.execute(
        "INSERT INTO enriched_transactions (
            txid, height, total_input_value, total_output_value,
            transaction_fee, fee_per_byte, transaction_size_bytes, fee_per_kb,
            total_p2ms_amount, data_storage_fee_rate, p2ms_outputs_count,
            input_count, output_count, is_coinbase
        ) VALUES (?1, ?2, 2000, 1000, 1000, 10.0, 100, 10000.0, 1000, 10.0, 1, 1, 1, 0)",
        rusqlite::params![txid, height],
    )?;
    Ok(())
}

/// Insert a transaction-level classification.
///
/// # FK Order
/// Call `insert_test_enriched_transaction()` BEFORE calling this function.
pub fn insert_test_tx_classification(
    db: &Database,
    params: &TestClassificationParams,
) -> AppResult<()> {
    let conn = db.connection();
    conn.execute(
        "INSERT INTO transaction_classifications (
            txid, protocol, variant, protocol_signature_found,
            classification_method, content_type
        ) VALUES (?1, ?2, ?3, ?4, 'SignatureBased', ?5)",
        rusqlite::params![
            params.txid,
            params.protocol,
            params.variant,
            params.protocol_signature_found as i32,
            params.content_type,
        ],
    )?;
    Ok(())
}

/// Parameters for inserting an output-level classification.
#[derive(Debug, Clone)]
pub struct TestOutputClassificationParams {
    pub txid: String,
    pub vout: i64,
    pub protocol: String,
    pub variant: Option<String>,
    pub content_type: Option<String>,
    pub is_spendable: bool,
    pub spendability_reason: String,
    pub protocol_signature_found: bool,
}

impl TestOutputClassificationParams {
    /// Create a classification for an unspendable data-carrying output.
    pub fn unspendable(txid: &str, vout: i64, protocol: &str) -> Self {
        Self {
            txid: txid.to_string(),
            vout,
            protocol: protocol.to_string(),
            variant: None,
            content_type: Some("application/octet-stream".to_string()),
            is_spendable: false,
            spendability_reason: "AllDataKeys".to_string(),
            protocol_signature_found: true,
        }
    }

    /// Create a classification for a spendable output.
    #[allow(dead_code)]
    pub fn spendable(txid: &str, vout: i64, protocol: &str) -> Self {
        Self {
            txid: txid.to_string(),
            vout,
            protocol: protocol.to_string(),
            variant: None,
            content_type: Some("application/octet-stream".to_string()),
            is_spendable: true,
            spendability_reason: "AllValidECPoints".to_string(),
            protocol_signature_found: true,
        }
    }

    /// Builder method to set variant.
    #[allow(dead_code)]
    pub fn with_variant(mut self, variant: &str) -> Self {
        self.variant = Some(variant.to_string());
        self
    }

    /// Builder method to set content type.
    #[allow(dead_code)]
    pub fn with_content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(content_type.to_string());
        self
    }

    /// Builder method to set content type to NULL.
    #[allow(dead_code)]
    pub fn without_content_type(mut self) -> Self {
        self.content_type = None;
        self
    }

    /// Builder method to set protocol_signature_found to false.
    #[allow(dead_code)]
    pub fn without_protocol_signature(mut self) -> Self {
        self.protocol_signature_found = false;
        self
    }
}

/// Insert an output-level classification.
///
/// # FK Order
/// Call BOTH `insert_test_output()` AND `insert_test_tx_classification()`
/// BEFORE calling this function.
pub fn insert_test_output_classification(
    db: &Database,
    params: &TestOutputClassificationParams,
) -> AppResult<()> {
    let conn = db.connection();
    conn.execute(
        "INSERT INTO p2ms_output_classifications (
            txid, vout, protocol, variant, protocol_signature_found,
            classification_method, content_type, is_spendable, spendability_reason
        ) VALUES (?1, ?2, ?3, ?4, ?5, 'SignatureBased', ?6, ?7, ?8)",
        rusqlite::params![
            params.txid,
            params.vout,
            params.protocol,
            params.variant,
            params.protocol_signature_found as i32,
            params.content_type,
            params.is_spendable as i32,
            params.spendability_reason,
        ],
    )?;
    Ok(())
}

/// Convenience function to insert a complete P2MS output (transaction_outputs + p2ms_outputs).
///
/// This is a shorthand for calling both `insert_test_output()` and `insert_test_p2ms_output()`.
///
/// # FK Order
/// Call `seed_analysis_blocks()` BEFORE calling this function.
pub fn insert_complete_p2ms_output(
    db: &Database,
    txid: &str,
    vout: i64,
    height: i64,
    amount: i64,
    script_size: i64,
) -> AppResult<()> {
    insert_test_output(
        db,
        &TestOutputParams::multisig(txid, vout, height, amount, script_size),
    )?;
    insert_test_p2ms_output(db, &TestP2msOutputParams::standard(txid, vout))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_analysis_test_db() -> AppResult<()> {
        let db = create_analysis_test_db()?;
        // Verify it's a valid database by checking a table exists
        let conn = db.connection();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'blocks'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(count, 1);
        Ok(())
    }

    #[test]
    fn test_seed_analysis_blocks() -> AppResult<()> {
        let db = create_analysis_test_db()?;
        seed_analysis_blocks(&db, &[100, 200, 300])?;

        let conn = db.connection();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))?;
        assert_eq!(count, 3);
        Ok(())
    }

    #[test]
    fn test_insert_complete_p2ms_output() -> AppResult<()> {
        let db = create_analysis_test_db()?;
        seed_analysis_blocks(&db, &[100])?;
        insert_complete_p2ms_output(&db, "test_tx", 0, 100, 1000, 105)?;

        let conn = db.connection();

        // Check transaction_outputs
        let tx_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM transaction_outputs", [], |r| r.get(0))?;
        assert_eq!(tx_count, 1);

        // Check p2ms_outputs
        let p2ms_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM p2ms_outputs", [], |r| r.get(0))?;
        assert_eq!(p2ms_count, 1);

        Ok(())
    }

    #[test]
    fn test_fk_safe_classification_order() -> AppResult<()> {
        let db = create_analysis_test_db()?;

        // Follow FK-safe order
        seed_analysis_blocks(&db, &[100])?;
        insert_test_output(&db, &TestOutputParams::multisig("tx1", 0, 100, 1000, 105))?;
        insert_test_p2ms_output(&db, &TestP2msOutputParams::standard("tx1", 0))?;
        insert_test_enriched_transaction(&db, "tx1", 100)?;
        insert_test_tx_classification(&db, &TestClassificationParams::new("tx1", "BitcoinStamps"))?;
        insert_test_output_classification(
            &db,
            &TestOutputClassificationParams::unspendable("tx1", 0, "BitcoinStamps"),
        )?;

        // Verify all insertions succeeded
        let conn = db.connection();
        let class_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM p2ms_output_classifications",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(class_count, 1);

        Ok(())
    }
}
