//! Database Seeding Helpers for Test Data Insertion
//!
//! This module provides FK-safe helpers for seeding test databases with transaction data.
//! All helpers follow the critical FK-safe seeding order from CLAUDE.md:
//!
//! 1. Stub blocks table (enables FK constraints)
//! 2. Transaction outputs (parent for burn_patterns)
//! 3. Enriched transactions (includes burn_patterns via batch insert)
//! 4. Transaction classifications (parent for output classifications)
//! 5. Output classifications (child)
//!
//! ## Key Principle
//!
//! **ALWAYS use `insert_enriched_transactions_batch()` with ALL outputs** (both P2MS and others)
//! as the third parameter. This ensures FK-safe insertion order automatically.
//!
//! ## Anti-Pattern (DO NOT USE)
//!
//! ```rust,ignore
//! // ❌ OLD PATTERN - causes FK violations
//! test_db.database_mut().insert_p2ms_batch(&p2ms_outputs)?;
//! test_db.database_mut()
//!     .insert_enriched_transactions_batch(&[(tx, inputs, Vec::new())])?;
//! ```
//!
//! ## Correct Pattern
//!
//! ```rust,ignore
//! // ✅ NEW PATTERN - FK-safe
//! test_db.database_mut()
//!     .insert_enriched_transactions_batch(&[(tx, inputs, p2ms_outputs.clone())])?;
//! ```

use crate::common::database::TestDatabase;
use data_carry_research::database::traits::{Stage1Operations, Stage2Operations};
use data_carry_research::types::{EnrichedTransaction, TransactionInput, TransactionOutput};

/// Seed a test database with an enriched transaction containing only P2MS outputs
///
/// This is the most common pattern for protocol tests (Stamps, Counterparty, Omni).
/// Handles FK-safe insertion automatically.
///
/// # Arguments
/// * `test_db` - Test database instance
/// * `tx` - Enriched transaction (should have tx.outputs populated with P2MS)
/// * `inputs` - Transaction inputs (use `create_test_inputs()` helper)
///
/// # Example
/// ```rust,ignore
/// use crate::common::db_seeding::{seed_enriched_transaction, create_test_inputs};
///
/// let tx = fixtures::create_test_enriched_transaction(txid);
/// let inputs = create_test_inputs(txid, "input_txid_here");
///
/// seed_enriched_transaction(&mut test_db, &tx, inputs)?;
/// ```
pub fn seed_enriched_transaction(
    test_db: &mut TestDatabase,
    tx: &EnrichedTransaction,
    inputs: Vec<TransactionInput>,
) -> anyhow::Result<()> {
    // Stage 1 always runs before Stage 2 in production, so seed the multisig outputs here
    // to ensure they are marked as unspent (is_spent = 0) before the Stage 2 UPSERT.
    if !tx.outputs.is_empty() {
        test_db
            .database_mut()
            .insert_transaction_output_batch(&tx.outputs)?;
    }

    // Pass tx.outputs as the third parameter for FK-safe insertion
    test_db
        .database_mut()
        .insert_enriched_transactions_batch(&[(tx.clone(), inputs, tx.outputs.clone())])?;

    Ok(())
}

/// Seed a test database with an enriched transaction containing P2MS + other outputs
///
/// Use this when the transaction has both P2MS outputs AND other output types
/// (e.g., OP_RETURN for OpReturnSignalled protocols).
///
/// # Arguments
/// * `test_db` - Test database instance
/// * `tx` - Enriched transaction
/// * `inputs` - Transaction inputs
/// * `p2ms_outputs` - P2MS outputs (will be added to tx.outputs)
/// * `other_outputs` - Non-P2MS outputs (OP_RETURN, P2PKH, etc.)
///
/// # Example
/// ```rust,ignore
/// use crate::common::db_seeding::{seed_enriched_transaction_with_outputs, create_test_inputs};
///
/// let tx = fixtures::create_test_enriched_transaction(txid);
/// let inputs = create_test_inputs(txid, "input_txid_here");
/// let p2ms_outputs = load_p2ms_outputs_from_json(fixture_path, txid)?;
/// let op_return_outputs = extract_op_returns(&json_value, txid)?;
///
/// seed_enriched_transaction_with_outputs(
///     &mut test_db,
///     &tx,
///     inputs,
///     p2ms_outputs,
///     op_return_outputs,
/// )?;
/// ```
pub fn seed_enriched_transaction_with_outputs(
    test_db: &mut TestDatabase,
    tx: &EnrichedTransaction,
    inputs: Vec<TransactionInput>,
    p2ms_outputs: Vec<TransactionOutput>,
    other_outputs: Vec<TransactionOutput>,
) -> anyhow::Result<()> {
    // Seed Stage 1 data first so P2MS outputs retain is_spent = 0 when Stage 2 runs
    if !p2ms_outputs.is_empty() {
        test_db
            .database_mut()
            .insert_transaction_output_batch(&p2ms_outputs)?;
    }

    // Combine all outputs for FK-safe insertion
    let mut all_outputs = p2ms_outputs;
    all_outputs.extend(other_outputs);

    test_db
        .database_mut()
        .insert_enriched_transactions_batch(&[(tx.clone(), inputs, all_outputs)])?;

    Ok(())
}

/// Create standard test transaction inputs
///
/// Generates transaction inputs for testing with realistic-looking data.
///
/// # Arguments
/// * `txid` - Transaction ID these inputs belong to
/// * `source_txid` - TXID of the input transaction (used for deobfuscation)
///
/// # Returns
/// Vector of transaction inputs (single input with standard test values)
///
/// # Example
/// ```rust,ignore
/// use crate::common::db_seeding::create_test_inputs;
///
/// let inputs = create_test_inputs(txid, "source_txid_for_deobfuscation");
/// ```
pub fn create_test_inputs(txid: &str, source_txid: &str) -> Vec<TransactionInput> {
    vec![TransactionInput {
        txid: source_txid.to_string(),
        vout: 0,
        value: 10000,
        script_sig: "test_script_sig".to_string(),
        sequence: 0xffffffff,
        source_address: Some(format!("1Test{}Address", &txid[..8])),
    }]
}

/// Create test transaction inputs with custom parameters
///
/// Allows full control over input parameters for specialized tests.
///
/// # Arguments
/// * `source_txid` - TXID of the input transaction
/// * `vout` - Output index being spent
/// * `value` - Value in satoshis
/// * `source_address` - Optional source address
///
/// # Example
/// ```rust,ignore
/// use crate::common::db_seeding::create_custom_test_input;
///
/// let inputs = vec![create_custom_test_input(
///     "input_txid_here",
///     0,
///     50000,
///     Some("1CounterpartyAddress123"),
/// )];
/// ```
pub fn create_custom_test_input(
    source_txid: &str,
    vout: u32,
    value: u64,
    source_address: Option<&str>,
) -> TransactionInput {
    TransactionInput {
        txid: source_txid.to_string(),
        vout,
        value,
        script_sig: "test_script_sig".to_string(),
        sequence: 0xffffffff,
        source_address: source_address.map(|s| s.to_string()),
    }
}

/// Build and seed an enriched transaction from P2MS outputs loaded from JSON
///
/// This is a convenience helper that combines common operations:
/// - Builds enriched transaction from fixture data
/// - Calculates total P2MS amount
/// - Seeds the database in FK-safe order
///
/// # Arguments
/// * `test_db` - Test database instance
/// * `txid` - Transaction ID
/// * `p2ms_outputs` - P2MS outputs (typically from `load_p2ms_outputs_from_json`)
/// * `source_txid` - Input TXID for deobfuscation
///
/// # Returns
/// The enriched transaction that was seeded
///
/// # Example
/// ```rust,ignore
/// use crate::common::db_seeding::build_and_seed_from_p2ms;
/// use crate::common::protocol_test_base::load_p2ms_outputs_from_json;
///
/// let p2ms_outputs = load_p2ms_outputs_from_json(fixture_path, txid)?;
/// let tx = build_and_seed_from_p2ms(
///     &mut test_db,
///     txid,
///     p2ms_outputs,
///     "input_txid_here",
/// )?;
/// ```
pub fn build_and_seed_from_p2ms(
    test_db: &mut TestDatabase,
    txid: &str,
    p2ms_outputs: Vec<TransactionOutput>,
    source_txid: &str,
) -> anyhow::Result<EnrichedTransaction> {
    use crate::common::fixtures;

    // Build enriched transaction with P2MS outputs
    let mut tx = fixtures::create_test_enriched_transaction(txid);
    let total_p2ms_amount: u64 = p2ms_outputs.iter().map(|o| o.amount).sum();
    tx.outputs = p2ms_outputs.clone();
    tx.p2ms_outputs_count = p2ms_outputs.len();
    tx.total_p2ms_amount = total_p2ms_amount;

    // Create inputs
    let inputs = create_test_inputs(txid, source_txid);

    // Seed database (FK-safe)
    seed_enriched_transaction(test_db, &tx, inputs)?;

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::fixtures;

    #[test]
    fn test_create_test_inputs() {
        let inputs = create_test_inputs("test_txid_12345678", "source_txid");

        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].txid, "source_txid");
        assert_eq!(inputs[0].vout, 0);
        assert_eq!(inputs[0].value, 10000);
        assert!(inputs[0].source_address.is_some());
    }

    #[test]
    fn test_create_custom_test_input() {
        let input = create_custom_test_input("input_tx", 5, 25000, Some("1Address"));

        assert_eq!(input.txid, "input_tx");
        assert_eq!(input.vout, 5);
        assert_eq!(input.value, 25000);
        assert_eq!(input.source_address, Some("1Address".to_string()));
    }

    #[test]
    fn test_seed_enriched_transaction() -> anyhow::Result<()> {
        let mut test_db = TestDatabase::new("seed_simple_test")?;
        let txid = "test_tx_123";

        // Create test transaction with P2MS outputs
        let mut tx = fixtures::create_test_enriched_transaction(txid);
        let p2ms_output = fixtures::create_test_p2ms_output(txid, 0, "5221deadbeef21aebeef52ae");
        tx.outputs = vec![p2ms_output];
        tx.p2ms_outputs_count = 1;

        let inputs = create_test_inputs(txid, "input_tx");

        // Seed database
        seed_enriched_transaction(&mut test_db, &tx, inputs)?;

        // Verify insertion succeeded (query transaction_outputs table directly)
        use rusqlite::params;
        let count: i64 = test_db.database().connection().query_row(
            "SELECT COUNT(*) FROM transaction_outputs WHERE txid = ?1",
            params![txid],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1, "Should have inserted 1 P2MS output");

        Ok(())
    }
}
