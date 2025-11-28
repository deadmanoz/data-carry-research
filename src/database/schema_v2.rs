//! Schema Version 2 - Production-Ready Bitcoin P2MS Analysis
//!
//! ## Key Improvements Over Schema V1
//!
//! 1. **P2MS Metadata Extraction**: Multisig parameters (required_sigs, total_pubkeys)
//!    extracted to dedicated columns in `p2ms_outputs` table. Eliminates expensive
//!    `json_extract()` calls in queries (5-10x speedup).
//!
//! 2. **Spending Chain Tracking**: New columns `is_spent`, `spent_in_txid`,
//!    `spent_at_height` enable UTXO lifetime analysis, address reuse detection,
//!    and spending pattern analysis.
//!
//! 3. **Block Normalisation**: Dedicated `blocks` table with height, hash, timestamp.
//!    Enables block-level analysis and temporal queries.
//!
//! 4. **Unified Burn Patterns**: Single source of truth in `burn_patterns` table.
//!    Eliminates duplication across enriched_transactions, transaction_classifications,
//!    and classification metadata JSON.
//!
//! 5. **Classification Column Extraction**: Frequently queried classification fields
//!    (protocol_signature_found, classification_method, content_type) extracted to
//!    columns for faster queries and proper indexing.
//!
//! 6. **Spendability in Classifications**: Spendability analysis fields moved to
//!    `p2ms_output_classifications` where they semantically belong (computed during
//!    classification, not structural data).
//!
//! 7. **Clear Semantics**: `is_spent` replaces `is_utxo` for clearer meaning
//!    (0 = unspent/UTXO, 1 = spent).
//!
//! ## Stage Population Strategy
//!
//! - **Stage 1**: Stub blocks + transaction_outputs + p2ms_outputs (P2MS only)
//! - **Stage 2**: Enrich transactions (all outputs, inputs, burn patterns) + backfill block info
//! - **Stage 3**: Classify protocols + compute spendability

use crate::errors::{AppError, AppResult};
use rusqlite::Connection;
use tracing::debug;

/// Initialise the complete Schema V2 for all stages
pub fn setup_schema_v2(connection: &Connection) -> AppResult<()> {
    connection
        .execute_batch(
            r#"
        -- ═══════════════════════════════════════════════════════════════════════════
        -- SCHEMA VERSION 2 - Production-Ready Bitcoin P2MS Analysis
        -- ═══════════════════════════════════════════════════════════════════════════

        PRAGMA user_version = 2;
        PRAGMA foreign_keys = ON;

        -- ═══════════════════════════════════════════════════════════════════════════
        -- PHASE 1: Foundation Tables (No Foreign Keys)
        -- ═══════════════════════════════════════════════════════════════════════════

        -- BLOCKS TABLE
        -- Stage 1: Inserts stub rows (height only, NULL hash/timestamp)
        -- Stage 2: Backfills hash/timestamp via RPC during batch processing
        CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY,
            block_hash TEXT UNIQUE,           -- NULLABLE until Stage 2 backfill
            timestamp INTEGER,                -- NULLABLE until Stage 2 backfill
            fetched_at INTEGER DEFAULT (strftime('%s', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(block_hash)
            WHERE block_hash IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_blocks_timestamp ON blocks(timestamp)
            WHERE timestamp IS NOT NULL;
        -- Covering index for stamps weekly fee analysis (JOIN on height with timestamp SELECT)
        CREATE INDEX IF NOT EXISTS idx_blocks_height_timestamp ON blocks(height, timestamp)
            WHERE timestamp IS NOT NULL;

        -- PROCESSING CHECKPOINTS
        CREATE TABLE IF NOT EXISTS processing_checkpoints (
            id INTEGER PRIMARY KEY,
            stage TEXT NOT NULL,
            last_processed_count INTEGER NOT NULL,
            total_processed INTEGER NOT NULL,
            csv_line_number INTEGER,
            batch_number INTEGER DEFAULT 0,
            state_json TEXT DEFAULT '{}',
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            updated_at INTEGER DEFAULT (strftime('%s', 'now'))
        );

        -- ═══════════════════════════════════════════════════════════════════════════
        -- PHASE 2: Core Transaction Tables
        -- ═══════════════════════════════════════════════════════════════════════════

        -- ENRICHED TRANSACTIONS
        -- Stage 2B: Populated during transaction fetching
        CREATE TABLE IF NOT EXISTS enriched_transactions (
            txid TEXT PRIMARY KEY,
            height INTEGER NOT NULL,

            -- Fee analysis
            total_input_value INTEGER NOT NULL,
            total_output_value INTEGER NOT NULL,
            transaction_fee INTEGER NOT NULL,
            fee_per_byte REAL NOT NULL,
            transaction_size_bytes INTEGER NOT NULL,
            fee_per_kb REAL NOT NULL,

            -- P2MS specific
            total_p2ms_amount INTEGER NOT NULL,
            data_storage_fee_rate REAL NOT NULL,
            p2ms_outputs_count INTEGER NOT NULL,

            -- Transaction metadata
            input_count INTEGER NOT NULL,
            output_count INTEGER NOT NULL,
            is_coinbase BOOLEAN NOT NULL,

            created_at INTEGER DEFAULT (strftime('%s', 'now'))
            -- NOTE: No FK to blocks(height) - enriched_transactions are created before block backfill
        );

        CREATE INDEX IF NOT EXISTS idx_enriched_txid ON enriched_transactions(txid);
        CREATE INDEX IF NOT EXISTS idx_enriched_height ON enriched_transactions(height);
        CREATE INDEX IF NOT EXISTS idx_enriched_fee_rate ON enriched_transactions(data_storage_fee_rate);
        CREATE INDEX IF NOT EXISTS idx_enriched_coinbase ON enriched_transactions(is_coinbase);
        CREATE INDEX IF NOT EXISTS idx_enriched_transactions_classification_lookup
            ON enriched_transactions(txid, height);
        CREATE INDEX IF NOT EXISTS idx_enriched_height_txid
            ON enriched_transactions(height, txid);
        -- Covering index for stamps weekly fee analysis (JOIN + filter + SELECT)
        CREATE INDEX IF NOT EXISTS idx_enriched_fee_analysis
            ON enriched_transactions(txid, height, is_coinbase, transaction_fee)
            WHERE is_coinbase = 0;
        -- Covering index for tx_size_analysis (global + per-protocol queries)
        -- Partial index on P2MS non-coinbase transactions, covering size/fee columns
        CREATE INDEX IF NOT EXISTS idx_enriched_tx_size_analysis
            ON enriched_transactions(transaction_size_bytes, transaction_fee)
            WHERE p2ms_outputs_count > 0 AND is_coinbase = 0;

        -- TRANSACTION OUTPUTS (All Types)
        -- Stage 1: P2MS outputs only (from UTXO dump)
        -- Stage 2B: All outputs for P2MS-containing transactions (via RPC)
        -- Stage 2C: Updates is_spent, spent_in_txid, spent_at_height
        CREATE TABLE IF NOT EXISTS transaction_outputs (
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            height INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            script_hex TEXT NOT NULL,
            script_type TEXT NOT NULL,        -- 'multisig', 'p2pkh', 'op_return', etc.
            script_size INTEGER NOT NULL,
            is_coinbase BOOLEAN NOT NULL,

            -- Spending tracking (is_spent replaces is_utxo)
            is_spent BOOLEAN NOT NULL DEFAULT 0,  -- 0 = UTXO (unspent), 1 = spent
            spent_in_txid TEXT,                   -- Which transaction spent this output
            spent_at_height INTEGER,              -- Height where spent

            -- Address (optional - NULL for OP_RETURN, unspendable)
            address TEXT,

            -- Script metadata (JSON for multisig, op_return, etc.)
            metadata_json TEXT,

            created_at INTEGER DEFAULT (strftime('%s', 'now')),

            PRIMARY KEY (txid, vout),
            FOREIGN KEY (height) REFERENCES blocks(height),
            FOREIGN KEY (spent_at_height) REFERENCES blocks(height)
            -- NOTE: spent_in_txid has NO FK (circular dependency, application logic maintains integrity)
        );

        CREATE INDEX IF NOT EXISTS idx_outputs_height ON transaction_outputs(height);
        CREATE INDEX IF NOT EXISTS idx_outputs_txid ON transaction_outputs(txid);
        CREATE INDEX IF NOT EXISTS idx_outputs_script_type ON transaction_outputs(script_type);
        CREATE INDEX IF NOT EXISTS idx_outputs_address ON transaction_outputs(address)
            WHERE address IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_outputs_unspent ON transaction_outputs(is_spent)
            WHERE is_spent = 0;  -- CRITICAL: UTXO set index
        CREATE INDEX IF NOT EXISTS idx_outputs_height_txid ON transaction_outputs(height, txid);
        CREATE INDEX IF NOT EXISTS idx_outputs_stage2_queue
            ON transaction_outputs(script_type, height, txid)
            WHERE script_type = 'multisig';
        CREATE INDEX IF NOT EXISTS idx_outputs_spent_at_height ON transaction_outputs(spent_at_height)
            WHERE spent_at_height IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_outputs_txid_multisig_unspent
            ON transaction_outputs(txid, script_type, is_spent)
            WHERE script_type = 'multisig' AND is_spent = 0;
        -- Covering index for stamps weekly fee analysis (CTE 2 JOIN + SUM)
        CREATE INDEX IF NOT EXISTS idx_outputs_fee_analysis
            ON transaction_outputs(txid, vout, script_type, script_size)
            WHERE script_type = 'multisig';

        -- ═══════════════════════════════════════════════════════════════════════════
        -- PHASE 3: P2MS Specific Tables
        -- ═══════════════════════════════════════════════════════════════════════════

        -- P2MS OUTPUTS (Extracted Metadata)
        -- Stage 1: Populated with multisig parameters extracted from script
        CREATE TABLE IF NOT EXISTS p2ms_outputs (
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,

            -- Multisig parameters (EXTRACTED - eliminates json_extract() in queries)
            required_sigs INTEGER NOT NULL,   -- M in M-of-N
            total_pubkeys INTEGER NOT NULL,   -- N in M-of-N
            pubkeys_json TEXT NOT NULL,       -- JSON array of hex pubkeys (variable length)

            PRIMARY KEY (txid, vout),
            FOREIGN KEY (txid, vout) REFERENCES transaction_outputs(txid, vout) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_p2ms_multisig_type ON p2ms_outputs(required_sigs, total_pubkeys);

        -- TRANSACTION INPUTS
        -- Stage 2B: Populated during transaction fetching
        CREATE TABLE IF NOT EXISTS transaction_inputs (
            txid TEXT NOT NULL,
            input_index INTEGER NOT NULL,
            prev_txid TEXT NOT NULL,
            prev_vout INTEGER NOT NULL,
            value INTEGER NOT NULL,
            script_sig TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            source_address TEXT,

            PRIMARY KEY (txid, input_index),
            FOREIGN KEY (txid) REFERENCES enriched_transactions(txid) ON DELETE CASCADE
            -- NOTE: No FK to transaction_outputs(prev_txid, prev_vout) - Stage 2 processes
            -- transactions in arbitrary order based on UTXO dump, so prev outputs may not
            -- exist in database yet. Data integrity maintained via stored value+source_address.
        );

        CREATE INDEX IF NOT EXISTS idx_inputs_txid ON transaction_inputs(txid);
        CREATE INDEX IF NOT EXISTS idx_inputs_prev_output ON transaction_inputs(prev_txid, prev_vout);

        -- BURN PATTERNS (Unified - Single Source of Truth)
        -- Stage 2B: Populated during burn pattern detection
        CREATE TABLE IF NOT EXISTS burn_patterns (
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            pubkey_index INTEGER NOT NULL,
            pattern_type TEXT NOT NULL,
            pattern_data TEXT NOT NULL,
            confidence TEXT NOT NULL,

            PRIMARY KEY (txid, vout, pubkey_index, pattern_type),
            FOREIGN KEY (txid) REFERENCES enriched_transactions(txid) ON DELETE CASCADE,
            FOREIGN KEY (txid, vout) REFERENCES p2ms_outputs(txid, vout) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_burn_txid ON burn_patterns(txid);
        CREATE INDEX IF NOT EXISTS idx_burn_type ON burn_patterns(pattern_type);
        CREATE INDEX IF NOT EXISTS idx_burn_confidence ON burn_patterns(confidence);

        -- ═══════════════════════════════════════════════════════════════════════════
        -- PHASE 4: Classification Tables
        -- ═══════════════════════════════════════════════════════════════════════════

        -- TRANSACTION CLASSIFICATIONS
        -- Stage 3: Populated with extracted classification columns
        CREATE TABLE IF NOT EXISTS transaction_classifications (
            txid TEXT PRIMARY KEY,
            protocol TEXT NOT NULL,
            variant TEXT,

            -- Extracted classification fields (no more JSON extraction in queries!)
            protocol_signature_found BOOLEAN NOT NULL DEFAULT 0,
            classification_method TEXT NOT NULL,
            content_type TEXT,
            transport_protocol TEXT,

            -- Minimal JSON for protocol-specific extras only
            additional_metadata_json TEXT,

            classification_timestamp INTEGER DEFAULT (strftime('%s', 'now')),

            FOREIGN KEY (txid) REFERENCES enriched_transactions(txid) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_tc_protocol ON transaction_classifications(protocol);
        CREATE INDEX IF NOT EXISTS idx_tc_variant ON transaction_classifications(variant);
        CREATE INDEX IF NOT EXISTS idx_tc_signature_found ON transaction_classifications(protocol_signature_found);
        CREATE INDEX IF NOT EXISTS idx_tc_content_type ON transaction_classifications(content_type);
        CREATE INDEX IF NOT EXISTS idx_tc_transport ON transaction_classifications(transport_protocol);
        -- Covering index for stamps weekly fee analysis (CTE 1 JOIN)
        CREATE INDEX IF NOT EXISTS idx_tc_protocol_txid ON transaction_classifications(protocol, txid);

        -- P2MS OUTPUT CLASSIFICATIONS
        -- Stage 3: Populated with protocol classification AND spendability analysis
        CREATE TABLE IF NOT EXISTS p2ms_output_classifications (
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            variant TEXT,                         -- NULLABLE: Many protocols have no variant

            -- Classification fields (extracted from JSON)
            protocol_signature_found BOOLEAN NOT NULL DEFAULT 0,
            classification_method TEXT NOT NULL,
            content_type TEXT,

            -- Spendability analysis (computed during classification, NOT in p2ms_outputs)
            is_spendable BOOLEAN NOT NULL DEFAULT 1,
            spendability_reason TEXT,
            real_pubkey_count INTEGER NOT NULL DEFAULT 0,
            burn_key_count INTEGER NOT NULL DEFAULT 0,
            data_key_count INTEGER NOT NULL DEFAULT 0,

            -- Minimal JSON for protocol-specific extras only
            additional_metadata_json TEXT,

            classification_timestamp INTEGER DEFAULT (strftime('%s', 'now')),

            -- PRIMARY KEY without variant (allows NULL variants)
            -- One classification per (output, protocol) - variant is metadata
            PRIMARY KEY (txid, vout, protocol),
            FOREIGN KEY (txid, vout) REFERENCES p2ms_outputs(txid, vout) ON DELETE CASCADE,
            FOREIGN KEY (txid) REFERENCES transaction_classifications(txid) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_poc_protocol ON p2ms_output_classifications(protocol);
        CREATE INDEX IF NOT EXISTS idx_poc_variant ON p2ms_output_classifications(variant);
        CREATE INDEX IF NOT EXISTS idx_poc_content_type ON p2ms_output_classifications(content_type);
        CREATE INDEX IF NOT EXISTS idx_poc_spendable ON p2ms_output_classifications(is_spendable);
        -- Covering index for stamps weekly fee analysis (CTE 2 txid lookup + vout JOIN)
        CREATE INDEX IF NOT EXISTS idx_poc_txid_vout ON p2ms_output_classifications(txid, vout);

        -- ═══════════════════════════════════════════════════════════════════════════
        -- PHASE 5: Triggers (After All Tables Exist)
        -- ═══════════════════════════════════════════════════════════════════════════

        -- TRIGGER 1: Enforce P2MS Script Type
        -- Prevents inserting into p2ms_outputs unless corresponding transaction_outputs
        -- row exists with script_type='multisig'
        CREATE TRIGGER IF NOT EXISTS enforce_p2ms_script_type
        BEFORE INSERT ON p2ms_outputs
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'P2MS output must reference multisig script_type')
            WHERE NOT EXISTS (
                SELECT 1 FROM transaction_outputs
                WHERE txid = NEW.txid
                  AND vout = NEW.vout
                  AND script_type = 'multisig'
            );
        END;

        -- TRIGGER 2: Enforce P2MS-Only Classification
        -- Prevents classifying non-P2MS outputs
        -- Updated from Schema V1 to reference p2ms_outputs table (cleaner)
        CREATE TRIGGER IF NOT EXISTS enforce_p2ms_only_classification
        BEFORE INSERT ON p2ms_output_classifications
        FOR EACH ROW
        BEGIN
            SELECT RAISE(ABORT, 'Classification violation: Output is not a P2MS output')
            WHERE NOT EXISTS (
                SELECT 1 FROM p2ms_outputs
                WHERE txid = NEW.txid AND vout = NEW.vout
            );
        END;
        "#,
        )
        .map_err(AppError::Database)?;

    debug!("Schema V2 initialised with all tables, indexes, and triggers");
    Ok(())
}
