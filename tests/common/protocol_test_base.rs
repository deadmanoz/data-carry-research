//! Protocol Test Base Module
//!
//! This module provides standardised utilities for protocol classification tests,
//! eliminating code duplication and ensuring consistent test patterns across
//! all protocol test files (Counterparty, Omni Layer, Bitcoin Stamps, Data Storage).

use anyhow::Result;
use data_carry_research::database::Database;
use data_carry_research::processor::stage3::Stage3Processor;
use data_carry_research::types::{
    burn_patterns::BurnPattern, ClassificationDetails, EnrichedTransaction, ProtocolType,
    ProtocolVariant, Stage3Config, TransactionInput, TransactionOutput,
};
use rusqlite::Connection;
use serde_json;
use std::fs;

use super::database::TestDatabase;
use super::db_seeding::seed_enriched_transaction;
use super::fixture_registry::ProtocolFixture;
use super::fixtures;

/// Standard protocol test configuration factory
///
/// Creates a consistent Stage3Config for all protocol tests with:
/// - Small batch size for testing (10)
/// - No height filtering (signature-based detection only)
pub fn create_protocol_test_config(db_path: &str) -> Stage3Config {
    Stage3Config {
        database_path: db_path.into(),
        batch_size: 10,
        progress_interval: 1000,
    }
}

/// Standard protocol test setup
///
/// Returns a TestDatabase with automatic cleanup and a standard config.
/// Use this for all protocol tests to ensure consistency.
pub fn setup_protocol_test(test_name: &str) -> Result<(TestDatabase, Stage3Config)> {
    let test_db = TestDatabase::new(test_name)?;

    // Insert stub blocks for common test heights (FK constraint satisfaction)
    // Height 0: Most protocol tests
    // Height 330000: Chancecoin, ASCII identifier protocols
    // Height 400000: Legitimate P2MS tests and others
    let conn = test_db.database().connection();
    conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (0)", [])?;
    conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (330000)", [])?;
    conn.execute("INSERT OR IGNORE INTO blocks (height) VALUES (400000)", [])?;

    let config = create_protocol_test_config(test_db.path());
    Ok((test_db, config))
}

/// Standard classification verification helper
///
/// Verifies that a transaction was classified correctly in the database.
pub fn verify_classification(
    test_db: &TestDatabase,
    txid: &str,
    expected_protocol: ProtocolType,
    expected_variant: Option<ProtocolVariant>,
) -> Result<ClassificationDetails> {
    let conn = Connection::open(test_db.path())?;

    let query_result = conn.query_row(
        "SELECT protocol, variant, additional_metadata_json
         FROM transaction_classifications WHERE txid = ?1",
        [txid],
        |row| {
            let protocol_str: String = row.get(0)?;
            let variant_str: Option<String> = row.get(1)?;
            let metadata_json: String = row.get(2)?;
            Ok((protocol_str, variant_str, metadata_json))
        },
    )?;

    let (protocol_str, variant_str, metadata_json) = query_result;

    // Verify protocol type
    let actual_protocol = match protocol_str.as_str() {
        "Counterparty" => ProtocolType::Counterparty,
        "AsciiIdentifierProtocols" => ProtocolType::AsciiIdentifierProtocols,
        "OmniLayer" => ProtocolType::OmniLayer,
        "BitcoinStamps" => ProtocolType::BitcoinStamps,
        "Chancecoin" => ProtocolType::Chancecoin,
        "PPk" => ProtocolType::PPk,
        "OpReturnSignalled" => ProtocolType::OpReturnSignalled,
        "DataStorage" => ProtocolType::DataStorage,
        "LikelyDataStorage" => ProtocolType::LikelyDataStorage,
        "LikelyLegitimateMultisig" => ProtocolType::LikelyLegitimateMultisig,
        "Unknown" => ProtocolType::Unknown,
        _ => return Err(anyhow::anyhow!("Unknown protocol type: {}", protocol_str)),
    };

    assert_eq!(
        actual_protocol, expected_protocol,
        "Protocol mismatch for txid {}: expected {:?}, got {:?}",
        txid, expected_protocol, actual_protocol
    );

    // Verify variant if specified
    if let Some(expected_var) = expected_variant {
        match variant_str {
            Some(var_str) => {
                let actual_variant = match var_str.as_str() {
                    // Counterparty variants (Display strings)
                    // Guard all variants with actual_protocol check to prevent collisions
                    "Transfer" if actual_protocol == ProtocolType::Counterparty => {
                        ProtocolVariant::CounterpartyTransfer
                    }
                    "Issuance" if actual_protocol == ProtocolType::Counterparty => {
                        ProtocolVariant::CounterpartyIssuance
                    }
                    "Destruction" if actual_protocol == ProtocolType::Counterparty => {
                        ProtocolVariant::CounterpartyDestruction
                    }
                    "Oracle" if actual_protocol == ProtocolType::Counterparty => {
                        ProtocolVariant::CounterpartyOracle
                    }
                    "Gaming" if actual_protocol == ProtocolType::Counterparty => {
                        ProtocolVariant::CounterpartyGaming
                    }
                    "Utility" if actual_protocol == ProtocolType::Counterparty => {
                        ProtocolVariant::CounterpartyUtility
                    }
                    "DEX" if actual_protocol == ProtocolType::Counterparty => {
                        ProtocolVariant::CounterpartyDEX
                    }
                    // AsciiIdentifierProtocols variants (Display strings)
                    "TB0001" => ProtocolVariant::AsciiIdentifierTB0001,
                    "TEST01" => ProtocolVariant::AsciiIdentifierTEST01,
                    "Metronotes" => ProtocolVariant::AsciiIdentifierMetronotes,
                    "Other ASCII Protocol" => ProtocolVariant::AsciiIdentifierOther,
                    "Unknown Variant" => ProtocolVariant::AsciiIdentifierUnknown,
                    // Omni Layer variants (Display strings)
                    "Transfer" => ProtocolVariant::OmniTransfer,
                    "Distribution" => ProtocolVariant::OmniDistribution,
                    "Issuance" => ProtocolVariant::OmniIssuance,
                    "Destruction" => ProtocolVariant::OmniDestruction,
                    "DEX" => ProtocolVariant::OmniDEX,
                    "Administration" => ProtocolVariant::OmniAdministration,
                    "Utility" => ProtocolVariant::OmniUtility,
                    "Failed Deobfuscation" => ProtocolVariant::OmniFailedDeobfuscation,
                    // Bitcoin Stamps variants (Display strings)
                    "Classic" => ProtocolVariant::StampsClassic,
                    "SRC-20" => ProtocolVariant::StampsSRC20,
                    "SRC-721" => ProtocolVariant::StampsSRC721,
                    "SRC-101" => ProtocolVariant::StampsSRC101,
                    "HTML" => ProtocolVariant::StampsHTML,
                    "Compressed" => ProtocolVariant::StampsCompressed,
                    "Data" => ProtocolVariant::StampsData,
                    "Unknown"
                        if matches!(
                            expected_var,
                            ProtocolVariant::StampsUnknown | ProtocolVariant::ChancecoinUnknown
                        ) =>
                    {
                        if matches!(expected_var, ProtocolVariant::StampsUnknown) {
                            ProtocolVariant::StampsUnknown
                        } else {
                            ProtocolVariant::ChancecoinUnknown
                        }
                    }
                    // Chancecoin variants (Display strings)
                    "Send" if matches!(expected_var, ProtocolVariant::ChancecoinSend) => {
                        ProtocolVariant::ChancecoinSend
                    }
                    "Order" => ProtocolVariant::ChancecoinOrder,
                    "BTCPay" => ProtocolVariant::ChancecoinBTCPay,
                    "Roll" => ProtocolVariant::ChancecoinRoll,
                    "Bet" => ProtocolVariant::ChancecoinBet,
                    "Cancel" => ProtocolVariant::ChancecoinCancel,
                    // PPk protocol variants (Display strings)
                    "PPkProfile" => ProtocolVariant::PPkProfile,
                    "PPkRegistration" => ProtocolVariant::PPkRegistration,
                    "PPkMessage" => ProtocolVariant::PPkMessage,
                    "PPkUnknown" => ProtocolVariant::PPkUnknown,
                    // OP_RETURN-signalled variants (Display strings)
                    "Protocol47930" => ProtocolVariant::OpReturnProtocol47930,
                    "CLIPPERZ" => ProtocolVariant::OpReturnCLIPPERZ,
                    "GenericASCII" => ProtocolVariant::OpReturnGenericASCII,
                    // LikelyDataStorage variants (Display strings)
                    "Invalid EC Point" => ProtocolVariant::LikelyDataStorageInvalidECPoint,
                    "High Output Count" => ProtocolVariant::LikelyDataStorageHighOutputCount,
                    "Dust Amount" => ProtocolVariant::LikelyDataStorageDustAmount,
                    // LikelyLegitimateMultisig variants (Display strings)
                    "Legitimate Multisig"
                        if !var_str.contains("Duplicate") && !var_str.contains("Null") =>
                    {
                        ProtocolVariant::LegitimateMultisig
                    }
                    "Legitimate Multisig (Duplicate Keys)" => {
                        ProtocolVariant::LegitimateMultisigDupeKeys
                    }
                    "Legitimate Multisig (Null-Padded)" => {
                        ProtocolVariant::LegitimateMultisigWithNullKey
                    }
                    // DataStorage variants (Display strings)
                    "Proof of Burn" => ProtocolVariant::DataStorageProofOfBurn,
                    "File Metadata" => ProtocolVariant::DataStorageFileMetadata,
                    "Embedded Data" => ProtocolVariant::DataStorageEmbeddedData,
                    "WikiLeaks Cablegate" => ProtocolVariant::DataStorageWikiLeaksCablegate,
                    "Null Data" => ProtocolVariant::DataStorageNullData,
                    "Generic" => ProtocolVariant::DataStorageGeneric,
                    _ => return Err(anyhow::anyhow!("Unknown protocol variant: {}", var_str)),
                };
                assert_eq!(
                    actual_variant, expected_var,
                    "Variant mismatch for txid {}: expected {:?}, got {:?}",
                    txid, expected_var, actual_variant
                );
            }
            None => {
                return Err(anyhow::anyhow!(
                    "Expected variant {:?} but got None for txid {}",
                    expected_var,
                    txid
                ))
            }
        }
    }

    // Parse and return classification details
    let details: ClassificationDetails = serde_json::from_str(&metadata_json)?;
    Ok(details)
}

/// Verify content type in transaction_classifications table
///
/// Uses the existing Database connection (via test_db.db.connection()) to query
/// the content_type field for a given transaction.
///
/// # Arguments
/// * `test_db` - Test database wrapper
/// * `txid` - Transaction ID to check
/// * `expected_content_type` - Expected MIME type (e.g., "image/png", "application/octet-stream") or None
pub fn verify_content_type(
    test_db: &TestDatabase,
    txid: &str,
    expected_content_type: Option<&str>,
) -> Result<()> {
    // Use the existing Database connection (not Connection::open)
    let conn = test_db.db.connection();

    let actual: Option<String> = conn.query_row(
        "SELECT content_type FROM transaction_classifications WHERE txid = ?1",
        [txid],
        |row| row.get(0),
    )?;

    assert_eq!(
        actual.as_deref(),
        expected_content_type,
        "Content type mismatch for txid {}",
        txid
    );
    Ok(())
}

/// Get classification metadata for a transaction
///
/// Returns the full ClassificationDetails for detailed inspection.
/// Use this when you need to examine specific protocol metadata.
pub fn get_classification_metadata(
    test_db: &TestDatabase,
    txid: &str,
) -> Result<ClassificationDetails> {
    let conn = Connection::open(test_db.path())?;

    let metadata_json: String = conn.query_row(
        "SELECT additional_metadata_json FROM transaction_classifications WHERE txid = ?1",
        [txid],
        |row| row.get(0),
    )?;

    let details: ClassificationDetails = serde_json::from_str(&metadata_json)?;
    Ok(details)
}

/// Standard JSON fixture loader for protocol tests
///
/// Loads P2MS outputs from JSON transaction data with consistent error handling.
/// Supports both raw Bitcoin Core RPC format and test fixture format.
pub fn load_p2ms_outputs_from_json(json_path: &str, txid: &str) -> Result<Vec<TransactionOutput>> {
    let content = fs::read_to_string(json_path)
        .map_err(|e| anyhow::anyhow!("Failed to read JSON file {}: {}", json_path, e))?;

    let tx: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse JSON from {}: {}", json_path, e))?;

    let mut outputs = Vec::new();

    if let Some(vouts) = tx["vout"].as_array() {
        for vout in vouts {
            if let (Some(spk), Some(n), Some(val)) = (
                vout.get("scriptPubKey"),
                vout.get("n").and_then(|x| x.as_u64()),
                vout.get("value").and_then(|x| x.as_f64()),
            ) {
                // Handle both standard "multisig" type and "nonstandard" P2MS outputs
                let is_multisig =
                    spk.get("type") == Some(&serde_json::Value::String("multisig".into()));
                let is_nonstandard_multisig = spk.get("type")
                    == Some(&serde_json::Value::String("nonstandard".into()))
                    && spk
                        .get("asm")
                        .and_then(|v| v.as_str())
                        .map(|s| s.contains("OP_CHECKMULTISIG"))
                        .unwrap_or(false);

                if is_multisig || is_nonstandard_multisig {
                    let script_hex = spk["hex"].as_str().unwrap_or("").to_string();
                    let (pubkeys, required_sigs, total_pubkeys) =
                        data_carry_research::types::parse_p2ms_script(&script_hex)
                            .unwrap_or_else(|_| (Vec::new(), 0, 0));

                    use data_carry_research::types::script_metadata::MultisigInfo;
                    let info = MultisigInfo {
                        pubkeys: pubkeys.clone(),
                        required_sigs,
                        total_pubkeys,
                    };

                    outputs.push(TransactionOutput {
                        txid: txid.to_string(),
                        vout: n as u32,
                        height: 0,
                        amount: (val * 100_000_000.0) as u64, // Convert BTC to satoshis
                        script_hex: script_hex.clone(),
                        script_type: "multisig".to_string(), // Always use "multisig" for internal database
                        is_coinbase: false,
                        script_size: script_hex.len() / 2,
                        metadata: serde_json::to_value(info).unwrap(),
                        address: None,
                    });
                }
            }
        }
    }

    if outputs.is_empty() {
        return Err(anyhow::anyhow!("No P2MS outputs found in {}", json_path));
    }

    Ok(outputs)
}

/// Load ALL transaction outputs from JSON (not just P2MS)
///
/// Used to populate the unified transaction_outputs table for protocol detection tests.
/// Parses all output types: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, P2PK, OP_RETURN, multisig, etc.
pub fn load_all_outputs_from_json(json_path: &str, txid: &str) -> Result<Vec<TransactionOutput>> {
    use data_carry_research::types::script_metadata::{
        parse_opreturn_script, parse_p2ms_script, ScriptType,
    };

    let content = fs::read_to_string(json_path)
        .map_err(|e| anyhow::anyhow!("Failed to read JSON file {}: {}", json_path, e))?;

    let tx: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse JSON from {}: {}", json_path, e))?;

    let mut outputs = Vec::new();

    if let Some(vouts) = tx["vout"].as_array() {
        for vout in vouts {
            if let (Some(spk), Some(n), Some(val)) = (
                vout.get("scriptPubKey"),
                vout.get("n").and_then(|x| x.as_u64()),
                vout.get("value").and_then(|x| x.as_f64()),
            ) {
                let script_hex = spk["hex"].as_str().unwrap_or("").to_string();
                let script_type_str = spk["type"].as_str().unwrap_or("unknown");
                let address = spk
                    .get("address")
                    .and_then(|a| a.as_str())
                    .map(|s| s.to_string());

                // Determine script type and metadata
                let (script_type, metadata_json) = match script_type_str {
                    "multisig" | "nonstandard" if script_hex.contains("ae") => {
                        // Multisig (OP_CHECKMULTISIG ends with 'ae')
                        if let Ok((pubkeys, required_sigs, total_pubkeys)) =
                            parse_p2ms_script(&script_hex)
                        {
                            use data_carry_research::types::script_metadata::MultisigInfo;
                            let info = MultisigInfo {
                                pubkeys: pubkeys.clone(),
                                required_sigs,
                                total_pubkeys,
                            };
                            (
                                ScriptType::Multisig,
                                serde_json::to_value(info).unwrap_or_default(),
                            )
                        } else {
                            (ScriptType::Unknown, serde_json::json!({}))
                        }
                    }
                    "nulldata" => {
                        // OP_RETURN
                        if let Some(op_data) = parse_opreturn_script(&script_hex) {
                            let metadata = serde_json::json!({
                                "op_return_hex": op_data.op_return_hex,
                                "protocol_prefix_hex": op_data.protocol_prefix_hex,
                                "data_hex": op_data.data_hex,
                                "data_length": op_data.data_length
                            });
                            (ScriptType::OpReturn, metadata)
                        } else {
                            (ScriptType::OpReturn, serde_json::json!({}))
                        }
                    }
                    "pubkeyhash" => (ScriptType::P2PKH, serde_json::json!({})),
                    "scripthash" => (ScriptType::P2SH, serde_json::json!({})),
                    "witness_v0_keyhash" => (ScriptType::P2WPKH, serde_json::json!({})),
                    "witness_v0_scripthash" => (ScriptType::P2WSH, serde_json::json!({})),
                    "witness_v1_taproot" => (ScriptType::P2TR, serde_json::json!({})),
                    "pubkey" => (ScriptType::P2PK, serde_json::json!({})),
                    _ => (ScriptType::Unknown, serde_json::json!({})),
                };

                outputs.push(TransactionOutput {
                    txid: txid.to_string(),
                    vout: n as u32,
                    height: 0,
                    amount: (val * 100_000_000.0) as u64, // Convert BTC to satoshis
                    script_hex: script_hex.clone(),
                    script_type: script_type.as_str().to_string(),
                    is_coinbase: false, // Test fixtures don't expose coinbase status
                    script_size: script_hex.len() / 2,
                    metadata: metadata_json,
                    address,
                });
            }
        }
    }

    Ok(outputs)
}

/// Get first input transaction ID from JSON
///
/// Helper for extracting the first input's txid from raw transaction JSON.
/// Useful for tests that need to create realistic transaction inputs.
pub fn get_first_input_txid_from_json(json_path: &str) -> Result<String> {
    let content = fs::read_to_string(json_path)?;
    let tx: serde_json::Value = serde_json::from_str(&content)?;

    if let Some(vin) = tx["vin"].as_array() {
        if let Some(first_input) = vin.first() {
            if let Some(txid) = first_input["txid"].as_str() {
                return Ok(txid.to_string());
            }
        }
    }

    Err(anyhow::anyhow!("No input txid found in {}", json_path))
}

/// Options for loading transaction data from JSON fixtures
///
/// This provides a consistent interface for loading transaction data
/// across all protocol tests, eliminating per-protocol helper functions.
#[derive(Default)]
pub struct TransactionLoadOptions {
    /// Load ALL outputs (P2MS, OP_RETURN, P2PKH, etc.) vs P2MS-only (default: false)
    pub include_all_outputs: bool,
    /// Load transaction inputs from JSON fixture (needed for Omni deobfuscation)
    pub include_inputs: bool,
    /// Apply burn patterns (e.g., Counterparty standard patterns)
    pub burn_patterns: Option<Vec<BurnPattern>>,
}

/// Load transaction from JSON fixture with consistent handling
///
/// This is the unified entry point for loading test transaction data.
/// All protocol tests should use this function instead of custom helpers.
///
/// # Arguments
/// * `json_path` - Path to JSON fixture file
/// * `txid` - Transaction ID to use
/// * `options` - Loading options (outputs type, inputs, burn patterns)
///
/// # Returns
/// Tuple of (EnrichedTransaction, Vec<TransactionInput>)
///
/// # Example
/// ```ignore
/// // Simple protocol (P2MS-only)
/// let (tx, _inputs) = load_transaction_from_json(path, txid, Default::default())?;
///
/// // Protocol needing all outputs (PPk, Omni)
/// let (tx, _) = load_transaction_from_json(path, txid,
///     TransactionLoadOptions { include_all_outputs: true, ..Default::default() })?;
///
/// // Protocol with burn patterns and inputs (Counterparty)
/// let (tx, inputs) = load_transaction_from_json(path, txid,
///     TransactionLoadOptions {
///         burn_patterns: Some(fixtures::counterparty_burn_patterns()),
///         include_inputs: true,
///         ..Default::default()
///     })?;
/// ```
pub fn load_transaction_from_json(
    json_path: &str,
    txid: &str,
    options: TransactionLoadOptions,
) -> Result<(EnrichedTransaction, Vec<TransactionInput>)> {
    // 1. Load outputs based on options.include_all_outputs
    let outputs = if options.include_all_outputs {
        load_all_outputs_from_json(json_path, txid)?
    } else {
        load_p2ms_outputs_from_json(json_path, txid)?
    };

    if outputs.is_empty() {
        anyhow::bail!("No outputs found in {}", json_path);
    }

    // 2. Create EnrichedTransaction
    let mut tx = fixtures::create_test_enriched_transaction(txid);
    tx.outputs = outputs.clone();
    tx.p2ms_outputs_count = outputs
        .iter()
        .filter(|o| o.script_type == "multisig")
        .count();

    // 3. Apply burn patterns if specified
    if let Some(patterns) = options.burn_patterns {
        tx.burn_patterns_detected = patterns;
    }

    // 4. Load inputs if requested
    let inputs = if options.include_inputs {
        load_transaction_inputs_from_json(json_path)?
    } else {
        Vec::new()
    };

    Ok((tx, inputs))
}

/// Load transaction inputs from JSON fixture
///
/// Extracts input data from the transaction's "vin" array. This is needed
/// for protocols like Omni that require sender address for deobfuscation.
///
/// Note: This loads basic input data. For protocols needing source addresses
/// (like Omni), use load_inputs_with_source_addresses instead.
pub fn load_transaction_inputs_from_json(json_path: &str) -> Result<Vec<TransactionInput>> {
    let content = fs::read_to_string(json_path)?;
    let tx: serde_json::Value = serde_json::from_str(&content)?;

    let mut inputs = Vec::new();
    if let Some(vin) = tx["vin"].as_array() {
        for (idx, input) in vin.iter().enumerate() {
            // Skip coinbase inputs
            if input.get("coinbase").is_some() {
                continue;
            }

            let prev_txid = input["txid"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing txid in input {}", idx))?
                .to_string();
            let prev_vout = input["vout"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("Missing vout in input {}", idx))?
                as u32;
            let sequence = input["sequence"].as_u64().unwrap_or(0xffffffff) as u32;
            let script_sig = input["scriptSig"]["hex"].as_str().unwrap_or("").to_string();

            inputs.push(TransactionInput {
                txid: prev_txid,
                vout: prev_vout,
                value: 0, // Not available without looking up previous tx
                script_sig,
                sequence,
                source_address: None, // Not available without looking up previous tx
            });
        }
    }

    Ok(inputs)
}

/// Load transaction inputs with source addresses from separate input fixture files
///
/// This is required for protocols like Omni that need the sender's address for
/// SHA256-based deobfuscation. It loads each input's previous transaction from
/// the input_fixture_dir to extract the source address.
pub fn load_inputs_with_source_addresses(
    json_path: &str,
    input_fixture_dir: &str,
) -> Result<Vec<TransactionInput>> {
    let content = fs::read_to_string(json_path)?;
    let tx: serde_json::Value = serde_json::from_str(&content)?;

    let mut inputs = Vec::new();
    if let Some(vin) = tx["vin"].as_array() {
        for input in vin {
            // Skip coinbase inputs
            if input.get("coinbase").is_some() {
                continue;
            }

            let prev_txid = input["txid"].as_str().unwrap();
            let prev_vout = input["vout"].as_u64().unwrap() as u32;

            // Load the previous transaction from stored JSON
            let input_json_path = format!("{}{}.json", input_fixture_dir, prev_txid);

            let prev_tx_content = fs::read_to_string(&input_json_path)?;
            let prev_tx: serde_json::Value = serde_json::from_str(&prev_tx_content)?;

            // Extract value and address from the specific output
            let output = &prev_tx["vout"][prev_vout as usize];
            let value = (output["value"].as_f64().unwrap() * 100_000_000.0) as u64;
            let source_address = output["scriptPubKey"]["address"]
                .as_str()
                .map(|s| s.to_string());

            inputs.push(TransactionInput {
                txid: prev_txid.to_string(),
                vout: prev_vout,
                value,
                script_sig: hex::encode(
                    hex::decode(input["scriptSig"]["hex"].as_str().unwrap_or(""))
                        .unwrap_or_default(),
                ),
                sequence: input["sequence"].as_u64().unwrap_or(0xffffffff) as u32,
                source_address,
            });
        }
    }

    Ok(inputs)
}

/// Standard Stage 3 processor runner
///
/// Runs Stage 3 processing and returns total classification count.
/// Use this for consistent test execution across protocols.
pub async fn run_stage3_processor(db_path: &str, config: Stage3Config) -> Result<usize> {
    let mut processor = Stage3Processor::new(db_path, config)?;
    processor.run().await?;

    let db = Database::new(db_path)?;
    let total_classified: i64 = db.connection().query_row(
        "SELECT COUNT(*) FROM transaction_classifications",
        [],
        |row| row.get(0),
    )?;
    Ok(total_classified as usize)
}

/// Verify Stage 3 processing completed successfully
///
/// Standard assertions for Stage 3 test completion.
/// Checks that processing ran without errors and classified expected number of transactions.
pub fn verify_stage3_completion(
    total_classified: usize,
    expected_total: usize,
    expected_protocol_count: usize,
) {
    assert_eq!(
        total_classified, expected_total,
        "Expected {} total classifications, got {}",
        expected_total, total_classified
    );

    assert!(
        total_classified >= expected_protocol_count,
        "Expected at least {} protocol classifications, got {}",
        expected_protocol_count,
        total_classified
    );
}

/// Verify that all output classifications for a transaction have spendability data
///
/// This is critical for protocols like Counterparty and Omni Layer where every output
/// MUST have spendability analysis (is_spendable.is_some()) even though they are
/// always spendable. The key counts (real_pubkey_count, data_key_count) must be
/// accurate per-output, not copied from a single analysis.
pub fn verify_output_spendability(
    test_db: &TestDatabase,
    txid: &str,
    expected_protocol: ProtocolType,
) -> Result<()> {
    let conn = Connection::open(test_db.path())?;

    let mut stmt = conn.prepare(
        "SELECT vout, is_spendable, real_pubkey_count, burn_key_count, data_key_count
         FROM p2ms_output_classifications
         WHERE txid = ?1 AND protocol = ?2
         ORDER BY vout",
    )?;

    let protocol_str = match expected_protocol {
        ProtocolType::Counterparty => "Counterparty",
        ProtocolType::OmniLayer => "OmniLayer",
        ProtocolType::BitcoinStamps => "BitcoinStamps",
        ProtocolType::LikelyLegitimateMultisig => "LikelyLegitimateMultisig",
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported protocol for spendability verification"
            ))
        }
    };

    let outputs = stmt.query_map([txid, protocol_str], |row| {
        let vout: u32 = row.get(0)?;
        let is_spendable: Option<bool> = row.get(1)?;
        let real_count: u8 = row.get(2)?;
        let burn_count: u8 = row.get(3)?;
        let data_count: u8 = row.get(4)?;
        Ok((vout, is_spendable, real_count, burn_count, data_count))
    })?;

    let mut output_count = 0;
    for result in outputs {
        let (vout, is_spendable, real_count, burn_count, data_count) = result?;
        output_count += 1;

        // CRITICAL: Every output must have spendability data
        assert!(
            is_spendable.is_some(),
            "Output {} of tx {} ({:?}) is missing is_spendable data - \
             this indicates spendability was not analysed per-output",
            vout,
            txid,
            expected_protocol
        );

        // Verify key counts are non-zero (at least one type of key present)
        let total_keys = real_count + burn_count + data_count;
        assert!(
            total_keys > 0,
            "Output {} of tx {} ({:?}) has zero key counts - \
             this indicates spendability analysis failed",
            vout,
            txid,
            expected_protocol
        );
    }

    assert!(
        output_count > 0,
        "No output classifications found for tx {} ({:?})",
        txid,
        expected_protocol
    );

    Ok(())
}

/// Verify that ALL P2MS outputs in a transaction are classified
///
/// This is a critical check to ensure protocol classifiers don't leave any P2MS outputs
/// unclassified. Every P2MS output should have spendability analysis, even if it doesn't
/// contain protocol data (e.g., "dust" outputs in Counterparty multi-output transactions).
pub fn verify_complete_output_coverage(
    test_db: &TestDatabase,
    txid: &str,
    expected_protocol: ProtocolType,
) -> Result<()> {
    let conn = test_db.database().connection();

    // Count P2MS outputs in transaction_outputs table
    let total_p2ms_outputs: u32 = conn.query_row(
        "SELECT COUNT(*) FROM transaction_outputs WHERE txid = ?1 AND script_type = 'multisig'",
        [txid],
        |row| row.get(0),
    )?;

    let protocol_str = match expected_protocol {
        ProtocolType::Counterparty => "Counterparty",
        ProtocolType::OmniLayer => "OmniLayer",
        ProtocolType::BitcoinStamps => "BitcoinStamps",
        ProtocolType::LikelyLegitimateMultisig => "LikelyLegitimateMultisig",
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported protocol for coverage verification"
            ))
        }
    };

    // Count classified outputs in p2ms_output_classifications table
    let classified_outputs: u32 = conn.query_row(
        "SELECT COUNT(*) FROM p2ms_output_classifications WHERE txid = ?1 AND protocol = ?2",
        [txid, protocol_str],
        |row| row.get(0),
    )?;

    assert_eq!(
        classified_outputs, total_p2ms_outputs,
        "Incomplete output coverage for tx {} ({:?}): {} P2MS outputs found, but only {} classified. \
         ALL P2MS outputs must be classified with spendability analysis!",
        txid, expected_protocol, total_p2ms_outputs, classified_outputs
    );

    Ok(())
}

/// Build an EnrichedTransaction from embedded P2MS script hex
///
/// This avoids RPC dependency by parsing script hex directly.
/// Script format: 51 <len1> <pubkey1> <len2> <pubkey2> [<len3> <pubkey3>] <m> ae
/// Where 51 = OP_1, ae = OP_CHECKMULTISIG
pub fn build_transaction_from_script_hex(
    txid: &str,
    script_hex: &str,
) -> Result<data_carry_research::types::EnrichedTransaction> {
    use data_carry_research::types::EnrichedTransaction;

    let (pubkeys, required_sigs, total_pubkeys) = parse_multisig_script(script_hex)?;

    // Build metadata JSON for multisig
    let metadata = serde_json::json!({
        "required_sigs": required_sigs,
        "total_pubkeys": total_pubkeys,
        "pubkeys": pubkeys
    });

    let output = TransactionOutput {
        txid: txid.to_string(),
        vout: 0,
        height: 0,
        amount: 5460, // Standard dust amount
        script_hex: script_hex.to_string(),
        script_type: "multisig".to_string(),
        is_coinbase: false,
        script_size: script_hex.len() / 2, // hex length / 2 = byte length
        metadata,
        address: None,
    };

    let tx_size = 250; // Approximate size
    let tx_fee = 4540u64;

    Ok(EnrichedTransaction {
        txid: txid.to_string(),
        height: 0,
        total_input_value: 10000,
        total_output_value: 5460,
        transaction_fee: tx_fee,
        fee_per_byte: tx_fee as f64 / tx_size as f64,
        transaction_size_bytes: tx_size,
        fee_per_kb: (tx_fee as f64 / tx_size as f64) * 1000.0,
        total_p2ms_amount: 5460,
        data_storage_fee_rate: tx_fee as f64 / (script_hex.len() / 2) as f64,
        p2ms_outputs_count: 1,
        burn_patterns_detected: vec![],
        input_count: 1,
        output_count: 1,
        is_coinbase: false,
        outputs: vec![output],
    })
}

/// Parse multisig script hex into components
///
/// Extracts pubkeys and multisig parameters with safety checks.
/// Fails loudly if script format is invalid.
pub fn parse_multisig_script(script_hex: &str) -> Result<(Vec<String>, u8, u8)> {
    let script_bytes = hex::decode(script_hex)?;

    if script_bytes.len() < 4 {
        anyhow::bail!("Script too short to be valid multisig");
    }

    // Check OP_1 at start (0x51 = 1-of-N)
    if script_bytes[0] != 0x51 {
        anyhow::bail!("Script does not start with OP_1 (0x51)");
    }

    // Check OP_CHECKMULTISIG at end (0xae)
    if script_bytes[script_bytes.len() - 1] != 0xae {
        anyhow::bail!("Script does not end with OP_CHECKMULTISIG (0xae)");
    }

    let mut pubkeys = Vec::new();
    let mut pos = 1; // Start after OP_1

    // Parse pubkeys
    while pos < script_bytes.len() - 2 {
        // -2 for <m> ae at end
        let len = script_bytes[pos] as usize;
        if len == 0x52 || len == 0x53 {
            // OP_2 or OP_3 (multisig count)
            break;
        }

        if pos + 1 + len > script_bytes.len() {
            anyhow::bail!("Pubkey length extends beyond script bounds");
        }

        let pubkey_bytes = &script_bytes[pos + 1..pos + 1 + len];
        pubkeys.push(hex::encode(pubkey_bytes));
        pos += 1 + len;
    }

    // Get total pubkeys count (should be OP_2 = 0x52 or OP_3 = 0x53)
    let total_pubkeys = match script_bytes[script_bytes.len() - 2] {
        0x52 => 2,
        0x53 => 3,
        other => anyhow::bail!("Unexpected total pubkeys opcode: {:#x}", other),
    };

    if pubkeys.len() != total_pubkeys as usize {
        anyhow::bail!(
            "Pubkey count mismatch: parsed {} pubkeys but script indicates {}",
            pubkeys.len(),
            total_pubkeys
        );
    }

    Ok((pubkeys, 1, total_pubkeys)) // Always 1-of-N for these protocols
}

/// Build a fake transaction with ASCII but no protocol signature
///
/// Used for false positive testing to ensure allowlist approach prevents matches.
pub fn build_fake_ascii_tx(
    txid: &str,
    ascii_text: &str,
) -> Result<data_carry_research::types::EnrichedTransaction> {
    // Build a fake 1-of-2 multisig with ASCII in second pubkey
    let ascii_hex = hex::encode(ascii_text.as_bytes());
    // Pad to 33 bytes total (1 byte prefix + ascii + padding)
    let padding_bytes = 33 - 1 - ascii_text.len();
    let padding = "00".repeat(padding_bytes);

    let pubkey1 = format!("03{}", "AA".repeat(32)); // Valid EC point prefix (33 bytes total)
    let pubkey2 = format!("16{}{}", ascii_hex, padding); // Invalid prefix + ASCII (33 bytes total)

    let script_hex = format!("5121{}21{}52ae", pubkey1, pubkey2);

    build_transaction_from_script_hex(txid, &script_hex)
}

/// Seed Stage 3 test data by manually inserting into all required tables
///
/// Since insert_test_transaction doesn't exist, manually insert into:
/// - blocks (stub block for height FK constraint)
/// - transaction_outputs (with is_spent = 0)
/// - enriched_transactions
/// - p2ms_outputs (for FK constraint satisfaction)
pub fn seed_stage3_test_data(
    conn: &Connection,
    tx: &data_carry_research::types::EnrichedTransaction,
) -> Result<()> {
    // Insert stub block for FK constraint FIRST
    conn.execute(
        "INSERT OR IGNORE INTO blocks (height) VALUES (?1)",
        [tx.height],
    )?;

    // Insert into transaction_outputs
    for output in &tx.outputs {
        let metadata_json = output.metadata.to_string();

        conn.execute(
            "INSERT OR REPLACE INTO transaction_outputs
             (txid, vout, height, amount, script_hex, script_type, is_coinbase, script_size, metadata_json, address, is_spent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                &output.txid,
                output.vout,
                output.height,
                output.amount,
                &output.script_hex,
                &output.script_type,
                output.is_coinbase,
                output.script_size,
                metadata_json,
                &output.address,
                0 // is_spent = 0 (unspent)
            ],
        )?;
    }

    // Insert into enriched_transactions
    conn.execute(
        "INSERT OR REPLACE INTO enriched_transactions
         (txid, height, is_coinbase, total_input_value, total_output_value, transaction_fee,
          fee_per_byte, transaction_size_bytes, fee_per_kb, total_p2ms_amount,
          data_storage_fee_rate, p2ms_outputs_count,
          input_count, output_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        rusqlite::params![
            &tx.txid,
            tx.height,
            tx.is_coinbase,
            tx.total_input_value,
            tx.total_output_value,
            tx.transaction_fee,
            tx.fee_per_byte,
            tx.transaction_size_bytes,
            tx.fee_per_kb,
            tx.total_p2ms_amount,
            tx.data_storage_fee_rate,
            tx.p2ms_outputs_count,
            tx.input_count,
            tx.output_count,
        ],
    )?;

    // Insert p2ms_outputs for P2MS outputs (required by burn_patterns FK and classification trigger)
    // CRITICAL: Must preserve real multisig metadata from TransactionOutput.metadata for protocol detection
    for output in &tx.outputs {
        if output.script_type == "multisig" {
            // Extract real multisig metadata from the output (needed for protocol signature detection)
            if let Some(multisig_info) = output.multisig_info() {
                let pubkeys_json = serde_json::to_string(&multisig_info.pubkeys)?;

                conn.execute(
                    "INSERT OR IGNORE INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        &output.txid,
                        output.vout,
                        multisig_info.required_sigs,
                        multisig_info.total_pubkeys,
                        pubkeys_json
                    ],
                )?;
            } else {
                // Fallback for outputs without metadata (shouldn't happen in real tests)
                conn.execute(
                    "INSERT OR IGNORE INTO p2ms_outputs (txid, vout, required_sigs, total_pubkeys, pubkeys_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        &output.txid,
                        output.vout,
                        1,
                        1,
                        "[]"
                    ],
                )?;
            }
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol Test Builder
// ═══════════════════════════════════════════════════════════════════════════════

/// Builder for protocol classification tests
///
/// Provides a unified interface for running protocol classification tests,
/// eliminating duplicate `run_*_test_from_json()` functions across protocol test files.
///
/// # Example
///
/// ```rust,ignore
/// // Simple protocol test (Chancecoin)
/// ProtocolTestBuilder::from_fixture(&fixture_registry::chancecoin::BET)
///     .execute()
///     .await?;
///
/// // Protocol with burn patterns (Stamps)
/// ProtocolTestBuilder::from_fixture(&fixture_registry::stamps::SRC20_DEPLOY)
///     .with_burn_patterns(fixtures::stamps_burn_patterns())
///     .execute()
///     .await?;
///
/// // Protocol needing all outputs (PPk, Omni)
/// ProtocolTestBuilder::from_fixture(&fixture_registry::ppk::RT_STANDARD)
///     .with_all_outputs()
///     .execute()
///     .await?;
/// ```
pub struct ProtocolTestBuilder {
    fixture: &'static ProtocolFixture,
    include_all_outputs: bool,
    include_inputs: bool,
    burn_patterns: Option<Vec<BurnPattern>>,
    skip_content_type_check: bool,
}

impl ProtocolTestBuilder {
    /// Create a new builder from a fixture registry entry
    pub fn from_fixture(fixture: &'static ProtocolFixture) -> Self {
        Self {
            fixture,
            include_all_outputs: false,
            include_inputs: false,
            burn_patterns: None,
            skip_content_type_check: false,
        }
    }

    /// Load ALL outputs (P2MS, OP_RETURN, P2PKH, etc.) instead of P2MS-only
    ///
    /// Required for protocols that examine non-P2MS outputs:
    /// - PPk (RT transport via OP_RETURN)
    /// - Omni Layer (Exodus address detection)
    /// - OP_RETURN Signalled protocols
    pub fn with_all_outputs(mut self) -> Self {
        self.include_all_outputs = true;
        self
    }

    /// Load transaction inputs from JSON fixture
    ///
    /// Required for protocols that need sender address:
    /// - Omni Layer (SHA256 deobfuscation)
    /// - Counterparty (ARC4 key derivation)
    pub fn with_inputs(mut self) -> Self {
        self.include_inputs = true;
        self
    }

    /// Apply burn patterns to the transaction
    ///
    /// Required for protocols with burn pattern detection:
    /// - Bitcoin Stamps (stamps_burn_patterns)
    /// - Counterparty (counterparty_burn_patterns)
    pub fn with_burn_patterns(mut self, patterns: Vec<BurnPattern>) -> Self {
        self.burn_patterns = Some(patterns);
        self
    }

    /// Skip content type verification
    ///
    /// Use for protocols where content_type is not yet implemented or is None.
    pub fn skip_content_type(mut self) -> Self {
        self.skip_content_type_check = true;
        self
    }

    /// Execute the test and verify results
    ///
    /// This performs the standard test flow:
    /// 1. Setup test database
    /// 2. Load transaction from JSON fixture
    /// 3. Seed database (FK-safe order)
    /// 4. Run Stage 3 processor
    /// 5. Verify classification matches expected protocol/variant
    /// 6. Verify content type matches expected MIME type (unless skipped)
    pub async fn execute(&self) -> Result<ProtocolTestResult> {
        let test_name = self.fixture.description;
        let txid = self.fixture.txid;

        // 1. Setup test database
        let (mut test_db, config) = setup_protocol_test(test_name)?;

        // 2. Print test header
        println!("\n╔══════════════════════════════════════════════════════════════");
        println!(
            "║ {} Protocol Classification Test",
            protocol_display_name(self.fixture.protocol)
        );
        println!("╠══════════════════════════════════════════════════════════════");
        println!("║ Test: {}", test_name);
        println!("║ TXID: {}", txid);
        if let Some(variant) = self.fixture.variant {
            println!("║ Expected Variant: {}", variant);
        }
        if let Some(content_type) = self.fixture.content_type {
            println!("║ Expected Content-Type: {}", content_type);
        }
        println!("╟──────────────────────────────────────────────────────────────");

        // 3. Load transaction from JSON fixture
        let options = TransactionLoadOptions {
            include_all_outputs: self.include_all_outputs,
            include_inputs: false, // We'll handle inputs separately for input_fixture_path
            burn_patterns: self.burn_patterns.clone(),
        };

        let (tx, _) = match load_transaction_from_json(self.fixture.path, txid, options) {
            Ok(result) => result,
            Err(e) => {
                println!(
                    "⚠️  Skipping test - no valid transaction data in {}: {}",
                    self.fixture.path, e
                );
                return Ok(ProtocolTestResult {
                    skipped: true,
                    classified_count: 0,
                });
            }
        };

        // Load inputs - use source address loader if input_fixture_path is set
        let inputs = if self.include_inputs {
            if let Some(input_path) = self.fixture.input_fixture_path {
                load_inputs_with_source_addresses(self.fixture.path, input_path)?
            } else {
                load_transaction_inputs_from_json(self.fixture.path)?
            }
        } else {
            Vec::new()
        };

        println!("║ P2MS Outputs Found: {}", tx.p2ms_outputs_count);
        println!("║");

        // 4. Seed database (FK-safe order)
        seed_enriched_transaction(&mut test_db, &tx, inputs)?;

        println!("║ Running Stage 3 Classification...");
        println!("╟──────────────────────────────────────────────────────────────");

        // 5. Run Stage 3 processor
        let total_classified = run_stage3_processor(test_db.path(), config).await?;

        // 6. Verify Stage 3 completion
        verify_stage3_completion(total_classified, 1, 1);

        println!("║ ✅ Classified: {}/{}", total_classified, 1);
        println!("║");

        // 7. Parse expected variant
        let expected_variant = self
            .fixture
            .variant
            .map(|v| parse_variant_string(v, self.fixture.protocol));

        // 8. Verify classification
        verify_classification(
            &test_db,
            txid,
            self.fixture.protocol,
            expected_variant.clone(),
        )?;

        println!("║ ✅ Protocol: {:?}", self.fixture.protocol);
        if let Some(ref variant) = expected_variant {
            println!("║ ✅ Variant: {:?}", variant);
        }

        // 9. Verify content type (unless skipped)
        if !self.skip_content_type_check {
            verify_content_type(&test_db, txid, self.fixture.content_type)?;
            if let Some(content_type) = self.fixture.content_type {
                println!("║ ✅ Content-Type: {}", content_type);
            }
        }

        println!("╚══════════════════════════════════════════════════════════════\n");

        Ok(ProtocolTestResult {
            skipped: false,
            classified_count: total_classified,
        })
    }
}

/// Result of a protocol test execution
#[derive(Debug)]
pub struct ProtocolTestResult {
    /// Whether the test was skipped (e.g., missing fixture)
    pub skipped: bool,
    /// Number of transactions classified
    pub classified_count: usize,
}

/// Get display name for a protocol type
fn protocol_display_name(protocol: ProtocolType) -> &'static str {
    match protocol {
        ProtocolType::BitcoinStamps => "Bitcoin Stamps",
        ProtocolType::Counterparty => "Counterparty",
        ProtocolType::OmniLayer => "Omni Layer",
        ProtocolType::Chancecoin => "Chancecoin",
        ProtocolType::PPk => "PPk",
        ProtocolType::OpReturnSignalled => "OP_RETURN Signalled",
        ProtocolType::AsciiIdentifierProtocols => "ASCII Identifier",
        ProtocolType::DataStorage => "DataStorage",
        ProtocolType::LikelyDataStorage => "LikelyDataStorage",
        ProtocolType::LikelyLegitimateMultisig => "LikelyLegitimateMultisig",
        ProtocolType::Unknown => "Unknown",
    }
}

/// Parse variant string to ProtocolVariant enum
fn parse_variant_string(variant_str: &str, protocol: ProtocolType) -> ProtocolVariant {
    match (protocol, variant_str) {
        // Bitcoin Stamps variants
        (ProtocolType::BitcoinStamps, "StampsClassic") => ProtocolVariant::StampsClassic,
        (ProtocolType::BitcoinStamps, "StampsSRC20") => ProtocolVariant::StampsSRC20,
        (ProtocolType::BitcoinStamps, "StampsSRC721") => ProtocolVariant::StampsSRC721,
        (ProtocolType::BitcoinStamps, "StampsSRC101") => ProtocolVariant::StampsSRC101,
        (ProtocolType::BitcoinStamps, "StampsHTML") => ProtocolVariant::StampsHTML,
        (ProtocolType::BitcoinStamps, "StampsCompressed") => ProtocolVariant::StampsCompressed,
        (ProtocolType::BitcoinStamps, "StampsData") => ProtocolVariant::StampsData,
        (ProtocolType::BitcoinStamps, "StampsUnknown") => ProtocolVariant::StampsUnknown,

        // Counterparty variants (7 semantically coherent categories)
        (ProtocolType::Counterparty, "CounterpartyTransfer") => {
            ProtocolVariant::CounterpartyTransfer
        }
        (ProtocolType::Counterparty, "CounterpartyIssuance") => {
            ProtocolVariant::CounterpartyIssuance
        }
        (ProtocolType::Counterparty, "CounterpartyDestruction") => {
            ProtocolVariant::CounterpartyDestruction
        }
        (ProtocolType::Counterparty, "CounterpartyDEX") => ProtocolVariant::CounterpartyDEX,
        (ProtocolType::Counterparty, "CounterpartyOracle") => ProtocolVariant::CounterpartyOracle,
        (ProtocolType::Counterparty, "CounterpartyGaming") => ProtocolVariant::CounterpartyGaming,
        (ProtocolType::Counterparty, "CounterpartyUtility") => ProtocolVariant::CounterpartyUtility,

        // Omni Layer variants (7 semantic categories + 1 special case)
        (ProtocolType::OmniLayer, "OmniTransfer") => ProtocolVariant::OmniTransfer,
        (ProtocolType::OmniLayer, "OmniDistribution") => ProtocolVariant::OmniDistribution,
        (ProtocolType::OmniLayer, "OmniIssuance") => ProtocolVariant::OmniIssuance,
        (ProtocolType::OmniLayer, "OmniDestruction") => ProtocolVariant::OmniDestruction,
        (ProtocolType::OmniLayer, "OmniDEX") => ProtocolVariant::OmniDEX,
        (ProtocolType::OmniLayer, "OmniAdministration") => ProtocolVariant::OmniAdministration,
        (ProtocolType::OmniLayer, "OmniUtility") => ProtocolVariant::OmniUtility,
        (ProtocolType::OmniLayer, "OmniFailedDeobfuscation") => {
            ProtocolVariant::OmniFailedDeobfuscation
        }

        // Chancecoin variants
        (ProtocolType::Chancecoin, "ChancecoinSend") => ProtocolVariant::ChancecoinSend,
        (ProtocolType::Chancecoin, "ChancecoinOrder") => ProtocolVariant::ChancecoinOrder,
        (ProtocolType::Chancecoin, "ChancecoinBTCPay") => ProtocolVariant::ChancecoinBTCPay,
        (ProtocolType::Chancecoin, "ChancecoinRoll") => ProtocolVariant::ChancecoinRoll,
        (ProtocolType::Chancecoin, "ChancecoinBet") => ProtocolVariant::ChancecoinBet,
        (ProtocolType::Chancecoin, "ChancecoinCancel") => ProtocolVariant::ChancecoinCancel,
        (ProtocolType::Chancecoin, "ChancecoinUnknown") => ProtocolVariant::ChancecoinUnknown,

        // PPk variants
        (ProtocolType::PPk, "PPkProfile") => ProtocolVariant::PPkProfile,
        (ProtocolType::PPk, "PPkRegistration") => ProtocolVariant::PPkRegistration,
        (ProtocolType::PPk, "PPkMessage") => ProtocolVariant::PPkMessage,
        (ProtocolType::PPk, "PPkUnknown") => ProtocolVariant::PPkUnknown,

        // OP_RETURN Signalled variants
        (ProtocolType::OpReturnSignalled, "OpReturnCLIPPERZ") => ProtocolVariant::OpReturnCLIPPERZ,
        (ProtocolType::OpReturnSignalled, "OpReturnProtocol47930") => {
            ProtocolVariant::OpReturnProtocol47930
        }
        (ProtocolType::OpReturnSignalled, "OpReturnGenericASCII") => {
            ProtocolVariant::OpReturnGenericASCII
        }

        // ASCII Identifier Protocol variants
        (ProtocolType::AsciiIdentifierProtocols, "AsciiIdentifierTB0001") => {
            ProtocolVariant::AsciiIdentifierTB0001
        }
        (ProtocolType::AsciiIdentifierProtocols, "AsciiIdentifierTEST01") => {
            ProtocolVariant::AsciiIdentifierTEST01
        }
        (ProtocolType::AsciiIdentifierProtocols, "AsciiIdentifierMetronotes") => {
            ProtocolVariant::AsciiIdentifierMetronotes
        }
        (ProtocolType::AsciiIdentifierProtocols, "AsciiIdentifierOther") => {
            ProtocolVariant::AsciiIdentifierOther
        }
        (ProtocolType::AsciiIdentifierProtocols, "AsciiIdentifierUnknown") => {
            ProtocolVariant::AsciiIdentifierUnknown
        }

        // DataStorage variants
        (ProtocolType::DataStorage, "DataStorageProofOfBurn") => {
            ProtocolVariant::DataStorageProofOfBurn
        }
        (ProtocolType::DataStorage, "DataStorageFileMetadata") => {
            ProtocolVariant::DataStorageFileMetadata
        }
        (ProtocolType::DataStorage, "DataStorageEmbeddedData")
        | (ProtocolType::DataStorage, "EmbeddedData") => ProtocolVariant::DataStorageEmbeddedData,
        (ProtocolType::DataStorage, "DataStorageWikiLeaksCablegate") => {
            ProtocolVariant::DataStorageWikiLeaksCablegate
        }
        (ProtocolType::DataStorage, "DataStorageBitcoinWhitepaper") => {
            ProtocolVariant::DataStorageBitcoinWhitepaper
        }
        (ProtocolType::DataStorage, "DataStorageNullData") => ProtocolVariant::DataStorageNullData,
        (ProtocolType::DataStorage, "DataStorageGeneric") => ProtocolVariant::DataStorageGeneric,

        // LikelyDataStorage variants
        (ProtocolType::LikelyDataStorage, "LikelyDataStorageInvalidECPoint") => {
            ProtocolVariant::LikelyDataStorageInvalidECPoint
        }
        (ProtocolType::LikelyDataStorage, "LikelyDataStorageHighOutputCount") => {
            ProtocolVariant::LikelyDataStorageHighOutputCount
        }
        (ProtocolType::LikelyDataStorage, "LikelyDataStorageDustAmount") => {
            ProtocolVariant::LikelyDataStorageDustAmount
        }

        // LikelyLegitimateMultisig variants
        (ProtocolType::LikelyLegitimateMultisig, "LegitimateMultisig") => {
            ProtocolVariant::LegitimateMultisig
        }
        (ProtocolType::LikelyLegitimateMultisig, "LegitimateMultisigDupeKeys") => {
            ProtocolVariant::LegitimateMultisigDupeKeys
        }
        (ProtocolType::LikelyLegitimateMultisig, "LegitimateMultisigWithNullKey") => {
            ProtocolVariant::LegitimateMultisigWithNullKey
        }

        // Fallback
        _ => panic!(
            "Unknown variant string '{}' for protocol {:?}",
            variant_str, protocol
        ),
    }
}
