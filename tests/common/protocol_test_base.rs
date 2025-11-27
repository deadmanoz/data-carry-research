//! Protocol Test Base Module
//!
//! This module provides standardised utilities for protocol classification tests,
//! eliminating code duplication and ensuring consistent test patterns across
//! all protocol test files (Counterparty, Omni Layer, Bitcoin Stamps, Data Storage).

use anyhow::Result;
use data_carry_research::database::traits::StatisticsOperations;
use data_carry_research::database::Database;
use data_carry_research::processor::stage3::Stage3Processor;
use data_carry_research::types::{
    ClassificationDetails, ProtocolType, ProtocolVariant, Stage3Config, TransactionOutput,
};
use rusqlite::Connection;
use serde_json;
use std::fs;

use super::database::TestDatabase;

/// Standard protocol test configuration factory
///
/// Creates a consistent Stage3Config for all protocol tests with:
/// - Small batch size for testing (10)
/// - No height filtering (signature-based detection only)
/// - Default tier2 patterns configuration
pub fn create_protocol_test_config(db_path: &str) -> Stage3Config {
    Stage3Config {
        database_path: db_path.into(),
        batch_size: 10,
        progress_interval: 1000,
        tier2_patterns_config: data_carry_research::types::Tier2PatternsConfig::default(),
    }
}

/// Standard protocol test setup
///
/// Returns a TestDatabase with automatic cleanup and a standard config.
/// Use this for all protocol tests to ensure consistency.
pub fn setup_protocol_test(test_name: &str) -> Result<(TestDatabase, Stage3Config)> {
    let test_db = TestDatabase::new(test_name)?;

    // Schema V2: Insert stub blocks for common test heights (FK constraint satisfaction)
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
                    "Invalid EC Point" => ProtocolVariant::InvalidECPoint,
                    "High Output Count" => ProtocolVariant::HighOutputCount,
                    "Dust Amount" => ProtocolVariant::DustAmount,
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
                        TransactionOutput::parse_p2ms_script(&script_hex)
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

/// Standard Stage 3 processor runner
///
/// Runs Stage 3 processing and returns classification stats.
/// Use this for consistent test execution across protocols.
pub async fn run_stage3_processor(
    db_path: &str,
    config: Stage3Config,
) -> Result<data_carry_research::database::ClassificationStats> {
    let mut processor = Stage3Processor::new(db_path, config)?;
    processor.run().await?;

    let db = Database::new_v2(db_path)?;
    let stats = db.get_classification_stats()?;
    Ok(stats)
}

/// Verify Stage 3 processing completed successfully
///
/// Standard assertions for Stage 3 test completion.
/// Checks that processing ran without errors and classified expected number of transactions.
pub fn verify_stage3_completion(
    stats: &data_carry_research::database::ClassificationStats,
    expected_total: usize,
    expected_protocol_count: usize,
) {
    assert_eq!(
        stats.total_classified, expected_total,
        "Expected {} total classifications, got {}",
        expected_total, stats.total_classified
    );

    assert!(
        stats.total_classified >= expected_protocol_count,
        "Expected at least {} protocol classifications, got {}",
        expected_protocol_count,
        stats.total_classified
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
    // Schema V2: Insert stub block for FK constraint FIRST
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

    // Schema V2: Insert p2ms_outputs for P2MS outputs (required by burn_patterns FK and classification trigger)
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
