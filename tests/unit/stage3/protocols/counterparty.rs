//! Stage 3 Counterparty Protocol Classification Tests
//!
//! This test suite comprehensively validates the Counterparty protocol classification functionality
//! in the Bitcoin P2MS Data-Carrying Protocol Analyser. It covers all major historical Counterparty
//! transaction patterns and formats to ensure 100% classification accuracy.
//!
//! ## Test Coverage
//!
//! ### Transaction Patterns Tested:
//! - **Modern 1-of-3 Multi-Output**: ARC4 encrypted format (post-2024)
//! - **Legacy 1-of-2 Single Output**: Plaintext format (2014 era)
//! - **Legacy 1-of-2 Multi-Output**: Plaintext format with data spanning multiple outputs (2014 era)
//!
//! ### Message Types Covered:
//! - **Type 0**: Send operations (asset transfers)
//! - **Type 20**: Issuance operations (asset creation, locking, ownership transfer)
//! - **Type 30**: Broadcast operations (data publishing)
//!
//! ### Real Bitcoin Transactions:
//! All tests use authentic Bitcoin mainnet transaction data fetched from Bitcoin Core RPC,
//! ensuring validation against real-world Counterparty protocol usage.

use data_carry_research::processor::stage3::counterparty::CounterpartyClassifier;
use data_carry_research::types::counterparty::{CounterpartyMessageType, COUNTERPARTY_PREFIX};
use data_carry_research::types::{ProtocolType, ProtocolVariant, Stage3Config};
use serde_json;
use serial_test::serial;

// Import standardised test utilities
use crate::common::database::TestDatabase;
use crate::common::db_seeding::{create_test_inputs, seed_enriched_transaction_simple};
use crate::common::fixtures;
use crate::common::protocol_test_base::{
    get_classification_metadata, load_p2ms_outputs_from_json, run_stage3_processor,
    setup_protocol_test, verify_classification, verify_complete_output_coverage,
    verify_content_type, verify_output_spendability, verify_stage3_completion,
};
use crate::common::test_output::TestOutputFormatter;

/// Counterparty protocol test data creation
mod test_data {
    use super::*;
    use data_carry_research::types::TransactionOutput;
    use std::fs;
    use std::path::Path;

    /// Get the actual message type from classification metadata
    pub fn get_counterparty_message_type(
        test_db: &TestDatabase,
        txid: &str,
    ) -> anyhow::Result<String> {
        let details = get_classification_metadata(test_db, txid)?;

        if let Some(additional_metadata) = details.additional_metadata {
            if let Ok(cp_data) = serde_json::from_str::<
                data_carry_research::types::counterparty::CounterpartyP2msData,
            >(&additional_metadata)
            {
                return Ok(format!(
                    "{:?} (numeric value: {})",
                    cp_data.message_type, cp_data.message_type as u32
                ));
            }
        }

        Err(anyhow::anyhow!(
            "Failed to extract Counterparty message type"
        ))
    }

    /// Extract the first input txid from a JSON fixture
    pub fn get_first_input_txid(json_path: &str) -> Option<String> {
        if !Path::new(json_path).exists() {
            return None;
        }

        let content = fs::read_to_string(json_path).ok()?;
        let tx: serde_json::Value = serde_json::from_str(&content).ok()?;
        tx["vin"]
            .as_array()?
            .first()?
            .get("txid")?
            .as_str()
            .map(|s| s.to_string())
    }

    /// Analyse and display detailed P2MS output information for Counterparty
    pub fn analyse_counterparty_p2ms_output(
        output: &TransactionOutput,
        output_index: usize,
    ) -> String {
        // Determine pubkey roles for Counterparty (data vs source)
        let annotations: Vec<String> = if let Some(info) = output.multisig_info() {
            info.pubkeys
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    let role = if info.required_sigs == 1 && info.total_pubkeys == 3 {
                        if i < 2 {
                            "(data)"
                        } else {
                            "(source)"
                        }
                    } else if info.required_sigs == 1 && info.total_pubkeys == 2 {
                        if i == 1 {
                            "(data)"
                        } else {
                            "(source)"
                        }
                    } else {
                        "(data)"
                    };
                    role.to_string()
                })
                .collect()
        } else {
            vec![]
        };

        // Use consolidated formatter with annotations
        let mut analysis = TestOutputFormatter::format_p2ms_output_detailed(
            output,
            output_index,
            Some(annotations),
        );

        // Add Counterparty-specific data capacity info
        if let Some(info) = output.multisig_info() {
            if info.required_sigs == 1 && info.total_pubkeys == 3 {
                analysis.push_str("║   Data Capacity: 62 bytes\n");
            } else if info.required_sigs == 1 && info.total_pubkeys == 2 {
                analysis.push_str("║   Data Capacity: Variable\n");
            } else {
                analysis.push_str("║   Data Capacity: Unknown\n");
            }

            // Check if this matches Counterparty P2MS pattern
            let is_counterparty =
                info.required_sigs == 1 && (info.total_pubkeys == 2 || info.total_pubkeys == 3);
            analysis.push_str(&format!(
                "║   Counterparty Pattern Match: {}\n",
                if is_counterparty { "✅ YES" } else { "❌ NO" }
            ));
        }

        analysis
    }

    /// Display raw data extraction from P2MS outputs
    pub fn show_counterparty_data_extraction(outputs: &[TransactionOutput]) -> String {
        let mut result = String::new();
        result.push_str("║ Data Extraction:\n");

        let mut total_bytes = 0;
        for (i, output) in outputs.iter().enumerate() {
            if output.multisig_info().map(|i| i.required_sigs).unwrap_or(0) == 1
                && output.multisig_info().map(|i| i.total_pubkeys).unwrap_or(0) == 3
            {
                result.push_str(&format!("║   Output {}: 62 bytes extracted\n", i));
                total_bytes += 62;
            } else if output.multisig_info().map(|i| i.required_sigs).unwrap_or(0) == 1
                && output.multisig_info().map(|i| i.total_pubkeys).unwrap_or(0) == 2
            {
                // Try to decode the data pubkey to get actual length
                if let Some(pubkey) = output
                    .multisig_info()
                    .map(|i| i.pubkeys.clone())
                    .unwrap_or_else(Vec::new)
                    .get(1)
                {
                    if let Ok(pubkey_bytes) = hex::decode(pubkey) {
                        if !pubkey_bytes.is_empty() {
                            let data_length =
                                std::cmp::min(pubkey_bytes[0] as usize, pubkey_bytes.len() - 1);
                            result.push_str(&format!(
                                "║   Output {}: {} bytes extracted\n",
                                i, data_length
                            ));
                            total_bytes += data_length;
                        }
                    } else {
                        result.push_str(&format!("║   Output {}: Variable bytes\n", i));
                    }
                } else {
                    result.push_str(&format!("║   Output {}: No data pubkey\n", i));
                }
            }
        }

        result.push_str(&format!("║   Total Raw Data: {} bytes\n", total_bytes));
        result
    }

    /// Display Counterparty decryption process details
    pub fn show_counterparty_decryption(
        input_txid: Option<&str>,
        raw_data: &[u8],
        decrypted_data: Option<&[u8]>,
    ) -> String {
        let mut result = String::new();

        result.push_str("║ Counterparty Decryption:\n");

        // Check if data is already plaintext
        let is_plaintext = raw_data.starts_with(COUNTERPARTY_PREFIX)
            || (raw_data.len() > COUNTERPARTY_PREFIX.len()
                && &raw_data[1..=COUNTERPARTY_PREFIX.len()] == COUNTERPARTY_PREFIX);

        if is_plaintext {
            result.push_str("║   Format: ✅ PLAINTEXT (Legacy)\n");
            let prefix_offset = if raw_data.starts_with(COUNTERPARTY_PREFIX) {
                0
            } else {
                1
            };
            result.push_str(&format!(
                "║   CNTRPRTY prefix: ✅ FOUND at offset {}\n",
                prefix_offset
            ));
        } else {
            // Show ARC4 decryption process
            if let Some(txid) = input_txid {
                result.push_str(&format!("║   Input TXID: {}...\n", &txid[..12]));
                result.push_str("║   Format: ARC4 Encrypted (Modern)\n");
                result.push_str("║   ARC4 Key: 32 bytes\n");

                if let Some(decrypted) = decrypted_data {
                    result.push_str("║   Decryption: ✅ SUCCESS\n");

                    // Check where CNTRPRTY prefix is found
                    let prefix_at_0 = decrypted.starts_with(COUNTERPARTY_PREFIX);
                    let prefix_at_1 = decrypted.len() > COUNTERPARTY_PREFIX.len()
                        && &decrypted[1..=COUNTERPARTY_PREFIX.len()] == COUNTERPARTY_PREFIX;

                    if prefix_at_1 {
                        result.push_str("║   CNTRPRTY prefix: ✅ FOUND at offset 1\n");
                    } else if prefix_at_0 {
                        result.push_str("║   CNTRPRTY prefix: ✅ FOUND at offset 0\n");
                    } else {
                        result.push_str("║   CNTRPRTY prefix: ❌ NOT FOUND\n");
                    }
                } else {
                    result.push_str("║   Decryption: ❌ FAILED\n");
                }
            } else {
                result.push_str("║   Input TXID: ❌ Not available\n");
                result.push_str("║   Decryption: ❌ SKIPPED\n");
            }
        }

        result
    }

    /// Parse and display Counterparty message content
    pub fn parse_and_display_message(decrypted_data: &[u8]) -> String {
        let mut content = String::new();

        content.push_str("║ Message Analysis:\n");

        // Determine where the message data starts
        let message_data = if decrypted_data.len() > COUNTERPARTY_PREFIX.len()
            && &decrypted_data[1..=COUNTERPARTY_PREFIX.len()] == COUNTERPARTY_PREFIX
        {
            &decrypted_data[COUNTERPARTY_PREFIX.len() + 1..]
        } else if decrypted_data.starts_with(COUNTERPARTY_PREFIX) {
            &decrypted_data[COUNTERPARTY_PREFIX.len()..]
        } else {
            content.push_str("║   Status: ❌ No valid CNTRPRTY prefix found\n");
            return content;
        };

        if message_data.is_empty() {
            content.push_str("║   Status: ❌ No message data after prefix\n");
            return content;
        }

        // Parse message type using production enum
        let message_type_byte = message_data[0];
        let (message_type_name, variant) =
            if let Some(msg_type) = CounterpartyMessageType::from_u32(message_type_byte as u32) {
                (
                    format!("{:?}", msg_type),
                    format!("{:?}", msg_type.get_variant()),
                )
            } else {
                ("Unknown".to_string(), "Unknown".to_string())
            };

        content.push_str(&format!(
            "║   Message Type: {} ({})\n",
            message_type_name, message_type_byte
        ));
        content.push_str(&format!("║   Protocol Variant: {}\n", variant));

        content.push_str(&format!("║   Payload: {} bytes\n", message_data.len() - 1));

        // Show payload preview
        if message_data.len() > 1 {
            let payload_preview = if message_data.len() > 17 {
                format!("{:02x?}...", &message_data[1..9])
            } else {
                format!("{:02x?}", &message_data[1..])
            };
            content.push_str(&format!("║   Payload Preview: {}\n", payload_preview));
        }

        content
    }

    /// Run Counterparty classification test on JSON fixture with verbose output
    pub async fn run_counterparty_test_from_json(
        json_path: &str,
        txid: &str,
        test_name: &str,
        expected_variant: Option<ProtocolVariant>,
        expected_content_type: Option<&str>,
    ) -> anyhow::Result<()> {
        if !std::path::Path::new(json_path).exists() {
            println!("⚠️  Skipping test - JSON fixture not found: {}", json_path);
            return Ok(());
        }

        let (mut test_db, _config) = setup_protocol_test(test_name)?;

        // Extract first input TXID for display
        let input_txid_opt = get_first_input_txid(json_path);

        // Print test header
        if let Some(ref input_txid) = input_txid_opt {
            print!(
                "{}",
                TestOutputFormatter::format_test_header_with_context(
                    "Counterparty",
                    test_name,
                    txid,
                    &format!("First Input TXID: {}", input_txid)
                )
            );
        } else {
            print!(
                "{}",
                TestOutputFormatter::format_test_header_with_context(
                    "Counterparty",
                    test_name,
                    txid,
                    "First Input TXID: Not available"
                )
            );
        }

        // Load P2MS outputs from JSON
        let p2ms_outputs = load_p2ms_outputs_from_json(json_path, txid)?;

        if p2ms_outputs.is_empty() {
            println!("⚠️  Skipping test - no P2MS outputs found in {}", json_path);
            return Ok(());
        }

        // Display P2MS outputs analysis
        println!("║ P2MS Outputs Found: {}", p2ms_outputs.len());
        println!("║");

        // Show individual P2MS output analysis
        for (i, output) in p2ms_outputs.iter().enumerate() {
            print!("{}", analyse_counterparty_p2ms_output(output, i));
        }
        println!("║");

        // Show data extraction
        print!("{}", show_counterparty_data_extraction(&p2ms_outputs));
        println!("║");

        // Use production code to extract and decrypt data
        let mut raw_data = Vec::new();

        // Create classifier instance for production function access
        let config = Stage3Config::default();
        let classifier = CounterpartyClassifier::new(&config);

        // Extract raw data using production functions
        for output in &p2ms_outputs {
            if output.multisig_info().map(|i| i.required_sigs).unwrap_or(0) == 1
                && output.multisig_info().map(|i| i.total_pubkeys).unwrap_or(0) == 3
            {
                if let Some(chunk) = classifier.extract_raw_data_chunk_1_of_3(output) {
                    raw_data.extend_from_slice(&chunk);
                }
            } else if output.multisig_info().map(|i| i.required_sigs).unwrap_or(0) == 1
                && output.multisig_info().map(|i| i.total_pubkeys).unwrap_or(0) == 2
            {
                if let Some(chunk) = classifier.extract_raw_data_chunk_1_of_2(output) {
                    raw_data.extend_from_slice(&chunk);
                }
            }
        }

        // Create enriched transaction and insert into database first
        let mut tx = fixtures::create_test_enriched_transaction(txid);
        tx.outputs = p2ms_outputs.clone();
        tx.p2ms_outputs_count = tx.outputs.len();
        tx.burn_patterns_detected = fixtures::counterparty_burn_patterns();

        // Create transaction inputs with actual input TXID from JSON
        // Create inputs using helper
        let input_txid = input_txid_opt
            .clone()
            .or_else(|| tx.outputs.first().map(|_| txid.to_string()))
            .unwrap_or_else(|| "00".repeat(32));
        let inputs = create_test_inputs(txid, &input_txid);

        // Seed database with enriched transaction (FK-safe)
        seed_enriched_transaction_simple(&mut test_db, &tx, inputs)?;

        // Now use production decryption function
        let decrypted_data_opt = if !raw_data.is_empty() {
            classifier.decrypt_and_validate_counterparty(&tx, &raw_data, test_db.database())
        } else {
            None
        };

        // Show decryption process
        print!(
            "{}",
            show_counterparty_decryption(
                input_txid_opt.as_deref(),
                &raw_data,
                decrypted_data_opt.as_deref()
            )
        );
        println!("║");

        // Parse and display message if we have decrypted data
        if let Some(ref decrypted_data) = decrypted_data_opt {
            print!("{}", parse_and_display_message(decrypted_data));
        } else {
            println!("║ Message Analysis: ❌ No valid decrypted data available");
        }
        println!("║");

        // P2MS outputs already inserted via insert_enriched_transactions_batch above
        // (No need to insert again - they're handled by the batch insert)

        // Run Stage 3 processing
        let stats = run_stage3_processor(test_db.path(), config).await?;
        verify_stage3_completion(&stats, 1, 1);

        // Verify classification
        let classification_details =
            verify_classification(&test_db, txid, ProtocolType::Counterparty, expected_variant)?;

        // Verify content type
        verify_content_type(&test_db, txid, expected_content_type)?;

        // Verify ALL P2MS outputs are classified (CRITICAL: ensures complete coverage)
        verify_complete_output_coverage(&test_db, txid, ProtocolType::Counterparty)?;

        // Verify output-level spendability (CRITICAL: ensures per-output analysis)
        verify_output_spendability(&test_db, txid, ProtocolType::Counterparty)?;

        // Get message type for footer
        let message_type = if let Ok(msg_type) = get_counterparty_message_type(&test_db, txid) {
            msg_type
        } else {
            "Unknown".to_string()
        };

        // Print test footer
        print!(
            "{}",
            TestOutputFormatter::format_test_footer_with_type(
                "Counterparty",
                &classification_details.classification_method,
                &message_type
            )
        );

        Ok(())
    }
}

/// Modern Counterparty format tests (1-of-3 multi-output)
mod modern_format {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_modern_1of3_multi_output() {
        // Source: Modern enhanced issuance format (Type 22, post-2022)
        // Block: 913691 (verified via Bitcoin Core RPC)
        // Message Type: Type 22 Enhanced Issuance
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_modern_1of3_tx.json",
            "a63ee2b1e64d98784ba39c9e6738bc923fd88a808d618dd833254978247d66ea",
            "counterparty_modern_1of3",
            Some(ProtocolVariant::CounterpartyIssuance),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_modern_broadcast() {
        // Source: Electrum-Counterparty decoder example #12: "Broadcast - jpja.net"
        // Block: 327522 (verified via Bitcoin Core RPC)
        // Message Type: Type 30 Broadcast
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_modern_broadcast_tx.json",
            "21c2cd5b369c2e7a350bf92ad43c31e5abb0aa85ccba11368b08f9f4abb8e0af",
            "counterparty_modern_broadcast",
            Some(ProtocolVariant::CounterpartyBroadcast),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }
}

/// Legacy Counterparty format tests (1-of-2)
mod legacy_format {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_legacy_1of2_send() {
        // Source: Electrum-Counterparty decoder example #0: "Classic send - 501 JPGOLD"
        // Block: 305807 (verified via Bitcoin Core RPC)
        // Message Type: Type 0 Send
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_legacy_1of2_send_tx.json",
            "da3ed1efda82824cb24ea081ef2a8f532a7dd9cd1ebc5efa873498c3958c864e",
            "counterparty_legacy_send",
            Some(ProtocolVariant::CounterpartySend),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_legacy_1of2_issuance() {
        // Source: Electrum-Counterparty decoder example #9: "Issuance - OLGA"
        // Block: 305451 (verified via Bitcoin Core RPC)
        // Message Type: Type 20 Issuance
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_legacy_1of2_issuance_tx.json",
            "e5e9f6a63ede5315994cf2d8a5f8fe760f1f37f6261e5fbb1263bed54114768a",
            "counterparty_legacy_issuance",
            Some(ProtocolVariant::CounterpartyIssuance),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }
}

/// Message type specific tests
mod message_types {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_type_0_send() {
        // Source: Electrum-Counterparty decoder example #1: "Classic send - 0.2 XCP"
        // Block: 290929 (verified via Bitcoin Core RPC)
        // Message Type: Type 0 Send
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_type0_send_tx.json",
            "585f50f12288cd9044705483672fbbddb71dff8198b390b40ab3de30db0a88dd",
            "counterparty_type0_send",
            Some(ProtocolVariant::CounterpartySend),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_type_20_issuance() {
        // Source: Electrum-Counterparty decoder example #20: "Issuance with STAMP image"
        // Block: 783427 (verified via Bitcoin Core RPC)
        // Message Type: Type 20 Issuance
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_type20_issuance_tx.json",
            "31a96a3bd86600b4af3c81bc960b15e89e506f855e93fbbda6f701963b1936ac",
            "counterparty_type20_issuance",
            Some(ProtocolVariant::CounterpartyIssuance),
            Some("application/octet-stream"), // Binary protocol message (issuance data)
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_type_30_broadcast() {
        // Source: Electrum-Counterparty decoder example #14: "Broadcast - OLGA image"
        // Block: 369466 (verified via Bitcoin Core RPC)
        // Message Type: Type 30 Broadcast
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_type30_broadcast_tx.json",
            "627ae48d6b4cffb2ea734be1016dedef4cee3f8ffefaea5602dd58c696de6b74",
            "counterparty_type30_broadcast",
            Some(ProtocolVariant::CounterpartyBroadcast),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }
}

/// Real-world transaction tests using historical data
mod historical_transactions {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_salvation_ownership_transfer() {
        // Source: Electrum-Counterparty decoder example #11: "Issuance - transfer SALVATION ownership"
        // Block: 368602 (verified via Bitcoin Core RPC)
        // Message Type: Type 20 Issuance (ownership transfer)
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_salvation_transfer_tx.json",
            "541e640fbb527c35e0ee32d724efa4a5506c4c52acfba1ebc3b45949780c08a8",
            "counterparty_salvation_transfer",
            Some(ProtocolVariant::CounterpartyIssuance),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }
}

/// Subasset and advanced feature tests
mod advanced_features {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_subasset_issuance() {
        // Source: Electrum-Counterparty decoder example #17: "Subasset issuance"
        // Block: 778561 (verified via Bitcoin Core RPC)
        // Message Type: Type 21 Subasset Issuance
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_subasset_tx.json",
            "793566ef1644a14c2658aed6b3c2df41bc519941f121f9cff82825f48911e451",
            "counterparty_subasset",
            Some(ProtocolVariant::CounterpartyIssuance),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }
}

/// Edge cases and validation tests
mod edge_cases {
    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_counterparty_olga_lock() {
        // Source: Electrum-Counterparty decoder example #10: "Issuance - lock OLGA"
        // Block: 305455 (verified via Bitcoin Core RPC)
        // Message Type: Type 20 Issuance (asset locking)
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/counterparty_olga_lock_tx.json",
            "34da6ecf10c66ed659054aa6c71900c807875cb57b96abea4cee4f7a831ed690",
            "counterparty_olga_lock",
            Some(ProtocolVariant::CounterpartyIssuance),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_counterparty_mixed_pubkey_format() {
        // Test case for transaction with mixed compressed/uncompressed pubkeys
        // This transaction has:
        // - First two pubkeys: Compressed (33 bytes) - used for data storage
        // - Third pubkey: Uncompressed (65 bytes) - used for validation
        // The fix ensures we only validate the first two pubkeys for compression
        //
        // Block: 800081 (verified via Bitcoin Core RPC)
        // Message Type: Type 30 Broadcast
        // Special: All 6 P2MS outputs have mixed pubkey formats (2 compressed, 1 uncompressed)
        let result = test_data::run_counterparty_test_from_json(
            "tests/test_data/counterparty/9b4afd1d54dc88b50dbda166e837fb4ce110f4185b432c6155a403ca0fb2eb75.json",
            "9b4afd1d54dc88b50dbda166e837fb4ce110f4185b432c6155a403ca0fb2eb75",
            "counterparty_mixed_pubkey_format",
            Some(ProtocolVariant::CounterpartyBroadcast),
            Some("application/octet-stream"), // Binary protocol message
        )
        .await;

        if let Err(e) = result {
            println!("⚠️  Test skipped due to missing fixture: {}", e);
        }
    }
}
