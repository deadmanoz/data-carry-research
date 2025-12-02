//! Common types shared across all processing stages
//!
//! This module contains fundamental types that are used throughout the Bitcoin P2MS analysis pipeline,
//! including UTXO records, P2MS outputs, and core data structures.

use serde::{Deserialize, Serialize};

/// Raw UTXO record from CSV file - matches the exact CSV structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoRecord {
    pub count: u64,
    pub txid: String,
    pub vout: u32,
    pub height: u32,
    pub coinbase: u8,   // 0 or 1
    pub amount: u64,    // Satoshis
    pub script: String, // Hex-encoded script
    #[serde(rename = "type")]
    pub script_type: String, // "p2ms" (bare multisig), "p2pkh", "nonstandard", etc.
    // Note: bitcoin-utxo-dump uses "p2ms" while Bitcoin Core uses "multisig"
    pub address: String, // Empty for P2MS
}

impl UtxoRecord {
    /// Check if this record is a P2MS output
    pub fn is_p2ms(&self) -> bool {
        self.script_type == "p2ms"
    }

    /// Check if this UTXO record should be processed for data analysis
    pub fn should_process_for_data(&self) -> bool {
        matches!(self.script_type.as_str(), "p2ms" | "nonstandard")
    }

    /// Convert to TransactionOutput with proper metadata based on script type
    pub fn to_transaction_output(&self) -> Result<TransactionOutput, crate::errors::AppError> {
        // Parse script type and metadata together to handle nonstandard detection
        let (normalised_script_type, metadata) = match self.script_type.as_str() {
            "p2ms" => {
                // Try to parse as standard multisig using shared parser
                match crate::types::script_metadata::parse_p2ms_script(&self.script) {
                    Ok((pubkeys, required_sigs, total_pubkeys)) => {
                        // Successfully parsed - this IS standard multisig
                        let info = crate::types::script_metadata::MultisigInfo {
                            pubkeys,
                            required_sigs,
                            total_pubkeys,
                        };
                        let metadata = serde_json::to_value(info)
                            .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
                        ("multisig".to_string(), metadata)
                    }
                    Err(_) => {
                        // Parser failed - nonstandard multisig-like script
                        // Treat same as "nonstandard" from bitcoin-utxo-dump
                        let info =
                            crate::types::script_metadata::parse_nonstandard_script(&self.script);
                        let metadata = serde_json::to_value(info)
                            .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
                        ("nonstandard".to_string(), metadata)
                    }
                }
            }
            "nonstandard" => {
                // Already marked as nonstandard by bitcoin-utxo-dump
                let info = crate::types::script_metadata::parse_nonstandard_script(&self.script);
                let metadata = serde_json::to_value(info)
                    .unwrap_or_else(|_| serde_json::Value::Object(Default::default()));
                ("nonstandard".to_string(), metadata)
            }
            other => {
                // Pass through other script types unchanged
                (
                    other.to_string(),
                    serde_json::Value::Object(Default::default()),
                )
            }
        };

        Ok(TransactionOutput {
            txid: self.txid.clone(),
            vout: self.vout,
            height: self.height,
            amount: self.amount,
            script_hex: self.script.clone(),
            script_type: normalised_script_type,
            is_coinbase: self.coinbase == 1,
            script_size: self.script.len() / 2,
            metadata,
            address: None, // Stage 1 doesn't extract addresses; Stage 2 will populate this
        })
    }
}

/// Generic transaction output for database storage
///
/// This structure stores ALL outputs for transactions containing at least one P2MS output.
/// Stage 1 (CSV) writes P2MS outputs only with placeholder address=None.
/// Stage 2 (RPC) writes ALL outputs with actual addresses from Bitcoin Core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub txid: String,
    pub vout: u32,
    pub height: u32,
    pub amount: u64,
    pub script_hex: String,
    pub script_type: String, // "multisig" (Bitcoin Core naming), "nonstandard", "op_return", etc.
    pub is_coinbase: bool,
    pub script_size: usize,
    pub metadata: serde_json::Value, // Script-specific parsed data
    pub address: Option<String>,     // Bitcoin address (None for OP_RETURN, unspendable, etc.)
}

impl TransactionOutput {
    /// Create a unique key for this output (txid:vout)
    pub fn output_key(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }

    /// Helper methods for accessing typed metadata
    /// Get multisig information if this is a multisig-like script
    pub fn multisig_info(&self) -> Option<crate::types::script_metadata::MultisigInfo> {
        serde_json::from_value(self.metadata.clone()).ok()
    }

    /// Get nonstandard script information
    pub fn nonstandard_info(&self) -> Option<crate::types::script_metadata::NonstandardInfo> {
        serde_json::from_value(self.metadata.clone()).ok()
    }

    /// Check if this output is a multisig type
    pub fn is_p2ms(&self) -> bool {
        self.script_type == "multisig"
    }

    /// Check if this output is nonstandard
    pub fn is_nonstandard(&self) -> bool {
        self.script_type == "nonstandard"
    }
}

/// Fee analysis results for a transaction
#[derive(Debug, Clone)]
pub struct FeeAnalysis {
    pub total_input_value: u64,
    pub total_output_value: u64,
    pub transaction_fee: u64,
    pub fee_per_byte: f64,
    pub transaction_size_bytes: u32,
    pub fee_per_kb: f64,
    pub total_p2ms_amount: u64,
    pub data_storage_fee_rate: f64,
    pub p2ms_outputs_count: usize,
}

/// Transaction input data from RPC calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub txid: String,                   // Previous transaction ID
    pub vout: u32,                      // Previous output index
    pub value: u64,                     // Value in satoshis
    pub script_sig: String,             // Hex-encoded script signature
    pub sequence: u32,                  // Sequence number
    pub source_address: Option<String>, // Address that funded this input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_record_is_p2ms() {
        let p2ms_record = UtxoRecord {
            count: 1,
            txid: "test_txid".to_string(),
            vout: 0,
            height: 100000,
            coinbase: 0,
            amount: 1000,
            script: "5121...53ae".to_string(),
            script_type: "p2ms".to_string(),
            address: "".to_string(),
        };

        let non_p2ms_record = UtxoRecord {
            count: 2,
            txid: "test_txid2".to_string(),
            vout: 1,
            height: 100001,
            coinbase: 0,
            amount: 2000,
            script: "76a914...88ac".to_string(),
            script_type: "p2pkh".to_string(),
            address: "1ABC...".to_string(),
        };

        assert!(p2ms_record.is_p2ms());
        assert!(!non_p2ms_record.is_p2ms());
    }

    #[test]
    fn test_utxo_record_to_transaction_output() {
        let p2ms_record = UtxoRecord {
            count: 1,
            txid: "test_txid".to_string(),
            vout: 0,
            height: 100000,
            coinbase: 1,
            amount: 1000,
            script: "5121...53ae".to_string(),
            script_type: "p2ms".to_string(),
            address: "".to_string(),
        };

        let output = p2ms_record.to_transaction_output().unwrap();
        assert_eq!(output.txid, "test_txid");
        assert_eq!(output.vout, 0);
        assert_eq!(output.height, 100000);
        assert_eq!(output.amount, 1000);
        assert_eq!(output.script_hex, "5121...53ae");
        assert!(output.is_coinbase);
        // Script parsing will fail for invalid hex, so it becomes nonstandard
        assert_eq!(output.script_size, 5); // "5121...53ae".len() / 2
    }

    #[test]
    fn test_p2ms_output_key() {
        let output = TransactionOutput {
            txid: "abc123".to_string(),
            vout: 5,
            height: 100000,
            amount: 1000,
            script_hex: "script".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size: 0,
            metadata: serde_json::json!({}),
            address: None,
        };

        assert_eq!(output.output_key(), "abc123:5");
    }

    #[test]
    fn test_p2ms_script_parsing() {
        use crate::types::parse_p2ms_script;

        // Test a valid 1-of-2 P2MS script: OP_1 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
        let valid_script = "51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179852ae";

        let result = parse_p2ms_script(valid_script);
        assert!(result.is_ok());

        let (pubkeys, required_sigs, total_pubkeys) = result.unwrap();
        assert_eq!(required_sigs, 1);
        assert_eq!(total_pubkeys, 2);
        assert_eq!(pubkeys.len(), 2);

        // Test invalid script
        let invalid_script = "invalid_hex";
        let result = parse_p2ms_script(invalid_script);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonstandard_multisig_classification() {
        use crate::types::parse_p2ms_script;

        // Real nonstandard multisig script from blockchain (TXID: 72590fcf0d8021bad77826c5008eaca3541f81d212d55bb7c02ec6a4bf584404)
        // This is a 1-of-3 structure but uses OP_PUSHDATA1 with 120-byte data chunks instead of standard pubkeys
        // Bitcoin Core classifies this as "nonstandard", not "multisig"
        let nonstandard_script = "514c78ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4c78ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4c78ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff53ae";

        // Parser should fail on this (it only handles 0x21/0x41 pubkey markers)
        let parse_result = parse_p2ms_script(nonstandard_script);
        assert!(
            parse_result.is_err(),
            "Parser should fail on nonstandard multisig with OP_PUSHDATA1"
        );

        // Now test the full conversion pipeline
        let utxo_record = UtxoRecord {
            count: 1,
            txid: "72590fcf0d8021bad77826c5008eaca3541f81d212d55bb7c02ec6a4bf584404".to_string(),
            vout: 0,
            height: 244029,
            coinbase: 0,
            amount: 10000,
            script_type: "p2ms".to_string(), // bitcoin-utxo-dump classifies as p2ms
            script: nonstandard_script.to_string(),
            address: "".to_string(),
        };

        let tx_output = utxo_record
            .to_transaction_output()
            .expect("Conversion should succeed");

        // CRITICAL: Should be classified as "nonstandard" (NOT "multisig")
        assert_eq!(
            tx_output.script_type, "nonstandard",
            "Nonstandard multisig-like script should be classified as 'nonstandard'"
        );

        // Metadata should be populated via try_parse_nonstandard_script()
        assert_ne!(
            tx_output.metadata,
            serde_json::Value::Object(Default::default()),
            "Nonstandard metadata should be present"
        );
    }
}

#[test]
fn test_omni_property_managed_script_parsing() {
    use crate::types::parse_p2ms_script;

    let script_hex = "514104dc82c5812af7e44e40f16e5e03607935c0d3e531096e94deae1263f3b464a898232f90f7f3d747ff693dd796ea9df9df3b7c838591bf570db160f858b0130e7621024a0fe93b27241f8d449a2bba5ba7e55890ebe02155508d18499db3d18bc7d2902102b344aa1859ad54fa42c4fc97842b7ddd9fa65d86ba1e80af84e53cee3e4b55d153ae";

    let result = parse_p2ms_script(script_hex);
    println!("Parsing result: {:?}", result);

    match result {
        Ok((pubkeys, required_sigs, total_pubkeys)) => {
            println!("✅ Parsing successful!");
            println!("Required sigs: {}", required_sigs);
            println!("Total pubkeys: {}", total_pubkeys);
            println!("Pubkeys found: {}", pubkeys.len());
            assert_eq!(required_sigs, 1);
            assert_eq!(total_pubkeys, 3);
            assert_eq!(pubkeys.len(), 3);
        }
        Err(e) => {
            println!("❌ Parsing failed: {}", e);
            panic!("Parsing should succeed");
        }
    }
}
