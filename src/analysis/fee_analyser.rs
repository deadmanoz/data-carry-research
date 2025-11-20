use crate::types::{FeeAnalysis, TransactionInput, TransactionOutput};
use corepc_client::bitcoin::Transaction;
use tracing::debug;

/// Fee analysis engine for comprehensive transaction cost calculations
pub struct FeeAnalyser;

impl FeeAnalyser {
    /// Perform comprehensive fee analysis for a transaction
    pub fn analyse_fees(
        transaction: &Transaction,
        inputs: &[TransactionInput],
        p2ms_outputs: &[TransactionOutput],
    ) -> FeeAnalysis {
        // Calculate total input and output values
        let total_input_value: u64 = inputs.iter().map(|input| input.value).sum();
        let total_output_value: u64 = transaction
            .output
            .iter()
            .map(|output| output.value.to_sat())
            .sum();

        // Calculate transaction fee
        let transaction_fee = if transaction.is_coinbase() {
            0 // Coinbase transactions don't have fees
        } else {
            total_input_value.saturating_sub(total_output_value)
        };

        // Transaction size analysis for fee rates
        let transaction_size_bytes = Self::calculate_transaction_size(transaction);
        let fee_per_byte = if transaction_size_bytes > 0 && !transaction.is_coinbase() {
            transaction_fee as f64 / transaction_size_bytes as f64
        } else {
            0.0
        };
        let fee_per_kb = fee_per_byte * 1000.0;

        // P2MS specific analysis
        let total_p2ms_amount: u64 = p2ms_outputs.iter().map(|output| output.amount).sum();

        let p2ms_data_size: usize = p2ms_outputs.iter().map(|output| output.script_size).sum();

        let data_storage_fee_rate = if p2ms_data_size > 0 && !transaction.is_coinbase() {
            transaction_fee as f64 / p2ms_data_size as f64
        } else {
            0.0
        };

        debug!(
            "Fee analysis: fee={} sats, size={} bytes, fee_rate={:.2} sat/byte, data_rate={:.2} sat/byte",
            transaction_fee, transaction_size_bytes, fee_per_byte, data_storage_fee_rate
        );

        FeeAnalysis {
            total_input_value,
            total_output_value,
            transaction_fee,
            fee_per_byte,
            transaction_size_bytes,
            fee_per_kb,
            total_p2ms_amount,
            data_storage_fee_rate,
            p2ms_outputs_count: p2ms_outputs.len(),
        }
    }

    /// Calculate the size of a transaction in bytes
    fn calculate_transaction_size(transaction: &Transaction) -> u32 {
        // Use the built-in size calculation from the bitcoin crate
        transaction.vsize() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corepc_client::bitcoin::{Amount, ScriptBuf, TxOut};

    fn create_test_p2ms_output(amount: u64, script_size: usize) -> TransactionOutput {
        use crate::types::script_metadata::MultisigInfo;

        let multisig_info = MultisigInfo {
            pubkeys: vec!["normal_key".to_string()],
            required_sigs: 1,
            total_pubkeys: 1,
        };

        TransactionOutput {
            txid: "test".to_string(),
            vout: 0,
            height: 100000,
            amount,
            script_hex: "test".to_string(),
            script_type: "multisig".to_string(),
            is_coinbase: false,
            script_size,
            metadata: serde_json::to_value(multisig_info).unwrap(),
            address: None,
        }
    }

    fn create_test_input(value: u64) -> TransactionInput {
        TransactionInput {
            txid: "input_tx".to_string(),
            vout: 0,
            value,
            script_sig: "script".to_string(),
            sequence: 0xffffffff,
            source_address: Some("1TestSourceAddress123456789".to_string()),
        }
    }

    #[test]
    fn test_fee_analysis_regular_transaction() {
        // Create a simple transaction with known values
        let outputs = vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: ScriptBuf::new(),
            },
        ];

        let transaction = Transaction {
            version: corepc_client::bitcoin::transaction::Version(1),
            lock_time: corepc_client::bitcoin::absolute::LockTime::ZERO,
            input: vec![], // Will be populated properly in real use
            output: outputs,
        };

        let inputs = vec![create_test_input(5000)]; // 5000 in, 3000 out = 2000 fee
        let p2ms_outputs = vec![create_test_p2ms_output(1000, 100)];

        let analysis = FeeAnalyser::analyse_fees(&transaction, &inputs, &p2ms_outputs);

        assert_eq!(analysis.total_input_value, 5000);
        assert_eq!(analysis.total_output_value, 3000);
        assert_eq!(analysis.transaction_fee, 2000);
        assert_eq!(analysis.total_p2ms_amount, 1000);
        assert_eq!(analysis.p2ms_outputs_count, 1);
        assert!(analysis.fee_per_byte > 0.0);
        assert!(analysis.data_storage_fee_rate > 0.0);
    }
}
