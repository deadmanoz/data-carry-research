/// ARC4 deobfuscation utility for examining P2MS data
///
/// This module provides a standalone tool to perform ARC4 deobfuscation on
/// Bitcoin P2MS transaction data. It attempts three decryption paths:
///
/// 1. **Counterparty**: Per-62-byte-chunk ARC4 with length prefixes
/// 2. **Bitcoin Stamps**: Simple concatenation + single ARC4 (both pure and Counterparty-embedded)
/// 3. **Raw fallback**: If neither matches, attempt simple ARC4 for protocol discovery
///
/// This is useful for:
/// - Examining ARC4-encrypted data in transactions
/// - Discovering new protocols that use ARC4 encryption
/// - Debugging protocol classification issues
/// - Understanding how different protocols structure their P2MS data
use crate::crypto::arc4;
use crate::decoder::protocol_detection::TransactionData;
use crate::processor::stage3::counterparty::CounterpartyClassifier;
use crate::rpc::BitcoinRpcClient;
use crate::types::counterparty::COUNTERPARTY_PREFIX;
use crate::types::stamps::validation::{self, StampsProcessingResult};
use crate::types::stamps::StampsTransport;
use crate::types::TransactionOutput;
use anyhow::{Context, Result};

/// Result of ARC4 deobfuscation analysis
#[derive(Debug)]
pub struct Arc4Result {
    pub txid: String,
    pub input_txid: String,
    pub p2ms_output_count: usize,

    /// Counterparty path result (if detected)
    pub counterparty: Option<CounterpartyArc4>,

    /// Bitcoin Stamps path result (if detected)
    pub stamps: Option<StampsArc4>,

    /// Raw fallback result (if neither protocol matched)
    pub raw_fallback: Option<RawArc4>,
}

/// Counterparty ARC4 decryption result
#[derive(Debug)]
pub struct CounterpartyArc4 {
    /// Raw P2MS data before decryption (Counterparty extraction: 31 bytes/chunk)
    pub raw_data: Vec<u8>,

    /// Decrypted data after per-chunk ARC4
    pub decrypted: Vec<u8>,
}

/// Bitcoin Stamps ARC4 decryption result
#[derive(Debug)]
pub struct StampsArc4 {
    /// Raw P2MS data before decryption (Stamps extraction: full pubkeys)
    pub raw_data: Vec<u8>,

    /// Decrypted data after ARC4
    pub decrypted: Vec<u8>,

    /// Offset of "stamp:" signature in decrypted data
    pub signature_offset: usize,

    /// Transport mechanism used
    pub transport: StampsTransport,
}

/// Raw ARC4 decryption result (fallback for unknown protocols)
#[derive(Debug)]
pub struct RawArc4 {
    /// Raw P2MS data before decryption
    pub raw_data: Vec<u8>,

    /// Decrypted data after simple ARC4
    pub decrypted: Vec<u8>,
}

/// Perform ARC4 deobfuscation analysis on a transaction
///
/// This function attempts to deobfuscate P2MS data using three methods:
/// 1. Counterparty per-chunk decryption
/// 2. Bitcoin Stamps processing (handles both pure and Counterparty-embedded)
/// 3. Raw ARC4 fallback (if neither protocol matches)
///
/// # Arguments
///
/// * `txid` - Transaction ID to analyse
/// * `rpc_client` - Bitcoin Core RPC client for fetching transaction data
///
/// # Returns
///
/// Returns `Arc4Result` containing results from all attempted decryption paths.
/// At least one path will typically succeed if the transaction contains P2MS outputs.
pub async fn deobfuscate_transaction(
    txid: &str,
    rpc_client: &BitcoinRpcClient,
) -> Result<Arc4Result> {
    // 1. Fetch transaction via RPC
    let tx = rpc_client
        .get_transaction(txid)
        .await
        .context("Failed to fetch transaction from Bitcoin Core")?;

    let tx_data = TransactionData {
        txid: txid.to_string(),
        transaction: tx,
    };

    // 2. Extract P2MS outputs
    let p2ms_outputs = tx_data.p2ms_outputs();
    anyhow::ensure!(
        !p2ms_outputs.is_empty(),
        "No P2MS outputs found in transaction"
    );

    // 3. Get ARC4 key from first input TXID
    let input_txid = tx_data
        .first_input_txid()
        .context("No input transactions found (coinbase or unusual transaction)")?;

    let arc4_key = arc4::prepare_key_from_txid(&input_txid)
        .context("Failed to prepare ARC4 key from input TXID")?;

    // 4. Try Counterparty decryption path
    let counterparty = try_counterparty_path(&p2ms_outputs, &input_txid);

    // 5. Try Bitcoin Stamps processing path (handles both pure and Counterparty-embedded)
    let stamps = try_stamps_path(&p2ms_outputs, &arc4_key);

    // 6. If neither protocol matched, try raw ARC4 fallback for unknown protocols
    let raw_fallback = if counterparty.is_none() && stamps.is_none() {
        try_raw_arc4_fallback(&p2ms_outputs, &arc4_key)
    } else {
        None
    };

    Ok(Arc4Result {
        txid: txid.to_string(),
        input_txid,
        p2ms_output_count: p2ms_outputs.len(),
        counterparty,
        stamps,
        raw_fallback,
    })
}

/// Try Counterparty decryption path
///
/// Uses per-62-byte-chunk ARC4 decryption with length prefixes, as specified
/// in the Counterparty protocol.
fn try_counterparty_path(
    p2ms_outputs: &[TransactionOutput],
    input_txid: &str,
) -> Option<CounterpartyArc4> {
    let classifier = CounterpartyClassifier::new();

    // Try multi-output extraction first
    if let Some(raw_data) = classifier.extract_multi_output_raw_data(p2ms_outputs) {
        if let Some(decrypted) =
            classifier.decrypt_counterparty_data_with_txid(&raw_data, input_txid)
        {
            return Some(CounterpartyArc4 {
                raw_data,
                decrypted,
            });
        }
    }

    // Fallback: try single-output extraction on ALL outputs (not just first!)
    // This handles transactions with a single data-bearing P2MS output
    for output in p2ms_outputs {
        if let Some(raw_data) = classifier.extract_single_output_raw_data(output) {
            if let Some(decrypted) =
                classifier.decrypt_counterparty_data_with_txid(&raw_data, input_txid)
            {
                return Some(CounterpartyArc4 {
                    raw_data,
                    decrypted,
                });
            }
        }
    }

    None
}

/// Try Bitcoin Stamps processing path
///
/// Calls the production Stamps processing function which handles:
/// - Pure Bitcoin Stamps (simple concatenation + single ARC4)
/// - Counterparty-embedded Stamps (per-chunk decryption then Stamps validation)
fn try_stamps_path(p2ms_outputs: &[TransactionOutput], arc4_key: &[u8]) -> Option<StampsArc4> {
    // Call production function (handles both pure and Counterparty-embedded)
    let stamps_result = validation::process_multioutput_stamps(p2ms_outputs, arc4_key)?;

    // Destructure to avoid partial move
    let StampsProcessingResult {
        valid_outputs,
        concatenated_data_size: _,
        decrypted_data,
        stamp_signature_offset,
        stamp_signature_variant: _,
    } = stamps_result;

    // Reconstruct raw data from ONLY the valid outputs that were actually used
    // This matches what was fed into ARC4 decryption
    let raw_data = extract_stamps_raw_data_from_valid_outputs(&valid_outputs)?;

    // Determine transport mechanism
    let transport = if decrypted_data
        .windows(COUNTERPARTY_PREFIX.len())
        .any(|w| w == COUNTERPARTY_PREFIX)
    {
        StampsTransport::Counterparty
    } else {
        StampsTransport::Pure
    };

    Some(StampsArc4 {
        raw_data,
        decrypted: decrypted_data,
        signature_offset: stamp_signature_offset,
        transport,
    })
}

/// Extract raw P2MS data from valid Stamps outputs
///
/// This reconstructs the exact bytes that were fed into ARC4 decryption,
/// using only the outputs that produced valid Stamps data.
fn extract_stamps_raw_data_from_valid_outputs(
    valid_outputs: &[&TransactionOutput],
) -> Option<Vec<u8>> {
    let mut concatenated = Vec::new();

    for output in valid_outputs {
        if let Some(info) = output.multisig_info() {
            if let Some(chunk) = validation::extract_data_chunk(&info.pubkeys) {
                concatenated.extend(chunk);
            }
        }
    }

    if concatenated.is_empty() {
        None
    } else {
        Some(concatenated)
    }
}

/// Try raw ARC4 fallback for unknown protocols
///
/// If neither Counterparty nor Bitcoin Stamps patterns match, this performs
/// a simple concatenation of all P2MS data followed by single ARC4 decryption.
///
/// This is useful for discovering new or unknown protocols that may be using
/// ARC4 encryption with similar patterns.
fn try_raw_arc4_fallback(p2ms_outputs: &[TransactionOutput], arc4_key: &[u8]) -> Option<RawArc4> {
    // Simple concatenation of ALL P2MS data (Stamps-style extraction)
    let mut raw_data = Vec::new();

    for output in p2ms_outputs {
        if let Some(info) = output.multisig_info() {
            // Use Stamps-style extraction (full pubkey payloads)
            if let Some(chunk) = validation::extract_data_chunk(&info.pubkeys) {
                raw_data.extend(chunk);
            }
        }
    }

    if raw_data.is_empty() {
        return None;
    }

    // Single ARC4 decrypt attempt
    let decrypted = arc4::decrypt(&raw_data, arc4_key)?;

    Some(RawArc4 {
        raw_data,
        decrypted,
    })
}
