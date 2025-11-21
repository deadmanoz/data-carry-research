//! PPk Protocol Decoder
//!
//! PPk (PPkPub) is an abandoned blockchain infrastructure protocol from Beijing University
//! of Posts and Telecommunications (2015-2019) that attempted to create a decentralised
//! naming and identity system built on Bitcoin.
//!
//! This decoder extracts PPk protocol data and constructs ODIN identifiers for resource location.
//!
//! ODIN Format: `ppk:[BLOCK_HEIGHT].[TRANSACTION_INDEX]/[DSS]`
//! - BLOCK_HEIGHT: Bitcoin block height
//! - TRANSACTION_INDEX: Transaction position within block (0-indexed)
//! - DSS: Data Specification String (resource path from OP_RETURN or P2MS data)
//!
//! Key characteristics:
//! - Marker pubkey in position 2: 0320a0de360cc2ae8672db7d557086a4e7c8eca062c0a5a4ba9922dee0aacf3e12
//! - 4 variants: Profile, Registration, Message, Unknown
//! - RT variants use TLV encoding: [RT:2][Length:1][JSON:variable]
//! - Registration uses quoted number strings: "315"}
//! - Message contains "PPk"/"ppk" substring or ≥80% printable ASCII
//!
//! References:
//! - https://github.com/ppkpub/SDK (archived 2015-2019)
//! - http://ppkpub.org (defunct)

use crate::decoder::protocol_detection::{DecodedProtocol, TransactionData};
use crate::rpc::BitcoinRpcClient;
use crate::types::ppk::{detect_ppk_variant, OdinIdentifier, PPkDetectionResult};
use tracing::{debug, info, warn};

/// Try to decode transaction as PPk protocol
///
/// This function:
/// 1. Calls shared `detect_ppk_variant()` for variant detection (DRY)
/// 2. Constructs ODIN identifier using RPC (for RT variants only)
/// 3. Returns DecodedProtocol::PPk with extracted data
///
/// Returns Some(DecodedProtocol::PPk) if valid PPk data found
pub async fn try_ppk(
    tx_data: &TransactionData,
    rpc_client: &BitcoinRpcClient,
) -> Option<DecodedProtocol> {
    debug!("Attempting PPk decode for txid: {}", tx_data.txid);

    // Extract OP_RETURN and P2MS outputs
    let op_return_outputs = tx_data.op_return_outputs();
    let p2ms_outputs = tx_data.p2ms_outputs();

    debug!(
        "Transaction has {} OP_RETURN and {} P2MS outputs",
        op_return_outputs.len(),
        p2ms_outputs.len()
    );

    // Call shared detection module (SINGLE SOURCE OF TRUTH)
    let detection_result = detect_ppk_variant(&op_return_outputs, &p2ms_outputs)?;

    info!("✅ PPk variant detected: {:?}", detection_result.variant);
    info!("   • Content type: {}", detection_result.content_type);

    // Construct ODIN identifier for ALL PPk variants
    // Each variant uses a specific DSS format for resource location
    let odin_identifier =
        construct_odin_identifier(&tx_data.txid, &detection_result, rpc_client).await;

    if let Some(ref odin) = odin_identifier {
        info!("   • ODIN: {}", odin.full_identifier);
        info!(
            "   • Block: {} (time: {})",
            odin.block_height, odin.block_time
        );
        info!("   • TX index: {}", odin.tx_index);
        info!("   • DSS: {}", odin.dss);
    }

    Some(DecodedProtocol::PPk {
        txid: tx_data.txid.clone(),
        variant: detection_result.variant,
        rt_json: detection_result.rt_json,
        raw_opreturn_bytes: detection_result.raw_opreturn_bytes,
        parsed_data: detection_result.parsed_data,
        content_type: detection_result.content_type.to_string(),
        odin_identifier,
        debug_info: None,
    })
}

/// Construct ODIN identifier for ALL PPk variants
///
/// ODIN format: `ppk:[BLOCK_HEIGHT].[TRANSACTION_INDEX]/[DSS]`
///
/// This function:
/// 1. Fetches transaction verbose data (includes blockhash)
/// 2. Fetches block data (includes height, time, tx array)
/// 3. Finds transaction index in block
/// 4. Extracts/generates DSS based on variant
/// 5. Constructs full ODIN identifier
///
/// Returns None if:
/// - Transaction not confirmed (no blockhash)
/// - RPC calls fail
async fn construct_odin_identifier(
    txid: &str,
    detection_result: &PPkDetectionResult,
    rpc_client: &BitcoinRpcClient,
) -> Option<OdinIdentifier> {
    use crate::types::ProtocolVariant;

    // Extract DSS (Data Specification String) based on variant
    // All variants get deterministic DSS for resource location
    let dss = match detection_result.variant {
        // Profile variant: Infer from JSON or use defaults
        ProtocolVariant::PPkProfile => {
            match &detection_result.rt_json {
                Some(json) => {
                    // Priority 1: Use "ap" (Application Path) if present
                    if let Some(ap) = json.get("ap").and_then(|v| v.as_str()) {
                        sanitize_dss(ap)
                    // Priority 2: If "title" exists, use profile.json convention
                    } else if json.get("title").is_some() {
                        "profile.json".to_string()
                    // Fallback: Generic data.json
                    } else {
                        "data.json".to_string()
                    }
                }
                None => "data.json".to_string(), // Shouldn't happen for Profile variant
            }
        }
        // Registration: Extract number from parsed data (e.g., "315" → reg_315.txt)
        ProtocolVariant::PPkRegistration => {
            if let Some(ref parsed_data) = detection_result.parsed_data {
                // Parse quoted number (e.g., "315"} → 315)
                let text = String::from_utf8_lossy(parsed_data);
                let number = text.trim().trim_matches('"').trim_end_matches('}').trim();
                format!("reg_{}.txt", sanitize_filename(number))
            } else {
                "registration.txt".to_string()
            }
        }
        // Message: Generic message.txt
        ProtocolVariant::PPkMessage => "message.txt".to_string(),
        // Unknown: Generic unknown.bin
        ProtocolVariant::PPkUnknown => "unknown.bin".to_string(),
        _ => "data.bin".to_string(), // Fallback for any future variants
    };

    // Get block position using new RPC method
    let (block_height, tx_index, block_time, _block_hash) =
        match rpc_client.get_transaction_block_position(txid).await {
            Ok(pos) => pos,
            Err(e) => {
                warn!(
                    "Failed to get block position for {}: {} (transaction may not be confirmed)",
                    txid, e
                );
                return None;
            }
        };

    // Construct ODIN identifier
    let odin = OdinIdentifier::new(block_height, tx_index, dss, block_time);

    debug!("Constructed ODIN: {}", odin.full_identifier);

    Some(odin)
}

/// Sanitize DSS path for safe filesystem usage
///
/// Removes/replaces dangerous characters:
/// - Directory traversal: ../, ./
/// - Path separators: / \
/// - Null bytes and control characters
///
/// Enforces max length of 200 characters.
fn sanitize_dss(input: &str) -> String {
    let sanitized = input
        .replace("..", "") // Remove directory traversal
        .replace(['/', '\\'], "_")
        .chars()
        .filter(|c| !c.is_control() && *c != '\0') // Remove control chars and nulls
        .take(200) // Max 200 chars
        .collect::<String>();

    if sanitized.is_empty() {
        "data.json".to_string()
    } else {
        sanitized
    }
}

/// Sanitize filename component (more restrictive than DSS)
///
/// Only allows: alphanumeric, hyphen, underscore, dot
/// Enforces max length of 50 characters.
fn sanitize_filename(input: &str) -> String {
    let sanitized = input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(50) // Max 50 chars for filenames
        .collect::<String>();

    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}
