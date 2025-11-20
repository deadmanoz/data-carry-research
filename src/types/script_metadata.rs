//! Script-specific metadata types for different Bitcoin script types
//!
//! This module contains structured metadata types for various script types,
//! allowing type-safe access to script-specific data stored in JSON.
//!
//! This module also provides shared parsing functions used by both Stage 1 (CSV)
//! and Stage 2 (RPC enrichment) to ensure consistent metadata extraction.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Bitcoin script types as defined by Bitcoin Core
///
/// This is a normalised representation used throughout the database.
/// Stage 1 (CSV) uses "p2ms" which gets normalised to "multisig".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptType {
    /// Pay-to-Multisig (M-of-N)
    Multisig,
    /// Pay-to-PubKey-Hash (standard address)
    P2PKH,
    /// Pay-to-Witness-PubKey-Hash (SegWit)
    P2WPKH,
    /// Pay-to-Script-Hash
    P2SH,
    /// Pay-to-Witness-Script-Hash (SegWit)
    P2WSH,
    /// Pay-to-Taproot
    P2TR,
    /// Pay-to-PubKey (legacy)
    P2PK,
    /// OP_RETURN data carrier
    #[serde(rename = "op_return")]
    OpReturn,
    /// Nonstandard script
    Nonstandard,
    /// Unknown/unparseable script
    Unknown,
}

impl ScriptType {
    /// Convert to database string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptType::Multisig => "multisig",
            ScriptType::P2PKH => "p2pkh",
            ScriptType::P2WPKH => "p2wpkh",
            ScriptType::P2SH => "p2sh",
            ScriptType::P2WSH => "p2wsh",
            ScriptType::P2TR => "p2tr",
            ScriptType::P2PK => "p2pk",
            ScriptType::OpReturn => "op_return",
            ScriptType::Nonstandard => "nonstandard",
            ScriptType::Unknown => "unknown",
        }
    }
}

impl FromStr for ScriptType {
    type Err = std::convert::Infallible;

    /// Parse from string representation (used in CSV and database)
    ///
    /// This implementation is infallible - unrecognised strings return `ScriptType::Unknown`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "multisig" | "p2ms" => ScriptType::Multisig,
            "p2pkh" | "pubkeyhash" => ScriptType::P2PKH,
            "p2wpkh" => ScriptType::P2WPKH,
            "p2sh" | "scripthash" => ScriptType::P2SH,
            "p2wsh" => ScriptType::P2WSH,
            "p2tr" => ScriptType::P2TR,
            "p2pk" | "pubkey" => ScriptType::P2PK,
            "op_return" | "nulldata" => ScriptType::OpReturn,
            "nonstandard" => ScriptType::Nonstandard,
            _ => ScriptType::Unknown,
        })
    }
}

/// Metadata for Pay-to-PubKey (P2PK) scripts
/// Used in early Bitcoin before P2PKH became standard
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P2PKInfo {
    /// The public key (hex-encoded, 33 bytes compressed or 65 bytes uncompressed)
    pub pubkey: String,
    /// Whether the pubkey is compressed
    pub is_compressed: bool,
}

/// Metadata for Pay-to-PubKey-Hash (P2PKH) scripts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P2PKHInfo {
    /// The Base58Check encoded Bitcoin address (starts with '1')
    pub address: String,
    /// The 20-byte pubkey hash (hex-encoded)
    pub pubkey_hash: String,
}

/// Metadata for Pay-to-Script-Hash (P2SH) scripts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P2SHInfo {
    /// The Base58Check encoded Bitcoin address (starts with '3')
    pub address: String,
    /// The 20-byte script hash (hex-encoded)
    pub script_hash: String,
}

/// Metadata for Pay-to-Multisig (P2MS) scripts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MultisigInfo {
    /// Public keys in the multisig script (hex-encoded)
    pub pubkeys: Vec<String>,
    /// Number of required signatures (M in M-of-N)
    pub required_sigs: u32,
    /// Total number of public keys (N in M-of-N)
    pub total_pubkeys: u32,
}

/// Metadata for nonstandard scripts
/// These are scripts that don't match any standard template recognised by Bitcoin Core
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NonstandardInfo {
    /// Classification of what this nonstandard script might be
    pub classification: NonstandardClassification,
    /// Total size of the script in bytes
    pub script_size: usize,
    /// Raw opcodes present in the script
    pub opcodes: Vec<u8>,
}

/// Classification of nonstandard scripts based on pattern analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "category", rename_all = "snake_case")]
pub enum NonstandardClassification {
    /// Looks like multisig but breaks policy expectations (e.g., Counterparty, Chancecoin)
    MultisigAnomaly(MultisigAnomaly),
    /// Witness program with unsupported version or length
    WitnessAnomaly(WitnessAnomaly),
    /// Scripts that are trivially spendable (e.g., OP_TRUE)
    AnyoneCanSpend(AnyoneCanSpendInfo),
    /// Custom push-only pattern that does not match a known template
    CustomPattern(CustomPatternInfo),
    /// Scripts that could not be classified but we still record minimal context
    Unknown(UnknownInfo),
}

/// Detailed information about a malformed or policy-breaking multisig script
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MultisigAnomaly {
    /// Estimated M for an M-of-N multisig script
    pub estimated_m: Option<u8>,
    /// Estimated N for an M-of-N multisig script
    pub estimated_n: Option<u8>,
    /// Ordered segments extracted from the script (pubkeys or raw data pushes)
    pub segments: Vec<MultisigSegment>,
    /// Issues detected while parsing the script
    pub issues: Vec<MultisigIssue>,
    /// Optional hint about the protocol that produced this script
    pub suspected_protocol: Option<String>,
}

/// Individual segment within a nonstandard multisig script
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MultisigSegment {
    /// A public key (compressed or uncompressed)
    Pubkey {
        /// Hex-encoded public key
        hex: String,
        /// Whether the key is compressed
        compressed: bool,
        /// Position in the original script (0-indexed)
        index: usize,
    },
    /// Arbitrary data chunk stored in place of a public key
    DataChunk {
        /// Hex-encoded data blob
        hex: String,
        /// Position in the original script (0-indexed)
        index: usize,
    },
}

/// Issues detected while attempting to classify a multisig script
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MultisigIssue {
    /// The script pushes more keys than the policy limit allows
    TooManyPubkeys {
        /// Policy limit that was exceeded
        policy_limit: u8,
    },
    /// A pushed element could not be parsed as a valid public key
    InvalidPubkeyFormat {
        /// Index of the offending element
        index: usize,
    },
    /// The script used a non-minimal push opcode for a segment
    NonCanonicalPush {
        /// Index of the element with a non-canonical push
        index: usize,
        /// Length of the pushed data in bytes
        pushed_len: usize,
    },
    /// The script omits the final OP_CHECKMULTISIG opcode
    MissingOpCheckmultisig,
}

/// Information about witness scripts that fall outside standard policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessAnomaly {
    /// Witness version extracted from the script
    pub version: u8,
    /// Length of the witness program in bytes
    pub program_len: usize,
    /// Allowed program lengths for this witness version (for comparison)
    pub standard_lengths: Vec<usize>,
    /// Specific issue detected with the witness program
    pub reason: WitnessIssue,
}

/// Reasons why a witness program may be considered nonstandard
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WitnessIssue {
    /// Witness version is not recognised by current consensus
    UnsupportedVersion,
    /// Witness program length does not match policy
    InvalidLength,
    /// Program was not minimally pushed onto the stack
    NonMinimalPush,
}

/// Information about trivially spendable scripts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnyoneCanSpendInfo {
    /// High-level pattern for the trivially spendable script
    pub pattern: AnyoneCanSpendPattern,
}

/// Patterns that result in a trivially spendable output
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnyoneCanSpendPattern {
    /// Simple OP_TRUE
    OpTrue,
    /// Single opcode (e.g., OP_1, OP_TRUE)
    SingleOpcode {
        /// Opcode value
        opcode: u8,
    },
    /// Empty script
    EmptyScript,
}

/// Information about push-only scripts that do not match a known template
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustomPatternInfo {
    /// Non-push opcodes encountered (if any)
    pub non_push_opcodes: Vec<u8>,
    /// Sizes of the pushed data segments
    pub push_sizes: Vec<usize>,
    /// Optional notes captured during analysis
    pub notes: Option<String>,
}

/// Minimal information for scripts that could not be classified
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnknownInfo {
    /// Hex-encoded hash of the script (for future lookup)
    pub script_hash: String,
    /// Optional analyst note about why this was left unknown
    pub notes: Option<String>,
}

/// Metadata for Pay-to-Witness-PubKey-Hash (P2WPKH) scripts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P2WPKHInfo {
    /// The Bech32 encoded address (starts with 'bc1' on mainnet)
    pub address: String,
    /// The 20-byte pubkey hash (hex-encoded)
    pub pubkey_hash: String,
}

/// Metadata for Pay-to-Witness-Script-Hash (P2WSH) scripts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P2WSHInfo {
    /// The Bech32 encoded address (starts with 'bc1' on mainnet)
    pub address: String,
    /// The 32-byte script hash (hex-encoded)
    pub script_hash: String,
}

/// Metadata for Pay-to-Taproot (P2TR) scripts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct P2TRInfo {
    /// The Bech32m encoded address (starts with 'bc1p' on mainnet)
    pub address: String,
    /// The 32-byte taproot output key (hex-encoded)
    pub output_key: String,
}

// ============================================================================
// SHARED PARSING FUNCTIONS
// ============================================================================

/// Parse a Pay-to-Multisig (P2MS) script to extract multisig parameters
///
/// Returns (pubkeys, required_sigs, total_pubkeys) on success.
/// This is the single source of truth used by both Stage 1 (CSV) and Stage 2 (RPC).
pub fn parse_p2ms_script(
    script_hex: &str,
) -> Result<(Vec<String>, u32, u32), crate::errors::AppError> {
    let script_bytes = hex::decode(script_hex).map_err(|_| {
        crate::errors::AppError::ScriptParse(format!("Failed to decode script hex: {}", script_hex))
    })?;

    if script_bytes.len() < 3 {
        return Err(crate::errors::AppError::ScriptParse(
            "Script too short to be P2MS".to_string(),
        ));
    }

    // P2MS format: OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG
    let required_sigs = if (0x51..=0x60).contains(&script_bytes[0]) {
        (script_bytes[0] - 0x50) as u32
    } else {
        return Err(crate::errors::AppError::ScriptParse(format!(
            "Invalid OP_M opcode: {}",
            script_bytes[0]
        )));
    };

    let mut pubkeys = Vec::new();
    let mut pos = 1;

    // Extract pubkeys
    while pos < script_bytes.len() - 2 {
        if script_bytes[pos] == 0x21 {
            // 33-byte compressed pubkey
            if pos + 34 > script_bytes.len() {
                break;
            }
            let pubkey = hex::encode(&script_bytes[pos + 1..pos + 34]);
            pubkeys.push(pubkey);
            pos += 34;
        } else if script_bytes[pos] == 0x41 {
            // 65-byte uncompressed pubkey
            if pos + 66 > script_bytes.len() {
                break;
            }
            let pubkey = hex::encode(&script_bytes[pos + 1..pos + 66]);
            pubkeys.push(pubkey);
            pos += 66;
        } else {
            break;
        }
    }

    // Verify OP_N matches pubkey count
    if pos < script_bytes.len() - 1 {
        let op_n = script_bytes[pos];
        let expected_n = if (0x51..=0x60).contains(&op_n) {
            (op_n - 0x50) as u32
        } else {
            return Err(crate::errors::AppError::ScriptParse(format!(
                "Invalid OP_N opcode: {}",
                op_n
            )));
        };

        if expected_n != pubkeys.len() as u32 {
            return Err(crate::errors::AppError::ScriptParse(format!(
                "Pubkey count mismatch: expected {}, found {}",
                expected_n,
                pubkeys.len()
            )));
        }

        // Verify OP_CHECKMULTISIG
        if pos + 1 < script_bytes.len() && script_bytes[pos + 1] != 0xae {
            return Err(crate::errors::AppError::ScriptParse(
                "Missing OP_CHECKMULTISIG".to_string(),
            ));
        }

        Ok((pubkeys, required_sigs, expected_n))
    } else {
        Err(crate::errors::AppError::ScriptParse(
            "Script truncated".to_string(),
        ))
    }
}

/// Parsed OP_RETURN output data
#[derive(Debug, Clone, serde::Serialize)]
pub struct OpReturnData {
    /// Full OP_RETURN script (hex-encoded)
    pub op_return_hex: String,
    /// Protocol prefix (first 2-4 bytes of data, hex-encoded)
    pub protocol_prefix_hex: Option<String>,
    /// Remaining data after prefix (hex-encoded)
    pub data_hex: Option<String>,
    /// Total data length in bytes
    pub data_length: usize,
}

/// Parse an OP_RETURN script to extract protocol data
///
/// Respects the declared PUSHDATA length to ensure trailing opcodes
/// are not included in the extracted protocol data.
///
/// This is the single source of truth used by both Stage 1 (CSV) and Stage 2 (RPC).
pub fn parse_opreturn_script(script_hex: &str) -> Option<OpReturnData> {
    let script_bytes = hex::decode(script_hex).ok()?;

    if script_bytes.len() < 2 || script_bytes[0] != 0x6a {
        return None;
    }

    let (data_start, declared_len) = match script_bytes[1] {
        op @ 0x01..=0x4b => (2, Some(op as usize)),
        0x4c => {
            if script_bytes.len() < 3 {
                return None;
            }
            (3, Some(script_bytes[2] as usize))
        }
        0x4d => {
            if script_bytes.len() < 4 {
                return None;
            }
            let len = u16::from_le_bytes([script_bytes[2], script_bytes[3]]) as usize;
            (4, Some(len))
        }
        0x4e => {
            if script_bytes.len() < 6 {
                return None;
            }
            let len = u32::from_le_bytes([
                script_bytes[2],
                script_bytes[3],
                script_bytes[4],
                script_bytes[5],
            ]) as usize;
            (6, Some(len))
        }
        _ => return None,
    };

    if script_bytes.len() <= data_start {
        return None;
    }

    let remaining = &script_bytes[data_start..];
    let data = if let Some(len) = declared_len {
        let clamped = len.min(remaining.len());
        &remaining[..clamped]
    } else {
        remaining
    };

    let (protocol_prefix_hex, remaining_data_hex) = if data.len() >= 4 {
        (Some(hex::encode(&data[..4])), Some(hex::encode(&data[4..])))
    } else if data.len() >= 2 {
        (Some(hex::encode(&data[..2])), Some(hex::encode(&data[2..])))
    } else {
        (None, Some(hex::encode(data)))
    };

    Some(OpReturnData {
        op_return_hex: script_hex.to_string(),
        protocol_prefix_hex,
        data_hex: remaining_data_hex,
        data_length: data.len(),
    })
}

/// Parse a nonstandard script and extract meaningful information
///
/// This is the single source of truth used by both Stage 1 (CSV) and Stage 2 (RPC).
pub fn parse_nonstandard_script(script_hex: &str) -> NonstandardInfo {
    use sha2::{Digest, Sha256};

    // Try to decode the script
    let script_bytes = match hex::decode(script_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Can't even decode hex, return unknown
            let mut hasher = Sha256::new();
            hasher.update(script_hex.as_bytes());
            let hash = format!("{:x}", hasher.finalize());

            return NonstandardInfo {
                classification: NonstandardClassification::Unknown(UnknownInfo {
                    script_hash: hash,
                    notes: Some("Failed to decode hex".to_string()),
                }),
                script_size: script_hex.len() / 2,
                opcodes: vec![],
            };
        }
    };

    // Check if it looks like a malformed multisig (e.g., Chancecoin)
    // Pattern: OP_1 <data1> <data2> OP_2 OP_CHECKMULTISIG
    if script_bytes.len() >= 5 {
        let last_byte = script_bytes[script_bytes.len() - 1];
        if last_byte == 0xae {
            // OP_CHECKMULTISIG
            // Try to parse as malformed multisig
            if let Some(anomaly) = parse_multisig_anomaly(&script_bytes) {
                return NonstandardInfo {
                    classification: NonstandardClassification::MultisigAnomaly(anomaly),
                    script_size: script_bytes.len(),
                    opcodes: vec![script_bytes[0], script_bytes[script_bytes.len() - 2], 0xae],
                };
            }
        }
    }

    // If we can't classify it, return as unknown
    let mut hasher = Sha256::new();
    hasher.update(&script_bytes);
    let hash = format!("{:x}", hasher.finalize());

    NonstandardInfo {
        classification: NonstandardClassification::Unknown(UnknownInfo {
            script_hash: hash,
            notes: Some("Could not determine script pattern".to_string()),
        }),
        script_size: script_bytes.len(),
        opcodes: script_bytes
            .iter()
            .filter(|&&b| b >= 0x50)
            .copied()
            .collect(),
    }
}

/// Parse a script as a malformed multisig (like Chancecoin)
///
/// This is the single source of truth used by both Stage 1 (CSV) and Stage 2 (RPC).
pub fn parse_multisig_anomaly(script_bytes: &[u8]) -> Option<MultisigAnomaly> {
    if script_bytes.len() < 5 {
        return None;
    }

    // Check for OP_CHECKMULTISIG at the end
    if script_bytes[script_bytes.len() - 1] != 0xae {
        return None;
    }

    // Extract M and N values
    let estimated_m = if (0x51..=0x60).contains(&script_bytes[0]) {
        Some(script_bytes[0] - 0x50)
    } else {
        None
    };

    let n_pos = script_bytes.len() - 2;
    let estimated_n = if (0x51..=0x60).contains(&script_bytes[n_pos]) {
        Some(script_bytes[n_pos] - 0x50)
    } else {
        None
    };

    let mut segments = Vec::new();
    let mut issues = Vec::new();
    let mut pos = 1;
    let mut segment_index = 0;

    // Try to extract segments
    while pos < script_bytes.len() - 2 {
        if pos >= script_bytes.len() {
            break;
        }

        let push_len = script_bytes[pos] as usize;
        if push_len == 0 || pos + 1 + push_len > script_bytes.len() - 2 {
            break;
        }

        let data = &script_bytes[pos + 1..pos + 1 + push_len];

        // Check if this is a valid pubkey
        if (push_len == 33 || push_len == 65)
            && (data[0] == 0x02 || data[0] == 0x03 || data[0] == 0x04)
        {
            segments.push(MultisigSegment::Pubkey {
                hex: hex::encode(data),
                compressed: push_len == 33,
                index: segment_index,
            });
        } else {
            // This is a data chunk, not a valid pubkey
            segments.push(MultisigSegment::DataChunk {
                hex: hex::encode(data),
                index: segment_index,
            });
            issues.push(MultisigIssue::InvalidPubkeyFormat {
                index: segment_index,
            });
        }

        segment_index += 1;
        pos += 1 + push_len;
    }

    // Determine suspected protocol
    let suspected_protocol = if segments.iter().any(|s| {
        if let MultisigSegment::DataChunk { hex, .. } = s {
            hex.starts_with("434841434e4345434f") // "CHANCECO"
        } else {
            false
        }
    }) {
        Some("Chancecoin".to_string())
    } else {
        None
    };

    Some(MultisigAnomaly {
        estimated_m,
        estimated_n,
        segments,
        issues,
        suspected_protocol,
    })
}

/// Check if a script hex represents a multisig script
pub fn is_multisig_script(script_hex: &str) -> bool {
    parse_p2ms_script(script_hex).is_ok()
}

/// Check if a script hex represents an OP_RETURN script
pub fn is_opreturn_script(script_hex: &str) -> bool {
    if let Ok(bytes) = hex::decode(script_hex) {
        !bytes.is_empty() && bytes[0] == 0x6a
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_p2pk_info_serialization() {
        let info = P2PKInfo {
            pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            is_compressed: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: P2PKInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_multisig_info_serialization() {
        let info = MultisigInfo {
            pubkeys: vec![
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string(),
                "02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737".to_string(),
            ],
            required_sigs: 1,
            total_pubkeys: 2,
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: MultisigInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_nonstandard_multisig_anomaly_serialization() {
        let info = NonstandardInfo {
            classification: NonstandardClassification::MultisigAnomaly(MultisigAnomaly {
                estimated_m: Some(1),
                estimated_n: Some(2),
                segments: vec![
                    MultisigSegment::Pubkey {
                        hex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                            .to_string(),
                        compressed: true,
                        index: 0,
                    },
                    MultisigSegment::DataChunk {
                        hex: "434841434e4345434f".to_string(), // "CHANCECO"
                        index: 1,
                    },
                ],
                issues: vec![MultisigIssue::InvalidPubkeyFormat { index: 1 }],
                suspected_protocol: Some("Chancecoin".to_string()),
            }),
            script_size: 75,
            opcodes: vec![0x51, 0x52, 0xae],
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: NonstandardInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_nonstandard_witness_anomaly_serialization() {
        let classification = NonstandardClassification::WitnessAnomaly(WitnessAnomaly {
            version: 2,
            program_len: 40,
            standard_lengths: vec![32],
            reason: WitnessIssue::InvalidLength,
        });

        let json = serde_json::to_string(&classification).unwrap();
        let deserialized: NonstandardClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(classification, deserialized);
    }

    #[test]
    fn test_p2pkh_info_serialization() {
        let info = P2PKHInfo {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            pubkey_hash: "62e907b15cbf27d5425399ebf6f0fb50ebb88f18".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        let deserialized: P2PKHInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    // ============================================================================
    // OP_RETURN PARSER TESTS
    // ============================================================================
    // These tests verify the shared parse_opreturn_script() function produces
    // identical results to the legacy OpReturnOutput::from_script_bytes()

    #[test]
    fn test_parse_opreturn_direct_length() {
        let script_hex = "6a04bb3a1234";
        let result = parse_opreturn_script(script_hex).unwrap();

        assert_eq!(result.op_return_hex, "6a04bb3a1234");
        assert_eq!(result.protocol_prefix_hex.as_deref(), Some("bb3a1234"));
        assert_eq!(result.data_hex.as_deref(), Some(""));
        assert_eq!(result.data_length, 4);
    }

    #[test]
    fn test_parse_opreturn_pushdata1_with_trailing_opcode() {
        let script_hex = "6a4c06bb3a1234567875";
        let result = parse_opreturn_script(script_hex).unwrap();

        assert_eq!(result.protocol_prefix_hex.as_deref(), Some("bb3a1234"));
        assert_eq!(result.data_hex.as_deref(), Some("5678"));
        assert_eq!(result.data_length, 6);
        // Ensure trailing opcode (0x75) was excluded
        assert_eq!(result.op_return_hex, "6a4c06bb3a1234567875");
    }

    #[test]
    fn test_parse_opreturn_pushdata2() {
        // Length 5 (little-endian 0x0005)
        let script_hex = "6a4d0500bb3a55aaee";
        let result = parse_opreturn_script(script_hex).unwrap();

        assert_eq!(result.protocol_prefix_hex.as_deref(), Some("bb3a55aa"));
        assert_eq!(result.data_hex.as_deref(), Some("ee"));
        assert_eq!(result.data_length, 5);
    }

    #[test]
    fn test_parse_opreturn_too_short_for_protocol() {
        let script_hex = "6a01bb";
        let result = parse_opreturn_script(script_hex).unwrap();

        assert!(result.protocol_prefix_hex.is_none());
        assert_eq!(result.data_hex.as_deref(), Some("bb"));
        assert_eq!(result.data_length, 1);
    }

    #[test]
    fn test_parse_opreturn_non_opreturn_script() {
        let script_hex = "76a91489abcdefabbaabbaabbaabbaabbaabbaabba88ac";
        assert!(parse_opreturn_script(script_hex).is_none());
    }

    #[test]
    fn test_parse_opreturn_comprehensive_coverage() {
        // Comprehensive test cases covering all PUSHDATA formats and edge cases
        // These test cases were originally validated against the legacy OpReturnOutput parser

        // Test case 1: Direct length encoding (OP_RETURN + length byte + data)
        let result = parse_opreturn_script("6a04bb3a1234").unwrap();
        assert_eq!(result.op_return_hex, "6a04bb3a1234");
        assert_eq!(result.protocol_prefix_hex.as_deref(), Some("bb3a1234"));
        assert_eq!(result.data_hex.as_deref(), Some(""));
        assert_eq!(result.data_length, 4);

        // Test case 2: PUSHDATA1 with trailing opcode (ensure trailing bytes excluded)
        let result = parse_opreturn_script("6a4c06bb3a1234567875").unwrap();
        assert_eq!(result.protocol_prefix_hex.as_deref(), Some("bb3a1234"));
        assert_eq!(result.data_hex.as_deref(), Some("5678"));
        assert_eq!(result.data_length, 6);
        assert_eq!(result.op_return_hex, "6a4c06bb3a1234567875");

        // Test case 3: PUSHDATA2 (little-endian length)
        let result = parse_opreturn_script("6a4d0500bb3a55aaee").unwrap();
        assert_eq!(result.protocol_prefix_hex.as_deref(), Some("bb3a55aa"));
        assert_eq!(result.data_hex.as_deref(), Some("ee"));
        assert_eq!(result.data_length, 5);

        // Test case 4: Too short for protocol prefix (< 4 bytes)
        let result = parse_opreturn_script("6a01bb").unwrap();
        assert!(result.protocol_prefix_hex.is_none());
        assert_eq!(result.data_hex.as_deref(), Some("bb"));
        assert_eq!(result.data_length, 1);
    }

    #[test]
    fn test_parse_opreturn_pushdata4() {
        // PUSHDATA4 format (though rarely used in practice)
        // Length 4 (little-endian 0x00000004)
        let script_hex = "6a4e04000000deadbeef";
        let result = parse_opreturn_script(script_hex).unwrap();

        assert_eq!(result.protocol_prefix_hex.as_deref(), Some("deadbeef"));
        assert_eq!(result.data_hex.as_deref(), Some(""));
        assert_eq!(result.data_length, 4);
    }

    #[test]
    fn test_parse_opreturn_empty_data() {
        // OP_RETURN with OP_0 (empty push) - not a valid PUSHDATA opcode
        // The parser expects a valid push opcode (0x01-0x4b, 0x4c, 0x4d, 0x4e)
        // OP_0 (0x00) is not a valid PUSHDATA opcode, so this returns None
        let script_hex = "6a00";
        let result = parse_opreturn_script(script_hex);

        // Should return None because OP_0 is not a valid PUSHDATA opcode
        assert!(result.is_none());
    }

    // ============================================================================
    // P2MS PARSER TESTS
    // ============================================================================

    #[test]
    fn test_parse_p2ms_valid_1of2() {
        let script_hex = "51210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179852ae";
        let result = parse_p2ms_script(script_hex);

        assert!(result.is_ok());
        let (pubkeys, required_sigs, total_pubkeys) = result.unwrap();
        assert_eq!(required_sigs, 1);
        assert_eq!(total_pubkeys, 2);
        assert_eq!(pubkeys.len(), 2);
    }

    #[test]
    fn test_parse_p2ms_invalid_hex() {
        let script_hex = "invalid_hex";
        let result = parse_p2ms_script(script_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_p2ms_script_too_short() {
        let script_hex = "51"; // Just OP_1
        let result = parse_p2ms_script(script_hex);
        assert!(result.is_err());
    }
}
