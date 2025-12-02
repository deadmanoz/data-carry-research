//! Debug display module for verbose transaction decoding output
//!
//! This module provides detailed, formatted output showing the intricate
//! details of the P2MS decoding process, especially for protocols like
//! Counterparty that use ARC4 obfuscation.

use crate::types::debug::{P2MSOutputDebugInfo, TransactionDebugInfo};
use crate::types::TransactionOutput;
use tracing::info;

impl P2MSOutputDebugInfo {
    /// Create debug info from a TransactionOutput
    pub fn from_output(output: &TransactionOutput) -> Option<Self> {
        let multisig_info = output.multisig_info()?;

        let multisig_type = format!(
            "{}-of-{}",
            multisig_info.required_sigs, multisig_info.total_pubkeys
        );

        // Create pubkey previews (first 8 and last 8 chars)
        let pubkey_previews: Vec<String> = multisig_info
            .pubkeys
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                if pk.len() > 20 {
                    format!(
                        "[{}]: {}...{} ({} bytes)",
                        i,
                        &pk[..8],
                        &pk[pk.len() - 8..],
                        pk.len() / 2
                    )
                } else {
                    format!("[{}]: {} ({} bytes)", i, pk, pk.len() / 2)
                }
            })
            .collect();

        Some(Self {
            vout: output.vout,
            multisig_type,
            pubkey_count: multisig_info.pubkeys.len(),
            pubkey_previews,
            extraction_method: String::new(),
            raw_chunk: Vec::new(),
            decrypted_chunk: None,
            has_cntrprty_prefix: false,
            length_prefix: None,
            has_stamp_signature: false,
            stamp_signature: None,
            notes: Vec::new(),
        })
    }

    /// Set the data extraction details
    pub fn set_extraction(&mut self, method: String, raw_data: Vec<u8>) {
        self.extraction_method = method;
        self.raw_chunk = raw_data;
    }

    /// Set the decrypted data and check for protocol signatures
    pub fn set_decrypted(&mut self, decrypted: Vec<u8>, _is_first_output: bool) {
        // Check for length prefix in all outputs (Counterparty multi-output has length prefix in each chunk)
        if !decrypted.is_empty() {
            self.length_prefix = Some(decrypted[0]);
        }

        // Check for CNTRPRTY prefix
        const CNTRPRTY: &[u8] = b"CNTRPRTY";
        if decrypted.len() > CNTRPRTY.len() {
            // Check at offset 0
            if &decrypted[..CNTRPRTY.len()] == CNTRPRTY {
                self.has_cntrprty_prefix = true;
                self.notes
                    .push("CNTRPRTY prefix found at offset 0".to_string());
            }
            // Check at offset 1 (after length prefix)
            else if decrypted.len() > CNTRPRTY.len() + 1
                && &decrypted[1..1 + CNTRPRTY.len()] == CNTRPRTY
            {
                self.has_cntrprty_prefix = true;
                self.notes
                    .push("CNTRPRTY prefix found at offset 1 (after length prefix)".to_string());
            }
        }

        // Check for Bitcoin Stamps signature
        use crate::types::stamps::validation;
        if let Some((offset, variant)) = validation::find_stamp_signature(&decrypted) {
            self.has_stamp_signature = true;
            self.stamp_signature = Some((format!("{:?}", variant), offset));
            self.notes.push(format!(
                "Bitcoin Stamps signature '{:?}' found at offset {}",
                variant, offset
            ));
        }

        self.decrypted_chunk = Some(decrypted);
    }

    /// Add a note about this output
    pub fn add_note(&mut self, note: String) {
        self.notes.push(note);
    }
}

impl TransactionDebugInfo {
    /// Create a new debug info structure
    pub fn new(txid: String, protocol: String) -> Self {
        Self {
            txid,
            protocol,
            p2ms_outputs: Vec::new(),
            total_raw_data: 0,
            total_decrypted_data: 0,
            arc4_key_txid: None,
            message_type: None,
        }
    }

    /// Add a P2MS output to the debug info
    pub fn add_output(&mut self, output: P2MSOutputDebugInfo) {
        self.total_raw_data += output.raw_chunk.len();
        if let Some(ref decrypted) = output.decrypted_chunk {
            self.total_decrypted_data += decrypted.len();
        }
        self.p2ms_outputs.push(output);
    }

    /// Display the debug information in a formatted tree structure
    pub fn display_verbose(&self) {
        info!("");
        info!("╔══════════════════════════════════════════════════════════════════╗");
        info!("║              DETAILED TRANSACTION DECODING ANALYSIS              ║");
        info!("╚══════════════════════════════════════════════════════════════════╝");
        info!("");
        info!("Transaction: {}", self.txid);
        info!("Protocol Detection: {}", self.protocol);

        if let Some(ref arc4_key) = self.arc4_key_txid {
            info!("ARC4 Key Source: First input TXID = {}", arc4_key);
        }

        info!("");
        info!("P2MS Output Analysis:");
        info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        let output_count = self.p2ms_outputs.len();
        let max_outputs_to_show = 5; // Show first 5 outputs in detail

        for (idx, output) in self.p2ms_outputs.iter().enumerate() {
            if idx >= max_outputs_to_show && idx < output_count - 1 {
                if idx == max_outputs_to_show {
                    info!("");
                    info!(
                        "  ... and {} more P2MS outputs (truncated for brevity) ...",
                        output_count - max_outputs_to_show - 1
                    );
                    info!("");
                }
                continue;
            }

            // Show last output if we have more than max_outputs_to_show
            if output_count > max_outputs_to_show && idx == output_count - 1 {
                info!(
                    "├── Output #{} (vout: {}) - {} multisig [LAST OUTPUT]",
                    idx, output.vout, output.multisig_type
                );
            } else {
                info!(
                    "├── Output #{} (vout: {}) - {} multisig",
                    idx, output.vout, output.multisig_type
                );
            }

            // Show pubkeys
            for pubkey_preview in &output.pubkey_previews {
                info!("│   ├── Pubkey{}", pubkey_preview);
            }

            // Show extraction method
            if !output.extraction_method.is_empty() {
                info!("│   ├── Data Extraction: {}", output.extraction_method);
            }

            // Show raw data info
            if !output.raw_chunk.is_empty() {
                let hex_preview = if output.raw_chunk.len() > 32 {
                    format!("{}...", hex::encode(&output.raw_chunk[..32]))
                } else {
                    hex::encode(&output.raw_chunk)
                };
                info!(
                    "│   ├── Raw chunk ({} bytes): {}",
                    output.raw_chunk.len(),
                    hex_preview
                );
            }

            // Show decrypted data info
            if let Some(ref decrypted) = output.decrypted_chunk {
                info!("│   └── After ARC4 decrypt:");

                if let Some(prefix) = output.length_prefix {
                    info!(
                        "│       ├── Length prefix: 0x{:02X} ({} bytes total message)",
                        prefix, prefix
                    );
                }

                if output.has_cntrprty_prefix {
                    info!("│       ├── CNTRPRTY found: YES");
                }

                if output.has_stamp_signature {
                    if let Some((ref variant, offset)) = output.stamp_signature {
                        info!(
                            "│       ├── Bitcoin Stamps signature: {} at offset {}",
                            variant, offset
                        );
                    }
                }

                let hex_preview = if decrypted.len() > 20 {
                    format!("{}...", hex::encode(&decrypted[..20]))
                } else {
                    hex::encode(decrypted)
                };
                info!("│       └── First 20 bytes: {}", hex_preview);
            }

            // Show any special notes
            for note in &output.notes {
                info!("│       ⚠️  {}", note);
            }

            if idx < output_count - 1 {
                info!("│");
            }
        }

        info!("");
        info!("Final Assembly:");
        info!("├── Total outputs processed: {}", self.p2ms_outputs.len());
        info!("├── Total data extracted: {} bytes", self.total_raw_data);

        if self.total_decrypted_data > 0 {
            info!(
                "├── Total decrypted size: {} bytes",
                self.total_decrypted_data
            );
        }

        if let Some(ref msg_type) = self.message_type {
            info!("├── Message type detected: {}", msg_type);
        }

        info!("└── Status: ✅ Successfully decoded");
        info!("");
        info!("════════════════════════════════════════════════════════════");
        info!("");
    }
}
