use crate::config::AppConfig;
use crate::decoder::arc4_tool::{self, Arc4Result};
use crate::errors::{AppError, AppResult};
use crate::types::stamps::StampsTransport;
use clap::Args;
use tracing::info;

/// Perform ARC4 deobfuscation on P2MS transaction data
#[derive(Args)]
pub struct Arc4Command {
    /// Transaction ID to analyse
    pub txid: String,

    /// Show raw P2MS data before decryption
    #[arg(long)]
    pub show_raw: bool,

    /// Output format: text, hex, json
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Bitcoin RPC URL (overrides config.toml)
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Bitcoin RPC username (overrides config.toml)
    #[arg(long)]
    pub rpc_username: Option<String>,

    /// Bitcoin RPC password (overrides config.toml)
    #[arg(long)]
    pub rpc_password: Option<String>,
}

impl Arc4Command {
    pub async fn run(&self) -> AppResult<()> {
        info!(
            "Starting ARC4 deobfuscation analysis for TXID: {}",
            self.txid
        );

        // Load configuration, allowing CLI overrides
        let config = AppConfig::load()
            .map_err(|e| AppError::Config(format!("Failed to load configuration: {}", e)))?;

        // Build RPC configuration with CLI overrides
        let mut rpc_config = config.bitcoin_rpc;
        if let Some(url) = &self.rpc_url {
            rpc_config.url = url.clone();
        }
        if let Some(username) = &self.rpc_username {
            rpc_config.username = username.clone();
        }
        if let Some(password) = &self.rpc_password {
            rpc_config.password = password.clone();
        }

        // Initialise RPC client
        let rpc_client = crate::rpc::BitcoinRpcClient::new(rpc_config)
            .await
            .map_err(|e| AppError::Config(format!("Failed to initialise RPC client: {}", e)))?;

        // Perform ARC4 deobfuscation
        let result = arc4_tool::deobfuscate_transaction(&self.txid, &rpc_client)
            .await
            .map_err(|e| AppError::Config(format!("ARC4 deobfuscation failed: {}", e)))?;

        // Format and print output
        match self.format.as_str() {
            "json" => print_arc4_json(&result),
            "hex" => print_arc4_hex(&result),
            _ => print_arc4_text(&result, self.show_raw),
        }

        Ok(())
    }
}

/// Print ARC4 result in text format
fn print_arc4_text(result: &Arc4Result, show_raw: bool) {
    println!("\n=== ARC4 Deobfuscation ===");
    println!("TXID: {}", result.txid);
    println!();
    println!("ARC4 Key (first input):");
    println!("  {}", result.input_txid);
    println!();
    println!("P2MS Outputs: {}", result.p2ms_output_count);
    println!();

    // Counterparty result
    if let Some(ref cp) = result.counterparty {
        println!("Counterparty:");
        println!("  Success");
        println!(
            "  Raw: {} bytes -> Decrypted: {} bytes",
            cp.raw_data.len(),
            cp.decrypted.len()
        );
        println!();

        if show_raw {
            println!("  Raw data (hex):");
            print_hex_dump(&cp.raw_data, 2);
            println!();
        }

        println!("  Hex (first 64 bytes):");
        let preview_len = cp.decrypted.len().min(64);
        println!("  {}", hex::encode(&cp.decrypted[..preview_len]));
        println!();

        println!("  ASCII:");
        println!("  {}", to_ascii_preview(&cp.decrypted, 80));
        println!();
    } else {
        println!("Counterparty:");
        println!("  Not detected");
        println!();
    }

    // Bitcoin Stamps result
    if let Some(ref stamps) = result.stamps {
        println!("Bitcoin Stamps:");
        println!(
            "  Success ({:?})",
            match stamps.transport {
                StampsTransport::Pure => "Pure",
                StampsTransport::Counterparty => "Counterparty",
            }
        );
        println!(
            "  Raw: {} bytes -> Decrypted: {} bytes",
            stamps.raw_data.len(),
            stamps.decrypted.len()
        );
        println!("  Signature at offset: {}", stamps.signature_offset);
        println!();

        if show_raw {
            println!("  Raw data (hex):");
            print_hex_dump(&stamps.raw_data, 2);
            println!();
        }

        println!("  ASCII:");
        println!("  {}", to_ascii_preview(&stamps.decrypted, 80));
        println!();
    } else {
        println!("Bitcoin Stamps:");
        println!("  Not detected");
        println!();
    }

    // Raw fallback result
    if let Some(ref raw) = result.raw_fallback {
        println!("Raw ARC4 Fallback:");
        println!("  Decrypted (unknown protocol)");
        println!(
            "  Raw: {} bytes -> Decrypted: {} bytes",
            raw.raw_data.len(),
            raw.decrypted.len()
        );
        println!();

        if show_raw {
            println!("  Raw data (hex):");
            print_hex_dump(&raw.raw_data, 2);
            println!();
        }

        println!("  Hex (first 64 bytes):");
        let preview_len = raw.decrypted.len().min(64);
        println!("  {}", hex::encode(&raw.decrypted[..preview_len]));
        println!();

        println!("  ASCII:");
        println!("  {}", to_ascii_preview(&raw.decrypted, 80));
        println!();

        println!("  Note: No known protocol signature detected.");
        println!("  Tip: This may be a new or unknown protocol using ARC4 encryption.");
        println!("  Tip: Look for patterns in the ASCII/hex output above.");
        println!();
    }
}

/// Print ARC4 result in JSON format
fn print_arc4_json(result: &Arc4Result) {
    let json = serde_json::json!({
        "txid": result.txid,
        "input_txid": result.input_txid,
        "p2ms_output_count": result.p2ms_output_count,
        "counterparty": result.counterparty.as_ref().map(|cp| {
            serde_json::json!({
                "raw_bytes": cp.raw_data.len(),
                "raw_data": hex::encode(&cp.raw_data),
                "decrypted_bytes": cp.decrypted.len(),
                "decrypted": hex::encode(&cp.decrypted),
            })
        }),
        "stamps": result.stamps.as_ref().map(|stamps| {
            serde_json::json!({
                "raw_bytes": stamps.raw_data.len(),
                "raw_data": hex::encode(&stamps.raw_data),
                "decrypted_bytes": stamps.decrypted.len(),
                "decrypted": hex::encode(&stamps.decrypted),
                "signature_offset": stamps.signature_offset,
                "transport": match stamps.transport {
                    StampsTransport::Pure => "pure",
                    StampsTransport::Counterparty => "counterparty",
                },
            })
        }),
        "raw_fallback": result.raw_fallback.as_ref().map(|raw| {
            serde_json::json!({
                "raw_bytes": raw.raw_data.len(),
                "raw_data": hex::encode(&raw.raw_data),
                "decrypted_bytes": raw.decrypted.len(),
                "decrypted": hex::encode(&raw.decrypted),
            })
        }),
    });

    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

/// Print ARC4 result in hex format (decrypted data only)
fn print_arc4_hex(result: &Arc4Result) {
    if let Some(ref cp) = result.counterparty {
        println!("{}", hex::encode(&cp.decrypted));
    } else if let Some(ref stamps) = result.stamps {
        println!("{}", hex::encode(&stamps.decrypted));
    } else if let Some(ref raw) = result.raw_fallback {
        println!("{}", hex::encode(&raw.decrypted));
    }
}

/// Convert bytes to ASCII preview with non-printable characters as dots
fn to_ascii_preview(data: &[u8], max_len: usize) -> String {
    let preview_len = data.len().min(max_len);
    let preview: String = data[..preview_len]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    if data.len() > max_len {
        format!("{}...", preview)
    } else {
        preview
    }
}

/// Print hex dump with indentation
fn print_hex_dump(data: &[u8], indent: usize) {
    let indent_str = " ".repeat(indent);
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        println!(
            "{}{:04x}: {:47}  {}",
            indent_str,
            offset,
            hex.join(" "),
            ascii
        );
    }
}
