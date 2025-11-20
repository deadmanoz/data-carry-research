use crate::errors::AppResult;
use clap::{Parser, Subcommand};
use tracing_subscriber;

pub mod commands;

/// Bitcoin P2MS Data-Carrying Protocol Analyser
#[derive(Parser)]
#[command(name = "p2ms-analyser")]
#[command(about = "Bitcoin P2MS Data-Carrying Protocol Analyser")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI commands
#[derive(Subcommand)]
pub enum Commands {
    /// Run Stage 1: P2MS Detection from UTXO CSV
    Stage1(commands::stage1::Stage1Command),
    /// Run Stage 2: Transaction Enrichment with RPC data and fee analysis
    Stage2(commands::stage2::Stage2Command),
    /// Run Stage 3: Protocol Classification
    Stage3(commands::stage3::Stage3Command),
    /// Test Bitcoin RPC connectivity
    TestRpc(commands::decoder::TestRpcCommand),
    /// Decode protocol data from transaction (Bitcoin Stamps, Counterparty, Omni, PPk, DataStorage, etc.)
    DecodeTxid(commands::decoder::DecodeTxidCommand),
    /// Fetch transaction data from Bitcoin Core RPC
    Fetch(commands::decoder::FetchCommand),
    /// Perform ARC4 deobfuscation on P2MS transaction data
    Arc4(commands::decoder::Arc4Command),
    /// Run analysis on database
    Analyse(commands::analysis::AnalyseCommand),
}

pub async fn run() -> AppResult<()> {
    // Initialise tracing subscriber to capture info!() macros
    // Uses RUST_LOG environment variable (defaults to "error" if not set)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .try_init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Stage1(command) => command.run(),
        Commands::Stage2(command) => command.run().await,
        Commands::Stage3(command) => command.run().await,
        Commands::TestRpc(command) => command.run().await,
        Commands::DecodeTxid(command) => command.run().await,
        Commands::Fetch(command) => command.run().await,
        Commands::Arc4(command) => command.run().await,
        Commands::Analyse(command) => command.run(),
    }
}
