# Bitcoin P2MS Data-Carrying Protocol Analyser

A research tool for analysing Pay-to-Multisig (P2MS) outputs in the UTXO set to identify and classify data-carrying protocols.

P2MS outputs are also known as "bare multisig" or "raw multisig", and are NOT to be confused with the modern, standard use of multisig, which relies on P2SH or P2WSH script types.

This repository was used to produce the research findings in the "P2MS Data Carry" post series:
- [P2MS Data Carry Part 1: Fundamentals and Examples](https://deadmanoz.xyz/posts/p2ms-data-carry-1)
- [P2MS Data Carry Part 2: UTXO set analysis](https://deadmanoz.xyz/posts/p2ms-data-carry-2)

This tool may be extended in the future to:
- Support script types beyond P2MS
- Process the blockchain (alongside the UTXO set)
- Support Bitcoin Core's UTXO set dump format

This project also served as an experiment in AI-assisted design and development and was co-authored by Claude Code.
Enjoy the comprehensive tests to keep the AI on the rails and the excessive emojis! 🤖✨

## Overview

This tool processes Bitcoin UTXO set dumps to extract and classify P2MS outputs used by various data-embedding protocols.
These protocols leverage Bitcoin's P2MS scripts to store arbitrary data including text, images, documents, name registrations, tokens and other digital assets directly on the Bitcoin blockchain.

### Supported Protocols

**Data-Carrying Protocols:**
- **Bitcoin Stamps**: Images and SRC-20/721 tokens with ARC4 obfuscation
- **Counterparty**: One of the earliest Bitcoin meta-protocols for asset issuance and trading (classified into 7 semantic categories: Transfer, Issuance, Destruction, DEX, Oracle, Gaming, Utility)
- **Omni Layer**: Early protocol that originally powered Tether (USDT) and other tokens
- **Chancecoin**: Historical gambling protocol with signature-based detection
- **ASCII Identifier Protocols**: Protocols detected via ASCII identifiers in P2MS outputs (e.g., `TB0001`, `TEST01`, `METROXMN`)
- **PPk**: Blockchain infrastructure protocol (ODIN) with marker pubkey and Registration/Message variants
- **OP_RETURN Signalled**: Protocols detected via identifiers in OP_RETURN outputs (e.g., "Protocol47930", `CLIPPERZ`)
- **Generic Data Storage**: General data storage, including text and files

**Other Classification Categories:**
- **Likely data storage**: Valid EC points with suspicious patterns (high output count, dust output amounts), or invalid EC points present
- **Likely legitimate multisig**: Likely legitimate multisig transactions as all pubkeys are valid EC points and we didn't get a hit on any of the data-carrying protocols.
- **Unknown**: Did not match any other classification, requires further analysis

### Protocol Detection Methodology

**For complete technical details, see [CLASSIFICATION_REFERENCE.md](CLASSIFICATION_REFERENCE.md)** - comprehensive reference for all protocol classifiers, detection methods, and variants.

**Classification Order**: Protocols are checked in precedence order to avoid misclassification:
1. **Omni Layer** - Exodus address detection (exclusive transport mechanism)
2. **Chancecoin** - Signature-based detection
3. **Bitcoin Stamps** - Checked BEFORE Counterparty to catch Stamps-on-Counterparty
4. **Counterparty** - ARC4-encoded messages
5. **ASCII Identifier Protocols** - identifiers such as `TB0001`, `TEST01`, `METROXMN` in P2MS outputs as unobfuscated ASCII
6. **PPk** - Marker pubkey detection with RT/Registration/Message variants
7. **WikiLeaks Cablegate** - Historical artifact (April 2013), produces `DataStorage` classifications with variant `DataStorageWikiLeaksCablegate`
8. **OP_RETURN Signalled** - identifiers such as `CLIPPERZ` and "Protocol 47930" (`0xbb3a` marker)
9. **Data Storage** - Generic data embedding patterns in P2MS outputs
10. **Likely Data Storage** - Valid EC points with suspicious patterns (5+ P2MS outputs, dust-ish amounts), or invalid EC points present
11. **Likely Legitimate Multisig** - All pubkeys are valid EC points (likely real multisig)
12. **Unknown** - Fallback for unclassified transactions

**Why order matters**:
- **Stamps before Counterparty**: Some Bitcoin Stamps transactions use Counterparty as a transport mechanism. Checking Counterparty first would misclassify these as plain Counterparty, missing the embedded `stamp:` signature inside the decrypted payload.

## Features

### Three-Stage Processing Pipeline for UTXO Set Analysis

#### Stage 1: P2MS Detection
- Stream processing of 30GB+ UTXO CSV files without memory loading
- Extracts P2MS outputs (e.g. ~2.5M entries) from UTXO set (e.g. ~150M total)

#### Stage 2: Transaction Enrichment
- Bitcoin Core RPC integration for full transaction data
- Input/output value calculations, burn pattern detection

#### Stage 3: Protocol Classification
- Signature-based protocol detection
- Modular classifier architecture for extensibility

### Unified Protocol Decoder

**Automatically detect and decode data from Bitcoin P2MS transactions** across most of the supported protocols with a single command.
The decoder identifies protocol signatures, handles multiple encoding formats (ARC4, SHA256, bzip2), and extracts embedded data including images (PNG, GIF, JPG, WebP, SVG) and JSON metadata.

**Key capabilities:**
- Automatic protocol detection; processes protocols in correct precedence order to avoid misclassification
- Image format recognition and extraction
- Organised output by protocol type
- Full RPC integration for complete transaction analysis
- **Note: as this codebase is initially focused on P2MS, it is currently limited to transactions involving at least one P2MS output**

## Quick Start

### Prerequisites

- Rust 1.70+
- SQLite 3.x
- Bitcoin Core node with RPC enabled (for Stage 2+):
  - **NOTE**: Must have `txindex=1` in `bitcoin.conf` to enable full transaction indexing
  - RPC authentication configured
  - Example `bitcoin.conf` snippet:
    ```ini
    txindex=1
    server=1
    rpcuser=bitcoin
    rpcpassword=your_password
    ```
- UTXO dump from [`bitcoin-utxo-dump`](https://github.com/in3rsha/bitcoin-utxo-dump), this will be ~30GB
- Around 13GB of disk space for the database this tool produces

### Installation

```bash
# Clone the repository
git clone https://github.com/deadmanoz/data-carry-research
cd data-carry-research

# Setup configuration
cp config.toml.example config.toml
# Edit config.toml with your paths and RPC settings

# Build the project
cargo build --release
# or
just build
```

### Basic Usage

Run all stages in sequence, unattended:
```bash
just production-pipeline
```

Or run each stage sequentially, but separately:
```bash
# Stage 1: Extract P2MS outputs (configure UTXO_CSV_PATH or config.toml first)
just stage1-production

# Stage 2: Enrich with transaction data (requires Bitcoin RPC)
# This stage takes the majority of the time (of all stages)
# as we need to lookup various transactions from Bitcoin RPC
just stage2-production

# Stage 3: Classify protocols
just stage3-production
```

Run the unified decoder:
```bash
# Decode any transaction involving P2MS with automatic protocol detection
just decode-txid <txid>
```

Decoded protocol data is organised in `output_data/` with protocol-specific subdirectories:

```plaintext
output_data/
├── decoded/               # Decode TXID path
│   ├── bitcoin_stamps/
│   │   ├── images/        # Decoded images (PNG, GIF, JPG, WebP, SVG)
│   │   ├── json/          # SRC-20, SRC-101, SRC-721, SRC-721r data
│   │   ├── html/          # HTML documents
│   │   ├── compressed/    # GZIP/ZLIB compressed data
│   │   └── data/          # Generic stamp data (XML, text, binary)
│   ├── counterparty/      # Counterparty protocol data (JSON)
│   ├── omni/              # Omni Layer protocol data (JSON)
│   ├── chancecoin/        # Chancecoin protocol data (JSON)
│   ├── ppk/               # PPk protocol data (JSON)
│   ├── datastorage/       # DataStorage protocol data
│   └── unknown/           # Unclassified/fallback transactions
├── fetched/               # Raw transaction JSON from Bitcoin Core RPC
│   └── <protocol>/
│       ├── <txid>.json
│       └── inputs/        # Input transaction cache
├── plots/                 # Visualisation outputs
│   ├── *.png, *.svg       # Plot files
│   └── *.json             # Plotly exports
└── analysis/              # Statistical analysis exports
    └── *.json             # JSON reports
```

See `just` for a complete list of available commands.

## Configuration

Create a `config.toml` file:

```toml
[paths]
utxo_csv = "/path/to/utxodump.csv"

[database]
default_path = "./p2ms_analysis.db"

[processing]
batch_size = 10000
progress_interval = 100000

[bitcoin_rpc]
url = "http://localhost:8332"
username = "bitcoin"
password = "your_password"
timeout_seconds = 60
max_retries = 10
concurrent_requests = 10
```

Environment variables can override config file settings:
```bash
export BITCOIN_RPC_URL="http://localhost:8332"
export BITCOIN_RPC_USERNAME="bitcoin"
export BITCOIN_RPC_PASSWORD="your_password"
```

## Database Analysis

Run after the 3 stages have completed:

```bash
# Statistics (fast shell script)
just stats <db>                              # Tabular statistics
just stats-json <db>                         # JSON format

# Analysis (umbrella command: just analyse <subcommand> [db] [options])
just analyse value <db>                      # Value distribution & economics
just analyse value-distributions <db>        # Value histograms (for plotting)
just analyse burn-patterns <db>              # Burn pattern analysis
just analyse fees <db>                       # Fee analysis
just analyse classifications <db>            # Classification statistics
just analyse signatures <db>                 # Protocol signature detection stats
just analyse spendability <db>               # Spendability analysis
just analyse full <db>                       # Comprehensive report (all analyses)

# Content type analysis (MIME type detection for embedded data)
just analyse content-types <db>              # All content types
just analyse content-types --protocol BitcoinStamps <db>
just analyse content-types --mime-type image/png <db>

# Data size analysis (byte statistics)
just analyse protocol-data-sizes <db>        # Protocol-level byte totals
just analyse spendability-data-sizes <db>    # Bytes by spendability
just analyse content-type-spendability <db>  # Content type byte breakdown
just analyse comprehensive-data-sizes <db>   # All data size analyses

# Additional analyses
just analyse multisig-configurations <db>    # Exhaustive multisig config breakdown
just analyse dust-thresholds <db>            # Bitcoin dust threshold analysis
just analyse tx-sizes <db>                   # Transaction size distribution
just analyse stamps-weekly-fees <db>         # Bitcoin Stamps weekly fee analysis
just analyse output-counts <db>              # P2MS output count distribution

# Temporal analysis (Plotly JSON output with --format plotly)
just analyse stamps-variant-temporal <db>    # Stamps variant distribution over time
just analyse protocol-temporal <db>          # Protocol distribution over time
just analyse spendability-temporal <db>      # Spendability distribution over time
```

**Note**: For database paths with spaces, use direct script invocation:
```bash
./scripts/analyse.sh value "./path with spaces.db" --format json
```

**Content Type Detection**: The analyser automatically detects MIME types for embedded data (images, JSON, text, binary)

## Testing

```bash
# Run all tests
just test                            # All cargo tests
just test-all                        # Comprehensive test suite (unit + integration + E2E)

# Test specific stages with small dataset
just stage1-small
just stage2-small
just stage3-small

# Run specific protocol tests (umbrella command: just stage3-test <subcommand>)
just stage3-test stamps              # Bitcoin Stamps tests
just stage3-test counterparty        # Counterparty tests
just stage3-test omni                # Omni Layer tests
just stage3-test datastorage         # DataStorage tests
just stage3-test decoder             # Unified decoder tests (requires Bitcoin RPC)
just stage3-test all                 # All Stage 3 tests
```

#### Test Organisation

Tests are organised into three categories:
- **Unit tests** (`tests/unit/`): Core functionality, RPC client, stage processors
- **Integration tests** (`tests/integration/`): Full pipeline, decoder tests
- **Test data** (`tests/test_data/`): Real Bitcoin transaction data in protocol-specific JSON files (counterparty/, stamps/, omni/)

Most protocol tests use real Bitcoin transaction data to ensure accurate validation.

For detailed testing documentation, see [tests/README.md](tests/README.md).

## Performance

Real-world production metrics on **M1 Max MacBook Pro** with Bitcoin Core running on localhost:

- **Stage 1**: 253,613 records/sec (streaming ~167M UTXOs in 11 minutes)
  - Processed: 167,109,782 records
  - P2MS outputs found: 2,302,320 (1.38% hit rate)
  - Time: 658.9s (10m 59s)

- **Stage 2**: 73.1 tx/sec (RPC-bound, 1.27M transactions in 4.8 hours)
  - Processed: 1,267,032 transactions
  - Time: 17,345.8s (4h 49m 6s)

- **Stage 3**: 293 classifications/sec (1.27M transactions in 1.2 hours)
  - Classified: 1,267,032 transactions
  - Time: 4,322.4s (1h 12m 2s)

**Total Pipeline**: ~6.2 hours for complete analysis of 167M UTXOs → 2.3M P2MS outputs → 1.27M classified protocols

**Memory**: ~100MB constant (streaming architecture)

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- Code is formatted (`cargo fmt`)
- Linting passes (`cargo clippy`)

## License

MIT License - See LICENSE file for details

## Resources

- [`bitcoin-utxo-dump`](https://github.com/in3rsha/bitcoin-utxo-dump)
- [Bitcoin Stamps Indexer](https://github.com/stampchain-io/btc_stamps) - Official Bitcoin Stamps indexer
- [Bitcoin Stamps Documentation](https://github.com/mikeinspace/stamps) - Protocol specs and documentation
- [Bitcoin Stamps Explorer](https://github.com/stampchain-io/BTCStampsExplorer) - Web explorer for Stamps
- [Stamps SDK](https://github.com/stampchain-io/stamps_sdk) - TypeScript SDK for Bitcoin Stamps
- [Counterparty Core](https://github.com/CounterpartyXCP/counterparty-core) - Counterparty protocol reference
- [Electrum-Counterparty](https://github.com/Jpja/Electrum-Counterparty) - Electrum wallet with Counterparty and Stamps support
- [OmniCore](https://github.com/OmniLayer/omnicore) - Omni Layer Bitcoin Core fork
- [Omni Layer Spec](https://github.com/OmniLayer/spec) - Omni Layer protocol specification
- [Chancecoin](https://github.com/chancecoin/chancecoinj) - Chancecoin protocol implementation
- [PPk Protocol (English docs)](https://github.com/ppkpub/docs/tree/master/English)
