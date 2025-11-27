# P2MS Analyser Development Automation

default_db_path := "./p2ms_analysis_production.db"

# Show available commands when running 'just' with no arguments
default:
    @echo "P2MS Analyser - Common Commands (run 'just --list' for full list)"
    @echo ""
    @echo "Build & Test:"
    @echo "  build                        - Build the project"
    @echo "  test                         - Run cargo tests"
    @echo "  test-all                     - Comprehensive test suite (5-15 min)"
    @echo "  lint                         - Format and lint code"
    @echo ""
    @echo "Development:"
    @echo "  stage1-small                 - Test Stage 1 (1M records)"
    @echo "  stage2-small                 - Test Stage 2 (requires RPC)"
    @echo "  stage3-small                 - Test Stage 3 classification"
    @echo "  test-rpc                     - Test Bitcoin RPC connectivity"
    @echo "  stage3-test <cmd> [opts...]  - Run tests (all, stamps, decoder, etc.)"
    @echo ""
    @echo "Production:"
    @echo "  production-pipeline          - Complete Stage 1→2→3 pipeline"
    @echo "  stage1-production            - Stage 1 only"
    @echo "  stage2-production            - Stage 2 only"
    @echo "  stage3-production            - Stage 3 only"
    @echo ""
    @echo "Analysis (use: just analyse <cmd> [db] [opts...]):"
    @echo "  analyse value [db] [opts]    - Value analysis"
    @echo "  analyse value-distributions  - Value distribution histograms (for plotting)"
    @echo "  analyse full [db] [opts]     - Comprehensive report"
    @echo "  analyse content-types [opts] - Content type distribution"
    @echo "  analyse protocol-data-sizes  - Protocol-level data sizes"
    @echo "  analyse comprehensive-data-sizes - All data size analyses"
    @echo "  analyse multisig-configurations - Multisig config exhaustive analysis"
    @echo "  analyse dust-thresholds      - Bitcoin dust threshold analysis"
    @echo "  analyse tx-sizes             - Transaction size distribution"
    @echo "  analyse stamps-weekly-fees   - Bitcoin Stamps weekly fee analysis"
    @echo "  stats [db]                   - Quick statistics"
    @echo ""
    @echo "Visualisation (use: just viz <cmd> [db] [opts...]):"
    @echo "  viz temporal [db] [opts]     - Temporal distribution plot"
    @echo "  viz protocols [db] [opts]    - Protocol distribution plot"
    @echo "  viz stats [db]               - Visualisation statistics"
    @echo ""
    @echo "Utilities:"
    @echo "  setup-config                 - First-time configuration"
    @echo "  clean                        - Clean build artifacts"
    @echo "  decode-txid <txid>           - Decode transaction via RPC"
    @echo ""
    @echo "Note: Arguments with spaces require direct script usage:"
    @echo "  ./scripts/analyse.sh value \"./path with spaces.db\" --format json"
    @echo "  ./scripts/viz.sh temporal \"./custom.db\" --output \"file with spaces.png\""
    @echo ""
    @echo "Commands accept subcommands: just analyse value, just viz temporal, etc."
    @echo "For full command list: just --list"
    @echo "For detailed help: See CLAUDE.md and docs/"

# ============================================================================
# === BASIC DEVELOPMENT ===
# ============================================================================

# Build the project
build:
    cargo build --release

# Run tests
test:
    cargo test

# Run comprehensive test suite (unit, integration, E2E pipeline)
test-all:
    ./scripts/test-all.sh

# Check code without building
check:
    cargo check

# Lint and format code
lint:
    cargo fmt
    cargo clippy -- -D warnings

# Clean test artifacts
clean:
    rm -f test_output/*.db
    rm -rf test_output/unit_tests/*.db

# ============================================================================
# === STAGE 1 DEVELOPMENT ===
# ============================================================================

# Integration test with small dataset (1M records)
stage1-small:
    ./scripts/stage1-runner.sh tests/test_data/utxo_1m.csv test_output/stage1_small.db 10000 "small dataset (1M records)"

# ============================================================================
# === STAGE 2 DEVELOPMENT ===
# ============================================================================

# Test Bitcoin RPC connectivity
test-rpc:
    cargo run -- test-rpc

# Test Bitcoin RPC with custom settings
test-rpc-custom url username password:
    cargo run -- test-rpc --rpc-url "{{url}}" --rpc-username "{{username}}" --rpc-password "{{password}}"

# Run Stage 2 on small database (requires Bitcoin RPC)
stage2-small:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Running Stage 2 on small database"
    if [ ! -f test_output/stage1_small.db ]; then
        echo "Creating small database first..."
        just stage1-small
    fi
    cargo run -- stage2 --database-path test_output/stage1_small.db --batch-size 50 --progress-interval 100

# ============================================================================
# === STAGE 3 DEVELOPMENT ===
# ============================================================================

# Run Stage 3 on small database
stage3-small:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Running Stage 3 on small database"
    if [ ! -f test_output/stage1_small.db ]; then
        echo "Creating small database first..."
        just stage1-small
        just stage2-small
    else
        # Check if we have Stage 2 data
        if ! sqlite3 test_output/stage1_small.db "SELECT name FROM sqlite_master WHERE type='table' AND name='enriched_transactions';" | grep -q enriched_transactions; then
            echo "Running Stage 2 enrichment first..."
            just stage2-small
        fi
    fi
    cargo run -- stage3 --database-path test_output/stage1_small.db --batch-size 100

# ============================================================================
# === STAGE 3 TESTING ===
# ============================================================================

# Run Stage 3 tests (umbrella command)
# Usage: just stage3-test <command> [options...]
# Commands: all, counterparty, stamps, omni, chancecoin, datastorage, core, decoder, decoder-verbose
# Examples:
#   just stage3-test all
#   just stage3-test stamps
#   just stage3-test decoder-verbose
stage3-test cmd *args="":
    ./scripts/test-stage3.sh "{{cmd}}" {{args}}

# ============================================================================
# === DECODER TOOLS ===
# ============================================================================

# Decode any transaction ID using RPC (no database required)
# Usage: just decode-txid <txid> [output_dir] [verbose]
# Examples:
#   just decode-txid <txid>                    # Uses default output dir
#   just decode-txid <txid> verbose            # Verbose mode with default output dir
#   just decode-txid <txid> /tmp/out verbose   # Custom output dir with verbose mode
decode-txid txid *args="":
    #!/usr/bin/env bash
    TXID="{{txid}}"
    OUTPUT_DIR="./output_data/decoded"
    VERBOSE_FLAG=""

    # Parse remaining arguments
    for arg in {{args}}; do
        case "$arg" in
            verbose|v|-v|--verbose)
                VERBOSE_FLAG="--verbose"
                ;;
            *)
                # Assume it's an output directory if it's not a verbose flag
                if [ "$arg" != "" ]; then
                    OUTPUT_DIR="$arg"
                fi
                ;;
        esac
    done

    echo "Attempting to decode transaction via RPC: $TXID"
    echo "Output directory: $OUTPUT_DIR"
    if [ -n "$VERBOSE_FLAG" ]; then
        echo "Verbose mode: ENABLED"
    fi
    echo "This command uses Bitcoin Core RPC to:"
    echo "  • Detect protocol (Bitcoin Stamps, Counterparty, Omni, PPk, DataStorage, etc.)"
    echo "  • Decode and save the data to the appropriate subdirectory"
    echo ""
    mkdir -p "$OUTPUT_DIR"
    RUST_LOG=info cargo run -- decode-txid "$TXID" --output-dir "$OUTPUT_DIR" $VERBOSE_FLAG

# ARC4 deobfuscation utility
arc4 txid:
    cargo run -- arc4 {{txid}}

# ARC4 with verbose output (shows raw P2MS data)
arc4-verbose txid:
    cargo run -- arc4 {{txid}} --show-raw

# ARC4 with JSON output
arc4-json txid:
    cargo run -- arc4 {{txid}} --format json

# ============================================================================
# === PRODUCTION ===
# ============================================================================

# Production pipeline (unattended, no prompts)
production-pipeline:
    ./scripts/production/pipeline.sh

# Production run with full dataset
stage1-production:
    ./scripts/production/stage1.sh

# Production Stage 2 enrichment
stage2-production:
    ./scripts/production/stage2.sh

# Production Stage 3 classification
stage3-production:
    ./scripts/production/stage3.sh

# ============================================================================
# === UTILITIES ===
# ============================================================================

# Setup configuration (copy example and prompt for UTXO path)
setup-config:
    #!/usr/bin/env bash
    if [ ! -f config.toml ]; then
        echo "Setting up configuration..."
        cp config.toml.example config.toml
        echo "✅ Created config.toml from example"
        echo ""
        echo "Please edit config.toml to set your UTXO CSV path:"
        echo "  utxo_csv = \"/path/to/your/utxodump.csv\""
        echo ""
        echo "Or set environment variable:"
        echo "  export UTXO_CSV_PATH=/path/to/your/utxodump.csv"
    else
        echo "⚠️ config.toml already exists"
    fi

# Create all test datasets
create-test-data:
    ./test_data/create_test_datasets.sh

# Fetch single transaction for investigation (saves to output_data/fetched/)
fetch-tx txid protocol="unknown" output="":
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Fetching transaction for investigation"
    echo "   Output: output_data/fetched/{{protocol}}/"
    if [ -n "{{output}}" ]; then
        cargo run --release -- fetch tx {{txid}} --protocol {{protocol}} --output {{output}}
    else
        cargo run --release -- fetch tx {{txid}} --protocol {{protocol}}
    fi

# Fetch transaction as test fixture (saves to tests/test_data/)
fetch-tx-fixture txid protocol:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Fetching transaction as test fixture"
    echo "   Output: tests/test_data/{{protocol}}/"
    cargo run --release -- fetch tx {{txid}} --protocol {{protocol}} --output-dir tests/test_data

# Fetch transaction with all its inputs (investigation)
fetch-tx-with-inputs txid protocol="unknown":
    cargo run --release -- fetch tx {{txid}} --protocol {{protocol}} --with-inputs

# Batch fetch transactions from file (investigation)
fetch-batch file protocol="unknown":
    cargo run --release -- fetch batch --file {{file}} --protocol {{protocol}}

# Scan test fixtures and fetch missing input transactions
scan-fixtures pattern="tests/test_data/omni/*.json":
    cargo run --release -- fetch scan-inputs {{pattern}}

# Show database statistics (shell script - fast, tabular format)
stats db_path=default_db_path:
    ./scripts/database_stats.sh "{{db_path}}"

# Show database statistics in JSON format
stats-json db_path=default_db_path:
    ./scripts/database_stats.sh "{{db_path}}" --json

# Run analysis commands (umbrella command)
# Usage: just analyse <command> [db_path] [options...]
# Commands: burn-patterns, fees, value, value-distributions, classifications, signatures, spendability,
#           content-types, full, protocol-data-sizes, spendability-data-sizes, content-type-spendability,
#           comprehensive-data-sizes, multisig-configurations, dust-thresholds, tx-sizes, stamps-weekly-fees
# Examples:
#   just analyse value                           # Uses default DB
#   just analyse value ./custom.db --format json
#   just analyse value-distributions --format json  # Value histogram data for plotting
#   just analyse content-types --protocol BitcoinStamps
#   just analyse protocol-data-sizes ./custom.db --format json
#   just analyse comprehensive-data-sizes        # All data size analyses
#   just analyse multisig-configurations         # Exhaustive multisig config analysis
#   just analyse dust-thresholds                 # Bitcoin dust threshold analysis
#   just analyse tx-sizes                        # Transaction size distribution
#   just analyse stamps-weekly-fees --format plotly  # Weekly fee analysis for plotting
analyse cmd db_path=default_db_path *args="":
    ./scripts/analyse.sh "{{cmd}}" "{{db_path}}" {{args}}

# Show schema of database
schema db_path=default_db_path:
    sqlite3 "{{db_path}}" ".schema"

# Query database interactively
query db_path=default_db_path:
    sqlite3 "{{db_path}}"

# List all P2MS outputs in database (limited to first 10)
list-outputs db_path=default_db_path:
    sqlite3 "{{db_path}}" "SELECT * FROM transaction_outputs ORDER BY height LIMIT 10;"

# Check for resume checkpoints
checkpoints db_path=default_db_path:
    sqlite3 "{{db_path}}" "SELECT * FROM processing_checkpoints;"

# Inspect specific transaction details
inspect-tx txid db_path=default_db_path:
    ./scripts/inspect_transaction.sh "{{txid}}" "{{db_path}}"

# ============================================================================
# === VISUALISATION ===
# ============================================================================

# Visualisation commands (umbrella command)
# Usage: just viz <command> [db_path] [options...]
# Commands: --help, stats, temporal, protocols, spendability, export-protocols, export-spendability
# Examples:
#   just viz --help
#   just viz stats
#   just viz temporal ./custom.db --bin monthly --output output_data/plots/temporal.png
viz cmd db_path=default_db_path *args="":
    #!/usr/bin/env bash
    # If cmd starts with -, it's a flag (like --help), don't pass db_path
    if [[ "{{cmd}}" =~ ^- ]]; then
        ./scripts/viz.sh "{{cmd}}" {{args}}
    else
        ./scripts/viz.sh "{{cmd}}" "{{db_path}}" {{args}}
    fi

# Build complete block time dataset (ONE-TIME operation, requires Bitcoin RPC)
# Auto-resumes if interrupted - use --no-resume to start fresh
build-block-times max_height="":
    #!/usr/bin/env bash
    if [ -n "{{max_height}}" ]; then
        .venv/bin/python visualisation/build_block_time_dataset.py --max-height {{max_height}}
    else
        .venv/bin/python visualisation/build_block_time_dataset.py
    fi
