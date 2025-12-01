#!/usr/bin/env bash
set -euo pipefail

# Analysis dispatcher for P2MS Analyser
# Routes analysis commands to the Rust CLI with proper argument handling
#
# Usage: ./scripts/analyse.sh <COMMAND> [DB_PATH] [OPTIONS...]
#
# Commands (all use --release for optimal performance):
#   burn-patterns              - Show burn patterns detected
#   fees                       - Show fee analysis
#   value                      - Show comprehensive value analysis
#   value-distributions        - Show value distribution histograms (for plotting)
#   classifications            - Show protocol classification statistics
#   signatures                 - Show protocol signature analysis
#   spendability               - Show spendability analysis
#   content-types              - Show content type distribution
#   protocol-data-sizes        - Show protocol-level data sizes
#   spendability-data-sizes    - Show data sizes by spendability
#   content-type-spendability  - Show content type spendability breakdown
#   comprehensive-data-sizes   - Show all data size analyses
#   multisig-configurations    - Show exhaustive multisig configuration breakdown
#   dust-thresholds            - Show Bitcoin dust threshold analysis
#   tx-sizes                   - Show transaction size distribution
#   stamps-weekly-fees         - Show Bitcoin Stamps weekly fee analysis
#   stamps-variant-temporal    - Show Stamps variant distribution over time
#   output-counts              - Show P2MS output count distribution per transaction
#   protocol-temporal          - Show protocol distribution over time
#   spendability-temporal      - Show spendability distribution over time
#   full                       - Show comprehensive analysis report
#
# Examples:
#   ./scripts/analyse.sh value                                    # Uses default DB
#   ./scripts/analyse.sh value ./test_output/stage3_small.db      # Custom DB
#   ./scripts/analyse.sh value --format json                      # JSON output, default DB
#   ./scripts/analyse.sh value ./custom.db --format json          # Custom DB + JSON
#   ./scripts/analyse.sh content-types --protocol BitcoinStamps   # Filter by protocol
#   ./scripts/analyse.sh spendability --format json               # Spendability in JSON

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <COMMAND> [DB_PATH] [OPTIONS...]"
    echo ""
    echo "Commands: burn-patterns, fees, value, value-distributions, classifications,"
    echo "          signatures, spendability, content-types, protocol-data-sizes,"
    echo "          spendability-data-sizes, content-type-spendability,"
    echo "          comprehensive-data-sizes, multisig-configurations, dust-thresholds,"
    echo "          tx-sizes, stamps-weekly-fees, stamps-variant-temporal, output-counts,"
    echo "          protocol-temporal, spendability-temporal, full"
    echo ""
    echo "Examples:"
    echo "  $0 value                           # Uses default DB"
    echo "  $0 value ./custom.db               # Custom DB path"
    echo "  $0 value --format json             # JSON output"
    echo "  $0 value-distributions --format json # Value histogram data for plotting"
    echo "  $0 spendability ./custom.db --format json"
    echo "  $0 protocol-data-sizes             # Protocol data sizes"
    echo "  $0 comprehensive-data-sizes --format json"
    echo "  $0 multisig-configurations         # Exhaustive multisig config analysis"
    echo "  $0 stamps-weekly-fees --format plotly # Weekly fee analysis for plotting"
    exit 1
fi

COMMAND="$1"
shift

# Default database path
DEFAULT_DB="./p2ms_analysis_production.db"
DB_PATH=""
EXTRA_ARGS=()

# Check if first argument is DB path (doesn't start with -)
# This avoids misinterpreting flag values as DB paths
if [[ $# -gt 0 ]] && [[ ! "$1" =~ ^- ]]; then
    DB_PATH="$1"
    shift
fi

# All remaining args are passed through
EXTRA_ARGS=("$@")

# Process EXTRA_ARGS to handle specific flags like --plotly
PROCESSED_EXTRA_ARGS=()
for arg in "${EXTRA_ARGS[@]}"; do
    if [[ "$arg" == "--plotly" ]]; then
        PROCESSED_EXTRA_ARGS+=("--format" "plotly")
    else
        PROCESSED_EXTRA_ARGS+=("$arg")
    fi
done

# Use default DB if none provided
if [[ -z "$DB_PATH" ]]; then
    DB_PATH="$DEFAULT_DB"
fi

# All analysis commands use --release for optimal performance
RUST_LOG=off cargo run --quiet --release -- analyse "$COMMAND" --database-path "$DB_PATH" ${PROCESSED_EXTRA_ARGS[@]+ "${PROCESSED_EXTRA_ARGS[@]}"}
