#!/usr/bin/env bash
set -euo pipefail

# Visualisation dispatcher for P2MS Analyser
# Routes visualisation commands to Python CLI with venv activation
#
# Usage: ./scripts/viz.sh <COMMAND> [DB_PATH] [OPTIONS...]
#
# Commands:
#   --help            - Show visualisation CLI help
#   stats             - Show visualisation database stats
#   temporal          - Generate temporal distribution plot
#   protocols         - Generate protocol distribution plot
#   spendability      - Generate spendability percentage plot
#   export-protocols  - Export protocol data as Plotly JSON
#   export-spendability - Export spendability data as Plotly JSON
#   stamps-weekly-fees - Export Bitcoin Stamps weekly fee data as Plotly JSON (via Rust CLI)
#
# Examples:
#   ./scripts/viz.sh --help                                     # Show help
#   ./scripts/viz.sh stats                                      # Stats with default DB
#   ./scripts/viz.sh temporal ./custom.db --bin monthly         # Custom DB
#   ./scripts/viz.sh protocols --bin yearly --output output_data/plots/protocols_yearly.png
#   ./scripts/viz.sh stamps-weekly-fees                         # Export weekly fee data

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <COMMAND> [DB_PATH] [OPTIONS...]"
    echo ""
    echo "Commands: --help, stats, temporal, protocols, spendability,"
    echo "          export-protocols, export-spendability, stamps-weekly-fees"
    echo ""
    echo "Examples:"
    echo "  $0 --help                          # Show CLI help"
    echo "  $0 stats                           # Stats with default DB"
    echo "  $0 temporal ./custom.db --bin monthly"
    echo "  $0 stamps-weekly-fees              # Export weekly fee data as Plotly JSON"
    exit 1
fi

COMMAND="$1"
shift

# Default database path
DEFAULT_DB="./p2ms_analysis_production.db"

# If command is --help or any flag, passthrough directly without DB path injection
if [[ "$COMMAND" =~ ^- ]]; then
    .venv/bin/python -m visualisation.cli "$COMMAND" "$@"
    exit 0
fi

# Handle stamps-weekly-fees - delegates to Rust CLI (not Python)
if [[ "${COMMAND}" == "stamps-weekly-fees" ]]; then
    # Default database and output paths
    DEFAULT_DB="./p2ms_analysis_production.db"
    DEFAULT_OUTPUT="./output_data/plots/stamps_weekly_fees.json"
    DB_PATH=""
    OUTPUT_PATH=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                OUTPUT_PATH="$2"
                shift 2
                ;;
            -*)
                # Unknown flag - pass through
                shift
                ;;
            *)
                # Non-flag argument - assume DB path
                if [[ -z "${DB_PATH}" ]]; then
                    DB_PATH="$1"
                fi
                shift
                ;;
        esac
    done

    # Use defaults if not provided
    if [[ -z "${DB_PATH}" ]]; then
        DB_PATH="${DEFAULT_DB}"
    fi
    if [[ -z "${OUTPUT_PATH}" ]]; then
        OUTPUT_PATH="${DEFAULT_OUTPUT}"
    fi

    # Delegate to just recipe which runs Rust CLI
    just analyse stamps-weekly-fees "${DB_PATH}" --format plotly -o "${OUTPUT_PATH}"
    exit 0
fi

# Check if first argument is DB path (doesn't start with -)
# This avoids misinterpreting flag values as DB paths
DB_PATH=""
EXTRA_ARGS=()

if [[ $# -gt 0 ]] && [[ ! "$1" =~ ^- ]]; then
    DB_PATH="$1"
    shift
fi

# All remaining args are passed through
EXTRA_ARGS=("$@")

# Use default DB if none provided
if [[ -z "$DB_PATH" ]]; then
    DB_PATH="$DEFAULT_DB"
fi

# Run Python visualisation CLI with venv
.venv/bin/python -m visualisation.cli "$COMMAND" --database "$DB_PATH" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
