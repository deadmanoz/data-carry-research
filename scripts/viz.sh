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
#
# Examples:
#   ./scripts/viz.sh --help                                     # Show help
#   ./scripts/viz.sh stats                                      # Stats with default DB
#   ./scripts/viz.sh temporal ./custom.db --bin monthly         # Custom DB
#   ./scripts/viz.sh protocols --bin yearly --output plots/protocols_yearly.png

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <COMMAND> [DB_PATH] [OPTIONS...]"
    echo ""
    echo "Commands: --help, stats, temporal, protocols, spendability,"
    echo "          export-protocols, export-spendability"
    echo ""
    echo "Examples:"
    echo "  $0 --help                          # Show CLI help"
    echo "  $0 stats                           # Stats with default DB"
    echo "  $0 temporal ./custom.db --bin monthly"
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
.venv/bin/python -m visualisation.cli "$COMMAND" --database "$DB_PATH" "${EXTRA_ARGS[@]}"
