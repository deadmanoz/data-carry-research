#!/bin/bash

# Script to create test datasets from the main 30GB+ UTXO CSV file
# CRITICAL: The main CSV file is huge - always create subsets for testing!

# Try to get the UTXO CSV path from environment variable first
MAIN_CSV="${UTXO_CSV_PATH:-}"

# If not set in environment, try to read from config.toml
if [ -z "$MAIN_CSV" ] && [ -f "../../config.toml" ]; then
    MAIN_CSV=$(grep "utxo_csv" ../../config.toml | cut -d'"' -f2 2>/dev/null || true)
fi

# Final fallback to prompt user
if [ -z "$MAIN_CSV" ] || [ ! -f "$MAIN_CSV" ]; then
    echo "ERROR: UTXO CSV file path not configured or file not found."
    echo ""
    echo "Please either:"
    echo "  1. Set environment variable: export UTXO_CSV_PATH=/path/to/utxodump.csv"
    echo "  2. Configure config.toml in the parent directory"
    echo "  3. Run 'just setup-config' in the project root directory"
    echo ""
    if [ -n "$MAIN_CSV" ]; then
        echo "Current configured path: $MAIN_CSV"
    fi
    exit 1
fi

echo "Creating test datasets from main UTXO CSV file..."
echo "Source: $MAIN_CSV"

# Create current directory (tests/test_data) if it doesn't exist
mkdir -p .

echo "Creating test datasets..."

# Small test dataset (1M records ~100MB) - for integration testing
echo "  Creating utxo_1m.csv (1M records)..."
head -n 1000001 "$MAIN_CSV" > utxo_1m.csv

# P2MS-focused test dataset (first 50K P2MS records)
echo "  Creating p2ms_focused.csv (P2MS records only)..."
head -n 1 "$MAIN_CSV" > p2ms_focused.csv
grep ",p2ms," "$MAIN_CSV" | head -n 50000 >> p2ms_focused.csv

echo "Test datasets created successfully!"
echo ""
echo "Dataset sizes:"
ls -lh utxo_*.csv p2ms_*.csv 2>/dev/null | awk '{print "  " $9 ": " $5}'

echo ""
echo "Usage examples:"
echo "  # Development"
echo "  cargo run -- stage1 --csv-path tests/test_data/utxo_1m.csv --database-path ./test_output/testing.db"
echo ""
echo "  # P2MS focused testing"
echo "  cargo run -- stage1 --csv-path tests/test_data/p2ms_focused.csv --database-path ./test_output/testing.db"