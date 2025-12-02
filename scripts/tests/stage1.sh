#!/usr/bin/env bash
set -euo pipefail

# Stage 1 parameterized runner
# Usage: ./scripts/tests/stage1.sh <CSV_PATH> <DB_PATH> <BATCH_SIZE> [DESCRIPTION]

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <CSV_PATH> <DB_PATH> <BATCH_SIZE> [DESCRIPTION]"
    echo ""
    echo "Examples:"
    echo "  $0 tests/test_data/utxo_1m.csv test_output/stage1_small.db 10000 'small dataset (1M records)'"
    exit 1
fi

CSV_PATH="$1"
DB_PATH="$2"
BATCH_SIZE="$3"
DESCRIPTION="${4:-dataset}"

echo "Testing with $DESCRIPTION"

# Check if CSV exists, create if needed
if [[ ! -f "$CSV_PATH" ]]; then
    echo "Creating test dataset..."
    ./tests/test_data/create_test_datasets.sh
fi

# Run Stage 1 with timing
time cargo run -- stage1 \
    --csv-path "$CSV_PATH" \
    --database-path "$DB_PATH" \
    --batch-size "$BATCH_SIZE"

echo "Test complete"
echo "Database stats:"
sqlite3 "$DB_PATH" "SELECT COUNT(*) as 'Total P2MS outputs' FROM transaction_outputs;"
