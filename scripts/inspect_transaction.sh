#!/bin/bash
# Quick transaction inspection tool
# Usage: ./scripts/inspect_transaction.sh <txid> [db_path]

set -e

TXID="$1"
DB_PATH="${2:-./p2ms_analysis_production.db}"

if [ -z "$TXID" ]; then
    echo "Usage: $0 <txid> [db_path]"
    echo ""
    echo "Example:"
    echo "  $0 1caf0432ef165b19d5b5d726dc7fd1461390283c15bade2c9683fd712099e53b"
    exit 1
fi

echo "======================================"
echo "Transaction Inspector"
echo "======================================"
echo "TXID: $TXID"
echo "Database: $DB_PATH"
echo ""

# Check if transaction exists in database
if ! sqlite3 "$DB_PATH" "SELECT 1 FROM enriched_transactions WHERE txid = '$TXID' LIMIT 1" > /dev/null 2>&1; then
    echo "❌ Transaction not found in database"
    exit 1
fi

echo "📊 DATABASE INFORMATION"
echo "========================================"
echo ""

# Protocol classification (per-transaction)
echo "Protocol Classification:"
sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT protocol, variant, classification_method
FROM transaction_classifications
WHERE txid = '$TXID';
EOF

echo ""
echo "P2MS Output Details:"
sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 5 10 20 60
SELECT
    vout,
    height,
    json_extract(metadata_json, '\$.required_sigs') || '-of-' || json_extract(metadata_json, '\$.total_pubkeys') as multisig_type,
    SUBSTR(script_hex, 1, 60) || '...' as script_preview
FROM transaction_outputs
WHERE txid = '$TXID'
  AND script_type = 'multisig'
ORDER BY vout;
EOF

echo ""
echo "Enrichment Data:"
sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT
    height,
    input_count,
    output_count,
    total_fee,
    total_input_value,
    total_output_value
FROM enriched_transactions
WHERE txid = '$TXID';
EOF

echo ""
echo "🔗 BITCOIN CORE RPC LOOKUP"
echo "========================================"
echo ""

# Fetch from Bitcoin Core using CLI tool
echo "Fetching transaction details from Bitcoin Core..."
echo ""

# Use cargo to fetch transaction (will be saved to /tmp for display only)
TEMP_FILE="/tmp/inspect_${TXID}.json"
rm -f "$TEMP_FILE" 2>/dev/null

if cargo run --release --quiet -- fetch tx "$TXID" --output-dir "/tmp" --output "inspect_${TXID}" 2>&1 | grep -q "✓ Fetched"; then
    if [ -f "$TEMP_FILE" ]; then
        echo "Transaction Overview:"
        jq '{
            txid: .txid,
            size: .size,
            vsize: .vsize,
            version: .version,
            locktime: .locktime,
            vin_count: (.vin | length),
            vout_count: (.vout | length),
            inputs_preview: [.vin[0:3][] | {
                txid: .txid,
                vout: .vout
            }],
            outputs_preview: [.vout[0:3][] | {
                n: .n,
                value: .value,
                type: .scriptPubKey.type
            }]
        }' "$TEMP_FILE"

        echo ""
        echo "P2MS Outputs Only:"
        jq '.vout[] | select(.scriptPubKey.type == "multisig") | {
            n: .n,
            value: .value,
            type: .scriptPubKey.type,
            hex: .scriptPubKey.hex
        }' "$TEMP_FILE"

        # Cleanup
        rm -f "$TEMP_FILE"
    fi
else
    echo "⚠️  Could not fetch transaction from Bitcoin Core"
    echo "Make sure Bitcoin Core is running and RPC is configured"
fi

echo ""
echo "========================================"
echo "💡 NEXT STEPS"
echo "========================================"
echo ""
echo "To decode this transaction with the unified decoder:"
echo "  cargo run -- decode-txid $TXID"
echo ""
echo "To extract just the classification:"
echo "  cargo run -- decode-txid $TXID --no-output"
echo ""
echo "To view raw script hex for manual analysis:"
echo "  sqlite3 $DB_PATH \"SELECT script_hex FROM transaction_outputs WHERE txid = '$TXID' AND script_type = 'multisig'\""
echo ""
