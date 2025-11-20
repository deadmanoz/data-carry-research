#!/usr/bin/env bash
set -euo pipefail

echo "STAGE 1: Processing full 30GB+ dataset"
echo "This will take significant time and resources!"
echo "Make sure UTXO_CSV_PATH environment variable is set or config.toml is configured"

# Check for existing checkpoint
if [[ -f ./p2ms_analysis_production.db ]]; then
    checkpoint_info=$(sqlite3 ./p2ms_analysis_production.db "SELECT csv_line_number, total_processed, batch_number FROM stage1_checkpoint ORDER BY created_at DESC LIMIT 1;" 2>/dev/null || echo "")
    if [[ -n "$checkpoint_info" ]]; then
        echo ""
        echo "Found checkpoint: Line $(echo "$checkpoint_info" | cut -d'|' -f1), Processed $(echo "$checkpoint_info" | cut -d'|' -f2), Batch $(echo "$checkpoint_info" | cut -d'|' -f3)"
        echo "Stage 1 will automatically resume from this checkpoint."
        echo ""
    fi
fi

read -r -p "Are you sure? Type 'YES' to continue: " confirm
if [[ "$confirm" = "YES" ]]; then
    time cargo run --release -- stage1 \
        --database-path ./p2ms_analysis_production.db \
        --batch-size 50000
    echo "Production processing complete!"
else
    echo "Production run cancelled"
fi
