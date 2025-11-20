#!/usr/bin/env bash
set -euo pipefail

echo "STAGE 2: Enriching production database"
echo "This requires Bitcoin RPC access and will take significant time!"
echo "Make sure your Bitcoin node is synced and RPC is configured"
if [[ ! -f ./p2ms_analysis_production.db ]]; then
    echo "Production database not found. Run 'just stage1-production' first."
    exit 1
fi

# Check for existing enriched data
if sqlite3 ./p2ms_analysis_production.db "SELECT name FROM sqlite_master WHERE type='table' AND name='enriched_transactions';" | grep -q enriched_transactions; then
    enriched_count=$(sqlite3 ./p2ms_analysis_production.db "SELECT COUNT(*) FROM enriched_transactions;")
    total_p2ms=$(sqlite3 ./p2ms_analysis_production.db "SELECT COUNT(DISTINCT txid) FROM transaction_outputs WHERE script_type = 'multisig';")
    if [[ "$enriched_count" -gt 0 ]]; then
        echo ""
        echo "Found existing enrichment data: $enriched_count / $total_p2ms transactions processed"
        echo "Stage 2 will automatically resume and process remaining transactions."
        echo ""
    fi
fi

read -r -p "Are you sure? Type 'YES' to continue: " confirm
if [[ "$confirm" = "YES" ]]; then
    time cargo run --release -- stage2 \
        --database-path ./p2ms_analysis_production.db \
        --batch-size 100 \
        --progress-interval 1000 \
        --concurrent-requests 5
    echo "Production Stage 2 enrichment complete!"
else
    echo "Production Stage 2 cancelled"
fi
