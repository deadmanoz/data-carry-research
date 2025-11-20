#!/usr/bin/env bash
set -euo pipefail

echo "🚀 UNATTENDED PRODUCTION PIPELINE: Stage 1 → Stage 2 → Stage 3"
echo "Processing complete 30GB+ dataset through all stages without prompts"
echo "Started: $(date)"
echo ""
echo "Requirements check:"
echo "  • 30GB+ UTXO CSV file configured in config.toml or UTXO_CSV_PATH"
echo "  • Bitcoin Core node with RPC enabled and txindex=1"
echo "  • ~10GB+ free disk space for final database"
echo "  • Stable system (process resumable via checkpoints)"
echo ""

# Pre-flight checks
echo "⚙️  Running pre-flight checks..."
if ! cargo run --quiet -- test-rpc &>/dev/null; then
    echo "❌ Bitcoin RPC connection failed. Check your Bitcoin node and configuration."
    exit 1
fi
echo "✅ Bitcoin RPC connection OK"

echo ""
echo "tarting production pipeline..."
echo ""

echo "=== STAGE 1: P2MS Detection ($(date)) ==="
time cargo run --release -- stage1 \
    --database-path ./p2ms_analysis_production.db \
    --batch-size 50000
echo "✅ Stage 1 complete: $(date)"
echo ""

echo "=== STAGE 2: Transaction Enrichment ($(date)) ==="
time cargo run --release -- stage2 \
    --database-path ./p2ms_analysis_production.db \
    --batch-size 100 \
    --progress-interval 1000 \
    --concurrent-requests 5
echo "✅ Stage 2 complete: $(date)"
echo ""

echo "=== STAGE 3: Protocol Classification ($(date)) ==="
time cargo run --release -- stage3 \
    --database-path ./p2ms_analysis_production.db \
    --batch-size 500
echo "✅ Stage 3 complete: $(date)"
echo ""

echo "UNATTENDED PRODUCTION PIPELINE FINISHED!"
echo "Completed: $(date)"
echo ""
echo "Final Results:"
# Get script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"$SCRIPT_DIR/../database_stats.sh" ./p2ms_analysis_production.db
