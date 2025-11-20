#!/usr/bin/env bash
set -euo pipefail

echo "STAGE 3: Protocol Classification"
echo "This will classify all enriched transactions!"
if [[ ! -f ./p2ms_analysis_production.db ]]; then
    echo "Production database not found. Run 'just stage1-production' first."
    exit 1
fi

# Check if we have Stage 2 data
if ! sqlite3 ./p2ms_analysis_production.db "SELECT name FROM sqlite_master WHERE type='table' AND name='enriched_transactions';" | grep -q enriched_transactions; then
    echo "No Stage 2 data found. Run 'just stage2-production' first."
    exit 1
fi

# Check if classification table already exists with data
if sqlite3 ./p2ms_analysis_production.db "SELECT name FROM sqlite_master WHERE type='table' AND name='transaction_classifications';" | grep -q transaction_classifications; then
    existing_count=$(sqlite3 ./p2ms_analysis_production.db "SELECT COUNT(*) FROM transaction_classifications;")
    if [[ "$existing_count" -gt 0 ]]; then
        echo "Found existing classification data: $existing_count records"
        echo ""
        echo "Current classification breakdown:"
        sqlite3 ./p2ms_analysis_production.db "SELECT protocol, COUNT(*) as count FROM transaction_classifications GROUP BY protocol ORDER BY count DESC;" 2>/dev/null || echo "Could not retrieve breakdown"
        echo ""
        echo "Options:"
        echo "  [R] RESUME - Continue from checkpoint (recommended after crashes)"
        echo "  [D] DROP and restart - Delete all classifications and start over"
        echo "  [C] CANCEL - Exit without changes"
        echo ""
        read -r -p "Choose option [R/D/C]: " action
        case "$action" in
            R|r)
                echo "Resuming Stage 3 classification from checkpoint..."
                ;;
            D|d)
                read -r -p "Confirm DROP and restart? Type 'DROP-AND-RECLASSIFY': " confirm
                if [[ "$confirm" != "DROP-AND-RECLASSIFY" ]]; then
                    echo "Production Stage 3 cancelled - existing classifications preserved"
                    exit 1
                fi
                echo "🗑️  Dropping existing classification tables..."
                sqlite3 ./p2ms_analysis_production.db "DROP TABLE IF EXISTS transaction_classifications;"
                sqlite3 ./p2ms_analysis_production.db "DROP TABLE IF EXISTS p2ms_output_classifications;"
                ;;
            *)
                echo "Production Stage 3 cancelled"
                exit 1
                ;;
        esac
    fi
else
    read -r -p "Ready to run Stage 3 classification. Type 'YES' to continue: " final_confirm
    if [[ "$final_confirm" != "YES" ]]; then
        echo "Production Stage 3 cancelled"
        exit 1
    fi
fi

time cargo run --release -- stage3 \
    --database-path ./p2ms_analysis_production.db \
    --batch-size 500
echo "Production Stage 3 classification complete!"
