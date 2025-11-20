#!/usr/bin/env bash
# Database statistics script for P2MS Analyser
# Shows comprehensive statistics across all processing stages
#
# Usage: ./scripts/database_stats.sh [db_path] [--json]
#
# Parameters:
#   db_path  - Path to database (default: ./p2ms_analysis_production.db)
#   --json   - Output in JSON format for scripting

set -euo pipefail

DB_PATH="${1:-./p2ms_analysis_production.db}"
JSON_OUTPUT=false

# Check for --json flag
if [[ "${2:-}" == "--json" ]] || [[ "${1:-}" == "--json" ]]; then
    JSON_OUTPUT=true
    if [[ "${1:-}" == "--json" ]]; then
        DB_PATH="./p2ms_analysis_production.db"
    fi
fi

# Validate database exists
if [[ ! -f "$DB_PATH" ]]; then
    echo "❌ Error: Database not found at $DB_PATH" >&2
    exit 1
fi

# Check if database is accessible
if ! sqlite3 "$DB_PATH" "SELECT 1" > /dev/null 2>&1; then
    echo "❌ Error: Database is locked or inaccessible" >&2
    echo "Wait for processing to complete, then re-run this script." >&2
    exit 1
fi

# Helper function to check if table exists
table_exists() {
    local table_name="$1"
    sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name='$table_name';" | grep -q "$table_name"
}

# JSON output mode
if [[ "$JSON_OUTPUT" == true ]]; then
    # Build JSON object with all statistics
    json_output='{'

    # Stage 1 stats (P2MS outputs only - other outputs are ingested for classification purposes)
    # CRITICAL: Only count UTXO outputs (is_spent = 0), not spent outputs
    total_outputs=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;")
    coinbase_outputs=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_coinbase = 1 AND is_spent = 0;")
    regular_outputs=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_coinbase = 0 AND is_spent = 0;")
    min_height=$(sqlite3 "$DB_PATH" "SELECT MIN(height) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;")
    max_height=$(sqlite3 "$DB_PATH" "SELECT MAX(height) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;")
    min_amount=$(sqlite3 "$DB_PATH" "SELECT MIN(amount) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;")
    max_amount=$(sqlite3 "$DB_PATH" "SELECT MAX(amount) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;")

    json_output+='"stage1":{'
    json_output+="\"total_outputs\":$total_outputs,"
    json_output+="\"coinbase_outputs\":$coinbase_outputs,"
    json_output+="\"regular_outputs\":$regular_outputs,"
    json_output+="\"height_range\":{\"min\":$min_height,\"max\":$max_height},"
    json_output+="\"amount_range\":{\"min\":$min_amount,\"max\":$max_amount}"

    # Add M-of-N distribution if multisig outputs exist (calculate once, reuse below)
    # CRITICAL: Only count UTXO outputs (is_spent = 0), not spent outputs
    total_multisig=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;")

    if [[ "$total_multisig" -gt 0 ]]; then
        json_output+=',"m_of_n_distribution":{'

        m_of_n_data=$(sqlite3 "$DB_PATH" <<'EOF'

        SELECT
            COALESCE(
                json_extract(metadata_json, '$.required_sigs') || '-of-' ||
                json_extract(metadata_json, '$.total_pubkeys'),
                'Unknown'
            ) as type,
            COUNT(*) as count
        FROM transaction_outputs
        WHERE script_type = 'multisig'
        AND is_spent = 0
        GROUP BY type
        ORDER BY count DESC;
EOF
        )

        first=true
        while IFS='|' read -r m_of_n count; do
            if [[ -z "$m_of_n" ]] || [[ -z "$count" ]]; then
                continue
            fi

            if [[ "$first" == true ]]; then
                first=false
            else
                json_output+=','
            fi
            json_output+="\"$m_of_n\":$count"
        done <<< "$m_of_n_data"

        json_output+='}'
    fi

    # Add nonstandard outputs count
    nonstandard_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_outputs WHERE script_type = 'nonstandard';")
    if [[ "$nonstandard_count" -gt 0 ]]; then
        json_output+=",\"nonstandard_outputs\":$nonstandard_count"
    fi

    json_output+='}'

    # Stage 2 stats (if table exists)
    if table_exists "enriched_transactions"; then
        enriched_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM enriched_transactions;")
        burn_pattern_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(DISTINCT txid) FROM burn_patterns;")
        total_burn_patterns=$(sqlite3 "$DB_PATH" "SELECT COALESCE(COUNT(*), 0) FROM burn_patterns;")
        avg_fee=$(sqlite3 "$DB_PATH" "SELECT COALESCE(ROUND(AVG(transaction_fee), 2), 0) FROM enriched_transactions WHERE transaction_fee > 0;")
        avg_fee_per_byte=$(sqlite3 "$DB_PATH" "SELECT COALESCE(ROUND(AVG(fee_per_byte), 2), 0) FROM enriched_transactions WHERE fee_per_byte > 0;")

        json_output+=',"stage2":{'
        json_output+="\"enriched_transactions\":$enriched_count,"
        json_output+="\"transactions_with_burn_patterns\":$burn_pattern_count,"
        json_output+="\"total_burn_patterns\":$total_burn_patterns,"
        json_output+="\"average_fee_sats\":$avg_fee,"
        json_output+="\"average_fee_per_byte\":$avg_fee_per_byte"
        json_output+='}'
    fi

    # Stage 3 stats (if table exists)
    if table_exists "transaction_classifications"; then
        total_classified=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_classifications;" 2>/dev/null || echo "0")

        json_output+=',"stage3":{'
        json_output+="\"total_classified\":$total_classified"

        # Only add classifications if we have data
        if [[ "$total_classified" -gt 0 ]]; then
            # Get classification breakdown
            classifications=$(sqlite3 "$DB_PATH" "SELECT protocol, COUNT(*) FROM transaction_classifications GROUP BY protocol ORDER BY COUNT(*) DESC;" 2>/dev/null)

            if [[ -n "$classifications" ]]; then
                json_output+=',"classifications":{'

                first=true
                while IFS='|' read -r protocol count; do
                    # Skip empty lines
                    if [[ -z "$protocol" ]] || [[ -z "$count" ]]; then
                        continue
                    fi

                    if [[ "$first" == true ]]; then
                        first=false
                    else
                        json_output+=','
                    fi
                    json_output+="\"$protocol\":$count"
                done <<< "$classifications"

                json_output+='}'
            fi

            # Likely Data Storage variant breakdown (if present)
            likely_data_storage_variants=$(sqlite3 "$DB_PATH" "SELECT COALESCE(variant, 'Unknown'), COUNT(*) FROM transaction_classifications WHERE protocol = 'LikelyDataStorage' GROUP BY variant ORDER BY COUNT(*) DESC;" 2>/dev/null)

            if [[ -n "$likely_data_storage_variants" ]]; then
                json_output+=',"likely_data_storage_variants":{'

                first=true
                while IFS='|' read -r variant count; do
                    if [[ -z "$variant" ]] || [[ -z "$count" ]]; then
                        continue
                    fi

                    if [[ "$first" == true ]]; then
                        first=false
                    else
                        json_output+=','
                    fi
                    json_output+="\"$variant\":$count"
                done <<< "$likely_data_storage_variants"

                json_output+='}'
            fi

            # Get content type distribution
            content_types=$(sqlite3 "$DB_PATH" "SELECT COALESCE(content_type, 'NULL'), COUNT(*) FROM transaction_classifications GROUP BY content_type ORDER BY COUNT(*) DESC;" 2>/dev/null)

            if [[ -n "$content_types" ]]; then
                json_output+=',"content_types":{'

                first=true
                while IFS='|' read -r mime_type count; do
                    # Skip empty lines
                    if [[ -z "$mime_type" ]] || [[ -z "$count" ]]; then
                        continue
                    fi

                    if [[ "$first" == true ]]; then
                        first=false
                    else
                        json_output+=','
                    fi
                    json_output+="\"$mime_type\":$count"
                done <<< "$content_types"

                json_output+='}'
            fi

            # Add M-of-N by protocol (if multisig outputs with classifications exist)
            # CRITICAL: Only count UTXO outputs (is_spent = 0), not spent outputs
            classified_multisig_total=$(sqlite3 "$DB_PATH" "
                SELECT COUNT(*)
                FROM transaction_outputs to2
                JOIN transaction_classifications tc ON tc.txid = to2.txid
                WHERE to2.script_type = 'multisig'
                AND to2.is_spent = 0;
            " 2>/dev/null || echo "0")

            if [[ "${classified_multisig_total:-0}" -gt 0 ]]; then
                json_output+=',"m_of_n_by_protocol":{'

                protocol_m_of_n=$(sqlite3 "$DB_PATH" <<'EOF'

            SELECT
                tc.protocol,
                COALESCE(
                    json_extract(to2.metadata_json, '$.required_sigs') || '-of-' ||
                    json_extract(to2.metadata_json, '$.total_pubkeys'),
                    'Unknown'
                ) as type,
                COUNT(*) as count
            FROM transaction_classifications tc
            JOIN transaction_outputs to2 ON tc.txid = to2.txid
            WHERE to2.script_type = 'multisig'
            AND to2.is_spent = 0
            GROUP BY tc.protocol, type
            ORDER BY tc.protocol, count DESC;
EOF
                )

                first_protocol=true
                current_protocol=""
                first_type=true

                while IFS='|' read -r protocol m_of_n count; do
                    if [[ -z "$protocol" ]] || [[ -z "$count" ]]; then
                        continue
                    fi

                    # Start new protocol object
                    if [[ "$protocol" != "$current_protocol" ]]; then
                        if [[ -n "$current_protocol" ]]; then
                            json_output+='}'  # Close previous protocol
                        fi

                        if [[ "$first_protocol" == true ]]; then
                            first_protocol=false
                        else
                            json_output+=','
                        fi

                        json_output+="\"$protocol\":{"
                        current_protocol="$protocol"
                        first_type=true
                    fi

                    if [[ "$first_type" == true ]]; then
                        first_type=false
                    else
                        json_output+=','
                    fi

                    json_output+="\"$m_of_n\":$count"
                done <<< "$protocol_m_of_n"

                if [[ -n "$current_protocol" ]]; then
                    json_output+='}'  # Close last protocol
                fi

                json_output+='}'  # Close m_of_n_by_protocol
            fi
        fi

        json_output+='}'
    fi

    # Add P2MS output-level classifications and spendability stats if output classifications exist
    # CRITICAL: Only count UTXO outputs (is_spent = 0), not spent outputs
    if table_exists "p2ms_output_classifications"; then
        total_outputs=$(sqlite3 "$DB_PATH" "
            SELECT COUNT(*)
            FROM p2ms_output_classifications c
            JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
            WHERE o.is_spent = 0;
        " 2>/dev/null || echo "0")

        if [[ "$total_outputs" -gt 0 ]]; then
            # Output-level protocol classifications
            json_output+=',"p2ms_output_classifications":{'
            json_output+="\"total_outputs\":$total_outputs"

            # Protocol breakdown at output level
            output_protocols=$(sqlite3 "$DB_PATH" "
                SELECT c.protocol, COUNT(*)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE o.is_spent = 0
                GROUP BY c.protocol
                ORDER BY COUNT(*) DESC;
            " 2>/dev/null)

            if [[ -n "$output_protocols" ]]; then
                json_output+=',"protocols":{'

                first=true
                while IFS='|' read -r protocol count; do
                    if [[ -z "$protocol" ]] || [[ -z "$count" ]]; then
                        continue
                    fi

                    if [[ "$first" == true ]]; then
                        first=false
                    else
                        json_output+=','
                    fi
                    json_output+="\"$protocol\":$count"
                done <<< "$output_protocols"

                json_output+='}'
            fi

            # Variant breakdown at output level
            output_variants=$(sqlite3 "$DB_PATH" "
                SELECT c.protocol, c.variant, COUNT(*)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE c.variant IS NOT NULL
                AND o.is_spent = 0
                GROUP BY c.protocol, c.variant
                ORDER BY c.protocol, COUNT(*) DESC;
            " 2>/dev/null)

            if [[ -n "$output_variants" ]]; then
                json_output+=',"variants":{'

                first_protocol=true
                current_protocol=""
                first_variant=true

                while IFS='|' read -r protocol variant count; do
                    if [[ -z "$protocol" ]] || [[ -z "$count" ]]; then
                        continue
                    fi

                    # Start new protocol object
                    if [[ "$protocol" != "$current_protocol" ]]; then
                        if [[ -n "$current_protocol" ]]; then
                            json_output+='}'  # Close previous protocol
                        fi

                        if [[ "$first_protocol" == true ]]; then
                            first_protocol=false
                        else
                            json_output+=','
                        fi

                        json_output+="\"$protocol\":{"
                        current_protocol="$protocol"
                        first_variant=true
                    fi

                    if [[ "$first_variant" == true ]]; then
                        first_variant=false
                    else
                        json_output+=','
                    fi

                    json_output+="\"$variant\":$count"
                done <<< "$output_variants"

                if [[ -n "$current_protocol" ]]; then
                    json_output+='}'  # Close last protocol
                fi

                json_output+='}'
            fi

            json_output+='}'

            # Spendability stats
            json_output+=',"spendability":{'
            json_output+="\"total_outputs\":$total_outputs"

            # High-level breakdown
            spendable=$(sqlite3 "$DB_PATH" "
                SELECT COUNT(*)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE c.is_spendable = 1
                AND o.is_spent = 0;
            " 2>/dev/null || echo "0")
            unspendable=$(sqlite3 "$DB_PATH" "
                SELECT COUNT(*)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE c.is_spendable = 0
                AND o.is_spent = 0;
            " 2>/dev/null || echo "0")

            json_output+=',"breakdown":{'
            json_output+="\"spendable\":$spendable,"
            json_output+="\"unspendable\":$unspendable"
            json_output+='}'

            # Per-protocol breakdown
            protocol_breakdown=$(sqlite3 "$DB_PATH" "
                SELECT c.protocol,
                    SUM(CASE WHEN c.is_spendable = 1 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN c.is_spendable = 0 THEN 1 ELSE 0 END)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE o.is_spent = 0
                GROUP BY c.protocol;
            " 2>/dev/null)

            if [[ -n "$protocol_breakdown" ]]; then
                json_output+=',"by_protocol":{'

                first=true
                while IFS='|' read -r protocol spendable_count unspendable_count; do
                    if [[ -z "$protocol" ]]; then
                        continue
                    fi

                    if [[ "$first" == true ]]; then
                        first=false
                    else
                        json_output+=','
                    fi
                    json_output+="\"$protocol\":{\"spendable\":$spendable_count,\"unspendable\":$unspendable_count}"
                done <<< "$protocol_breakdown"

                json_output+='}'
            fi

            # Spendability reasons
            reasons=$(sqlite3 "$DB_PATH" "
                SELECT COALESCE(c.spendability_reason, 'NULL'), COUNT(*)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE o.is_spent = 0
                GROUP BY c.spendability_reason
                ORDER BY COUNT(*) DESC;
            " 2>/dev/null)

            if [[ -n "$reasons" ]]; then
                json_output+=',"reasons":{'

                first=true
                while IFS='|' read -r reason count; do
                    if [[ -z "$count" ]]; then
                        continue
                    fi

                    if [[ "$first" == true ]]; then
                        first=false
                    else
                        json_output+=','
                    fi
                    json_output+="\"$reason\":$count"
                done <<< "$reasons"

                json_output+='}'
            fi

            # Key composition totals
            key_totals=$(sqlite3 "$DB_PATH" "
                SELECT SUM(c.real_pubkey_count), SUM(c.burn_key_count), SUM(c.data_key_count)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE o.is_spent = 0;
            " 2>/dev/null)
            IFS='|' read -r total_real total_burn total_data <<< "$key_totals"

            json_output+=',"key_composition":{'
            json_output+="\"total_real_keys\":${total_real:-0},"
            json_output+="\"total_burn_keys\":${total_burn:-0},"
            json_output+="\"total_data_keys\":${total_data:-0}"
            json_output+='}'

            # Value by spendability (CRITICAL: Only count UTXO outputs, not spent ones!)
            value_data=$(sqlite3 "$DB_PATH" "
                SELECT
                    CASE
                        WHEN c.is_spendable = 1 THEN 'spendable'
                        WHEN c.is_spendable = 0 THEN 'unspendable'
                        ELSE 'not_evaluated'
                    END as category,
                    COUNT(*) as outputs,
                    SUM(o.amount) as total_sats,
                    PRINTF('%.8f', SUM(o.amount) / 100000000.0) as total_btc
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE o.script_type = 'multisig'
                AND o.is_spent = 0
                GROUP BY c.is_spendable
                ORDER BY SUM(o.amount) DESC;
            " 2>/dev/null)

            if [[ -n "$value_data" ]]; then
                json_output+=',"value_by_spendability":{'

                first=true
                while IFS='|' read -r category outputs total_sats total_btc; do
                    if [[ -z "$category" ]] || [[ -z "$outputs" ]]; then
                        continue
                    fi

                    if [[ "$first" == true ]]; then
                        first=false
                    else
                        json_output+=','
                    fi
                    json_output+="\"$category\":{\"outputs\":$outputs,\"satoshis\":$total_sats,\"btc\":\"$total_btc\"}"
                done <<< "$value_data"

                json_output+='}'
            fi

            json_output+='}'
        fi
    fi

    json_output+='}'

    echo "$json_output" | jq '.'
    exit 0
fi

# Human-readable output mode
echo "📊 Database Statistics for: $DB_PATH"
echo ""
echo "=== STAGE 1: P2MS Detection ==="
echo "(Note: Other script types are ingested for classification purposes only)"
echo ""

sqlite3 "$DB_PATH" <<EOF
.mode column
.headers off
SELECT 'Total P2MS outputs: ' || COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;
SELECT 'Coinbase outputs: ' || COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_coinbase = 1 AND is_spent = 0;
SELECT 'Regular outputs: ' || COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_coinbase = 0 AND is_spent = 0;
SELECT 'Height range: ' || MIN(height) || ' - ' || MAX(height) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;
SELECT 'Amount range: ' || MIN(amount) || ' - ' || MAX(amount) || ' sats' FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;
EOF

# Store total multisig count (for M-of-N analysis and verification)
# CRITICAL: Only count UTXO outputs (is_spent = 0), not spent outputs
total_multisig=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;")

# Show M-of-N multisig distribution (only if multisig outputs exist)
if [[ "$total_multisig" -gt 0 ]]; then
    echo ""
    echo "=== M-OF-N MULTISIG DISTRIBUTION (UTXO SET ONLY) ==="

    sqlite3 "$DB_PATH" <<'EOF'
.mode column
.headers on
.width 18 12 12
SELECT
    COALESCE(
        json_extract(metadata_json, '$.required_sigs') || '-of-' ||
        json_extract(metadata_json, '$.total_pubkeys'),
        'Unknown'
    ) as multisig_type,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0), 0), 2) || '%' as percentage
FROM transaction_outputs
WHERE script_type = 'multisig'
AND is_spent = 0
GROUP BY multisig_type
ORDER BY count DESC;
EOF

    # Verification (run actual query to detect SQL errors)
    breakdown_total=$(sqlite3 "$DB_PATH" "SELECT SUM(count) FROM (SELECT COUNT(*) as count FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0 GROUP BY COALESCE(json_extract(metadata_json, '\$.required_sigs') || '-of-' || json_extract(metadata_json, '\$.total_pubkeys'), 'Unknown'));")
    echo ""
    echo "Verification: M-of-N breakdown total = $breakdown_total, Expected = $total_multisig"
    if [[ "$breakdown_total" != "$total_multisig" ]]; then
        echo "⚠️  WARNING: M-of-N breakdown total doesn't match!"
    fi
fi

# Show nonstandard outputs (malformed P2MS that couldn't be parsed)
nonstandard_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_outputs WHERE script_type = 'nonstandard';")
if [[ "$nonstandard_count" -gt 0 ]]; then
    echo ""
    echo "=== NONSTANDARD/MALFORMED OUTPUTS ==="
    echo "Nonstandard outputs: $nonstandard_count"
    echo "Note: These are malformed P2MS scripts that Bitcoin Core couldn't parse"
    echo "      (e.g., invalid opcodes, truncated scripts, parsing errors)"
fi

# Check if Stage 2 tables exist and show stats
if table_exists "enriched_transactions"; then
    echo ""
    echo "=== STAGE 2: Transaction Enrichment ==="

    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers off
SELECT 'Enriched transactions: ' || COUNT(*) FROM enriched_transactions;
SELECT 'Transactions with burn patterns: ' || COUNT(DISTINCT txid) FROM burn_patterns;
SELECT 'Total burn patterns detected: ' || COALESCE((SELECT COUNT(*) FROM burn_patterns), 0);
SELECT 'Average fee per transaction: ' || PRINTF('%.2f', AVG(transaction_fee)) || ' sats' FROM enriched_transactions WHERE transaction_fee > 0;
SELECT 'Average fee per byte: ' || PRINTF('%.2f', AVG(fee_per_byte)) || ' sat/byte' FROM enriched_transactions WHERE fee_per_byte > 0;
EOF

    # Show Exodus outputs if they exist
    if table_exists "exodus_outputs"; then
        exodus_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM exodus_outputs;")
        if [[ "$exodus_count" -gt 0 ]]; then
            echo "Exodus outputs detected: $exodus_count (Omni Layer protocol marker)"
        fi
    fi

    # Show WikiLeaks outputs if they exist
    if table_exists "wikileaks_outputs"; then
        wikileaks_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM wikileaks_outputs;")
        if [[ "$wikileaks_count" -gt 0 ]]; then
            echo "WikiLeaks donation outputs: $wikileaks_count (historical significance)"
        fi
    fi
fi

# Check if Stage 3 tables exist and show stats
if table_exists "transaction_classifications"; then
    echo ""
    echo "=== STAGE 3: Protocol Classification ==="

    total_classified=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_classifications;")
    echo "Total classified transactions: $total_classified"
    echo ""
    echo "Classification breakdown:"

    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 25 12 12
SELECT
    protocol,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / $total_classified, 2) || '%' as percentage
FROM transaction_classifications
GROUP BY protocol
ORDER BY count DESC;
EOF

    # Verify breakdown totals match
    breakdown_total=$(sqlite3 "$DB_PATH" "SELECT SUM(count) FROM (SELECT COUNT(*) as count FROM transaction_classifications GROUP BY protocol);")
    echo ""
    echo "Verification: Breakdown total = $breakdown_total, Expected = $total_classified"
    if [[ "$breakdown_total" != "$total_classified" ]]; then
        echo "⚠️  WARNING: Protocol breakdown total doesn't match!"
    fi

    # Show variant breakdown for protocols with variants
    echo ""
    echo "Protocol variants (sorted by count):"

    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 25 30 10
SELECT
    protocol,
    COALESCE(variant, 'N/A') as variant,
    COUNT(*) as count
FROM transaction_classifications
WHERE variant IS NOT NULL
GROUP BY protocol, variant
ORDER BY COUNT(*) DESC, protocol;
EOF

    # Show variant totals
    variant_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_classifications WHERE variant IS NOT NULL;")
    no_variant_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_classifications WHERE variant IS NULL;")
    echo ""
    echo "Variant summary: $variant_count with variants, $no_variant_count without"

    # Highlight LikelyDataStorage details if present
    likely_data_storage_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM transaction_classifications WHERE protocol = 'LikelyDataStorage';")
    if [[ "$likely_data_storage_count" -gt 0 ]]; then
        echo ""
        echo "Likely Data Storage Variants:"

        sqlite3 "$DB_PATH" <<'EOF'
.mode column
.headers on
.width 28 12
SELECT
    COALESCE(variant, 'Unknown') as variant,
    COUNT(*) as count
FROM transaction_classifications
WHERE protocol = 'LikelyDataStorage'
GROUP BY variant
ORDER BY count DESC;
EOF
    fi

    # Show content type distribution
    echo ""
    echo "Content Type Distribution (MIME types):"

    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 40 12 12
SELECT
    COALESCE(content_type, 'NULL') as content_type,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / $total_classified, 2) || '%' as percentage
FROM transaction_classifications
GROUP BY content_type
ORDER BY count DESC;
EOF

    # Verify content type breakdown
    content_total=$(sqlite3 "$DB_PATH" "SELECT SUM(count) FROM (SELECT COUNT(*) as count FROM transaction_classifications GROUP BY content_type);")
    echo ""
    echo "Verification: Content type total = $content_total, Expected = $total_classified"
    if [[ "$content_total" != "$total_classified" ]]; then
        echo "⚠️  WARNING: Content type breakdown doesn't match!"
    fi

    # Get count of UTXO multisig outputs that have classifications (for per-protocol M-of-N analysis)
    classified_multisig_total=$(sqlite3 "$DB_PATH" "
        SELECT COUNT(*)
        FROM transaction_outputs to2
        JOIN transaction_classifications tc ON tc.txid = to2.txid
        WHERE to2.script_type = 'multisig'
        AND to2.is_spent = 0;
    " 2>/dev/null || echo "0")

    # Show M-of-N distribution by protocol (UTXO only - excludes spent outputs)
    # WARNING: This query is slow due to JSON extraction on 2.4M rows
    if [[ "${classified_multisig_total:-0}" -gt 0 ]]; then
        echo ""
        echo "M-of-N Distribution by Protocol (UTXO SET ONLY):"

        sqlite3 "$DB_PATH" <<'EOF'
.mode column
.headers on
.width 25 18 10 15
WITH protocol_totals AS (
    SELECT
        tc.protocol,
        COUNT(*) as total
    FROM transaction_classifications tc
    JOIN transaction_outputs to2 ON tc.txid = to2.txid
    WHERE to2.script_type = 'multisig'
    AND to2.is_spent = 0
    GROUP BY tc.protocol
)
SELECT
    tc.protocol,
    COALESCE(
        json_extract(to2.metadata_json, '$.required_sigs') || '-of-' ||
        json_extract(to2.metadata_json, '$.total_pubkeys'),
        'Unknown'
    ) as multisig_type,
    COUNT(*) as outputs,
    ROUND(COUNT(*) * 100.0 / NULLIF(pt.total, 0), 2) || '%' as pct_of_protocol
FROM transaction_classifications tc
JOIN transaction_outputs to2 ON tc.txid = to2.txid
JOIN protocol_totals pt ON pt.protocol = tc.protocol
WHERE to2.script_type = 'multisig'
AND to2.is_spent = 0
GROUP BY tc.protocol, multisig_type
ORDER BY tc.protocol, outputs DESC;
EOF

        # Verification: run actual query to detect SQL errors
        protocol_breakdown_sum=$(sqlite3 "$DB_PATH" "
            SELECT SUM(count) FROM (
                SELECT COUNT(*) as count
                FROM transaction_classifications tc
                JOIN transaction_outputs to2 ON tc.txid = to2.txid
                WHERE to2.script_type = 'multisig'
                AND to2.is_spent = 0
                GROUP BY tc.protocol,
                    COALESCE(
                        json_extract(to2.metadata_json, '\$.required_sigs') || '-of-' ||
                        json_extract(to2.metadata_json, '\$.total_pubkeys'),
                        'Unknown'
                    )
            );
        " 2>/dev/null)
        echo ""
        echo "Verification: Per-protocol sum = $protocol_breakdown_sum, Expected = $classified_multisig_total"
        if [[ "$protocol_breakdown_sum" != "$classified_multisig_total" ]]; then
            echo "⚠️  WARNING: Per-protocol breakdown sum doesn't match!"
        fi
    fi

    # Show P2MS output-level protocol classifications if table exists
    # CRITICAL: Only count UTXO outputs (is_spent = 0), not spent outputs
    if table_exists "p2ms_output_classifications"; then
        total_outputs=$(sqlite3 "$DB_PATH" "
            SELECT COUNT(*)
            FROM p2ms_output_classifications c
            JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
            WHERE o.is_spent = 0;
        ")

        if [[ "$total_outputs" -gt 0 ]]; then
            echo ""
            echo "=== P2MS OUTPUT-LEVEL PROTOCOL CLASSIFICATION ==="
            echo ""
            echo "Output-level Protocol Breakdown:"

            sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 25 12 12
SELECT
    c.protocol,
    COUNT(*) as outputs,
    ROUND(COUNT(*) * 100.0 / $total_outputs, 2) || '%' as percentage
FROM p2ms_output_classifications c
JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
WHERE o.is_spent = 0
GROUP BY c.protocol
ORDER BY outputs DESC;
EOF

            # Verify output-level protocol breakdown
            output_protocol_total=$(sqlite3 "$DB_PATH" "
                SELECT SUM(outputs) FROM (
                    SELECT COUNT(*) as outputs
                    FROM p2ms_output_classifications c
                    JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                    WHERE o.is_spent = 0
                    GROUP BY c.protocol
                );
            ")
            echo ""
            echo "Verification: Output-level protocol total = $output_protocol_total, Expected = $total_outputs"
            if [[ "$output_protocol_total" != "$total_outputs" ]]; then
                echo "⚠️  WARNING: Output-level protocol breakdown doesn't match!"
            fi

            # Show variant breakdown at output level for protocols with variants
            output_variant_count=$(sqlite3 "$DB_PATH" "
                SELECT COUNT(*)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE c.variant IS NOT NULL
                AND o.is_spent = 0;
            ")
            if [[ "$output_variant_count" -gt 0 ]]; then
                echo ""
                echo "Output-level Protocol Variants (sorted by count):"

                sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 25 30 10
SELECT
    c.protocol,
    COALESCE(c.variant, 'N/A') as variant,
    COUNT(*) as outputs
FROM p2ms_output_classifications c
JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
WHERE c.variant IS NOT NULL
AND o.is_spent = 0
GROUP BY c.protocol, c.variant
ORDER BY COUNT(*) DESC, c.protocol;
EOF
            fi

            echo ""
            echo "=== OUTPUT SPENDABILITY ANALYSIS ==="
            echo ""
            echo "High-level Spendability Breakdown:"

            sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 18 12 12
SELECT
    CASE c.is_spendable
        WHEN 1 THEN 'Spendable'
        WHEN 0 THEN 'Unspendable'
        ELSE 'Not Evaluated'
    END as spendability,
    COUNT(*) as outputs,
    ROUND(COUNT(*) * 100.0 / $total_outputs, 2) || '%' as percentage
FROM p2ms_output_classifications c
JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
WHERE o.is_spent = 0
GROUP BY c.is_spendable
ORDER BY c.is_spendable DESC NULLS LAST;
EOF

            # Verify spendability breakdown
            spend_total=$(sqlite3 "$DB_PATH" "
                SELECT SUM(outputs) FROM (
                    SELECT COUNT(*) as outputs
                    FROM p2ms_output_classifications c
                    JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                    WHERE o.is_spent = 0
                    GROUP BY c.is_spendable
                );
            ")
            echo ""
            echo "Verification: Spendability total = $spend_total, Expected = $total_outputs"
            if [[ "$spend_total" != "$total_outputs" ]]; then
                echo "⚠️  WARNING: Spendability breakdown doesn't match!"
            fi

            echo ""
            echo "Spendability by Protocol:"

            sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 25 12 12 12
SELECT
    c.protocol,
    SUM(CASE WHEN c.is_spendable = 1 THEN 1 ELSE 0 END) as spendable,
    SUM(CASE WHEN c.is_spendable = 0 THEN 1 ELSE 0 END) as unspendable,
    PRINTF('%.2f%%',
        SUM(CASE WHEN c.is_spendable = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)
    ) as spendable_pct
FROM p2ms_output_classifications c
JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
WHERE o.is_spent = 0
GROUP BY c.protocol
ORDER BY c.protocol;
EOF

            # Verify protocol spendability totals (sum the grouped breakdown)
            protocol_total=$(sqlite3 "$DB_PATH" "
                SELECT SUM(spendable + unspendable) FROM (
                    SELECT
                        SUM(CASE WHEN c.is_spendable = 1 THEN 1 ELSE 0 END) as spendable,
                        SUM(CASE WHEN c.is_spendable = 0 THEN 1 ELSE 0 END) as unspendable
                    FROM p2ms_output_classifications c
                    JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                    WHERE o.is_spent = 0
                    GROUP BY c.protocol
                );
            ")
            echo ""
            echo "Verification: Protocol breakdown sum = $protocol_total, Expected = $total_outputs"
            if [[ "$protocol_total" != "$total_outputs" ]]; then
                echo "⚠️  WARNING: Protocol spendability breakdown doesn't sum correctly!"
            fi

            echo ""
            echo "Spendability Reason Distribution:"

            sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 30 12 12
SELECT
    COALESCE(c.spendability_reason, 'NULL') as reason,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / $total_outputs, 2) || '%' as percentage
FROM p2ms_output_classifications c
JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
WHERE o.is_spent = 0
GROUP BY c.spendability_reason
ORDER BY count DESC;
EOF

            # Verify all outputs have reasons
            reason_total=$(sqlite3 "$DB_PATH" "
                SELECT SUM(count) FROM (
                    SELECT COUNT(*) as count
                    FROM p2ms_output_classifications c
                    JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                    WHERE o.is_spent = 0
                    GROUP BY c.spendability_reason
                );
            ")
            null_reasons=$(sqlite3 "$DB_PATH" "
                SELECT COUNT(*)
                FROM p2ms_output_classifications c
                JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
                WHERE c.spendability_reason IS NULL
                AND o.is_spent = 0;
            ")
            echo ""
            echo "Verification: Reason total = $reason_total, NULL reasons = $null_reasons"
            if [[ "$null_reasons" -gt 0 ]]; then
                echo "⚠️  WARNING: $null_reasons outputs missing spendability_reason!"
            fi

            echo ""
            echo "Key Composition Summary:"

            sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 15 12 12 12
SELECT
    'Total Keys' as metric,
    SUM(c.real_pubkey_count) as real_keys,
    SUM(c.burn_key_count) as burn_keys,
    SUM(c.data_key_count) as data_keys
FROM p2ms_output_classifications c
JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
WHERE o.is_spent = 0;

SELECT
    'Average/Output' as metric,
    PRINTF('%.2f', AVG(c.real_pubkey_count)) as real_keys,
    PRINTF('%.2f', AVG(c.burn_key_count)) as burn_keys,
    PRINTF('%.2f', AVG(c.data_key_count)) as data_keys
FROM p2ms_output_classifications c
JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
WHERE o.is_spent = 0;
EOF

            echo ""
            echo "Total Value by Spendability (UTXO SET ONLY - Excludes Spent Outputs):"

            sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
.width 18 12 18 18
SELECT
    CASE
        WHEN c.is_spendable = 1 THEN 'Spendable'
        WHEN c.is_spendable = 0 THEN 'Unspendable'
        ELSE 'Not Evaluated'
    END as category,
    COUNT(*) as outputs,
    PRINTF('%.8f', SUM(o.amount) / 100000000.0) as total_btc,
    PRINTF('%.2f%%', SUM(o.amount) * 100.0 / (SELECT SUM(amount) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0)) as pct_of_value
FROM p2ms_output_classifications c
JOIN transaction_outputs o ON c.txid = o.txid AND c.vout = o.vout
WHERE o.script_type = 'multisig'
AND o.is_spent = 0
GROUP BY c.is_spendable
ORDER BY SUM(o.amount) DESC;
EOF

            # Verify value breakdown totals (UTXO only)
            value_breakdown_total=$(sqlite3 "$DB_PATH" "SELECT SUM(amount) FROM transaction_outputs o JOIN p2ms_output_classifications c ON o.txid = c.txid AND o.vout = c.vout WHERE o.script_type = 'multisig' AND o.is_spent = 0;")
            p2ms_utxo_total=$(sqlite3 "$DB_PATH" "SELECT SUM(amount) FROM transaction_outputs WHERE script_type = 'multisig' AND is_spent = 0;")
            echo ""
            echo "Verification: Value breakdown total = $value_breakdown_total sats, P2MS UTXO outputs = $p2ms_utxo_total sats"
            if [[ "$value_breakdown_total" != "$p2ms_utxo_total" ]]; then
                echo "⚠️  WARNING: Not all P2MS UTXO outputs have spendability classifications!"
            fi
        fi
    fi
fi

echo ""
echo "✅ Statistics complete"
