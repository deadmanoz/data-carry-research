#!/usr/bin/env bash
# Comprehensive Test Suite Runner
# Runs all tests (unit, integration, E2E) with intelligent RPC detection

set -euo pipefail

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧪 COMPREHENSIVE P2MS ANALYSER TEST SUITE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "This will run:"
echo "  • Unit tests (~140 tests)"
echo "  • Integration tests (non-RPC)"
echo "  • RPC-dependent tests (if Bitcoin Core available)"
echo "  • E2E pipeline tests (Stage 1→2→3)"
echo ""
echo "Estimated time: 5-15 minutes (depending on RPC availability)"
echo ""

# ============================================================================
# Step 1: Unit Tests
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 UNIT TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cargo test unit:: 2>&1 | tee /tmp/unit_test_output.txt

# ============================================================================
# Step 2: Integration Tests (Non-RPC)
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔗 INTEGRATION TESTS (Non-RPC)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
{
    cargo test integration::stage3_pipeline
    cargo test integration::content_type_queries
    cargo test integration::spendability_queries
} 2>&1 | tee /tmp/integration_test_output.txt

# ============================================================================
# Step 3: Check Bitcoin Core RPC Availability
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔌 RPC CONNECTIVITY CHECK"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cargo run -- test-rpc 2>&1 | tee /tmp/rpc_check_output.txt
RPC_EXIT_CODE=$?

# ============================================================================
# Step 4: RPC-Dependent Tests (Conditional)
# ============================================================================
if [ $RPC_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔓 RPC-DEPENDENT TESTS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    echo ""
    echo "📡 Unified Decoder Tests (68 tests)..."
    cargo test integration::unified_decoder 2>&1 | tee /tmp/decoder_test_output.txt

    echo ""
    echo "🔧 Stage 2 Pipeline Integration Tests..."
    cargo test integration::stage2_pipeline 2>&1 | tee /tmp/stage2_pipeline_output.txt

    echo ""
    echo "🔧 ARC4 Tool Integration Tests..."
    cargo test integration::arc4_tool 2>&1 | tee /tmp/arc4_test_output.txt
else
    echo ""
    echo "⚠️  Skipping RPC-dependent tests (Bitcoin Core not available)"
    echo "   - integration::unified_decoder:: (68 tests)"
    echo "   - integration::stage2_pipeline:: (15 tests)"
    echo "   - integration::arc4_tool:: (4 tests)"
    echo ""
    echo "To enable these tests:"
    echo "   1. Start Bitcoin Core with -rpcconnect=localhost"
    echo "   2. Ensure credentials in config.toml (bitcoin:bitcoin)"
fi

# ============================================================================
# Step 5: E2E Stage Pipeline Tests
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 E2E STAGE PIPELINE TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "📄 Stage 1: P2MS Extraction (Small Dataset - 1M records)..."
just stage1-small 2>&1 | tee /tmp/stage1_output.txt
STAGE1_EXIT_CODE=$?

if [ $RPC_EXIT_CODE -eq 0 ] && [ $STAGE1_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "💰 Stage 2: Transaction Enrichment (requires RPC)..."
    just stage2-small 2>&1 | tee /tmp/stage2_output.txt
    STAGE2_EXIT_CODE=$?

    if [ $STAGE2_EXIT_CODE -eq 0 ]; then
        echo ""
        echo "🏷️  Stage 3: Protocol Classification..."
        just stage3-small 2>&1 | tee /tmp/stage3_output.txt
    fi
else
    if [ $RPC_EXIT_CODE -ne 0 ]; then
        echo "⚠️  Skipping Stage 2 and Stage 3 (Bitcoin Core RPC not available)"
    else
        echo "❌ Skipping Stage 2 and Stage 3 (Stage 1 failed)"
    fi
fi

# ============================================================================
# Step 6: Generate Summary Report
# ============================================================================
echo ""
./scripts/test-summary.sh

# ============================================================================
# Cleanup
# ============================================================================
echo ""
echo "🧹 Cleaning up test artifacts..."
just clean
rm -f /tmp/*test_output.txt /tmp/*pipeline_output.txt /tmp/rpc_check_output.txt 2>/dev/null || true
echo "✅ Cleanup complete"
