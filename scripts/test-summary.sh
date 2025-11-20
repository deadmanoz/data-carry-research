#!/usr/bin/env bash
# Test Summary Parser
# Parses test output files and generates formatted summary

set -euo pipefail

# ANSI colour codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

# Function to parse cargo test output
parse_test_output() {
    local file="$1"
    local total=0
    local passed=0
    local failed=0
    local duration="N/A"

    if [ -f "$file" ]; then
        # Extract test results (format: "test result: ok. X passed; Y failed; ...")
        if grep -q "test result:" "$file"; then
            passed=$(grep "test result:" "$file" | tail -1 | sed -n 's/.*\([0-9]\+\) passed.*/\1/p')
            failed=$(grep "test result:" "$file" | tail -1 | sed -n 's/.*\([0-9]\+\) failed.*/\1/p')
            total=$((passed + failed))

            # Extract duration from "Finished ... in X.XXs"
            if grep -q "Finished.*in" "$file"; then
                duration=$(grep "Finished.*in" "$file" | tail -1 | sed -n 's/.*in \([0-9.]\+s\).*/\1/p')
            fi
        fi
    fi

    echo "$total:$passed:$failed:$duration"
}

# Function to check if command succeeded
check_success() {
    local file="$1"
    if [ -f "$file" ]; then
        if grep -q "test result: ok" "$file"; then
            echo "SUCCESS"
        elif grep -q "test result: FAILED" "$file"; then
            echo "FAILED"
        else
            echo "UNKNOWN"
        fi
    else
        echo "SKIPPED"
    fi
}

# Function to extract failed tests
extract_failures() {
    local file="$1"
    if [ -f "$file" ]; then
        grep "^test.*FAILED$" "$file" | sed 's/test \(.*\) \.\.\. FAILED/   • \1/' || true
    fi
}

# Parse all test outputs
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 COMPREHENSIVE TEST SUITE SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Unit Tests
unit_result=$(parse_test_output "/tmp/unit_test_output.txt")
unit_total=$(echo "$unit_result" | cut -d: -f1)
unit_passed=$(echo "$unit_result" | cut -d: -f2)
unit_failed=$(echo "$unit_result" | cut -d: -f3)
unit_duration=$(echo "$unit_result" | cut -d: -f4)

echo "🧪 UNIT TESTS"
if [ "$unit_failed" -gt 0 ]; then
    echo -e "   ${RED}❌ $unit_failed failed${NC}"
fi
echo -e "   ${GREEN}✅ $unit_passed passed${NC}"
echo "   ⏱️  $unit_duration"
echo ""

# Integration Tests (Non-RPC)
integration_result=$(parse_test_output "/tmp/integration_test_output.txt")
integration_total=$(echo "$integration_result" | cut -d: -f1)
integration_passed=$(echo "$integration_result" | cut -d: -f2)
integration_failed=$(echo "$integration_result" | cut -d: -f3)
integration_duration=$(echo "$integration_result" | cut -d: -f4)

echo "🔗 INTEGRATION TESTS (Non-RPC)"
if [ "$integration_failed" -gt 0 ]; then
    echo -e "   ${RED}❌ $integration_failed failed${NC}"
fi
echo -e "   ${GREEN}✅ $integration_passed passed${NC}"
echo "   ⏱️  $integration_duration"
echo ""

# RPC Connectivity
rpc_available=false
if [ -f "/tmp/rpc_check_output.txt" ]; then
    if grep -q "successfully" "/tmp/rpc_check_output.txt"; then
        rpc_available=true
        echo -e "🔌 RPC CONNECTIVITY: ${GREEN}✅ AVAILABLE${NC}"
    else
        echo -e "🔌 RPC CONNECTIVITY: ${YELLOW}⚠️  UNAVAILABLE${NC}"
    fi
else
    echo "🔌 RPC CONNECTIVITY: ⚠️  NOT CHECKED"
fi
echo ""

# RPC-Dependent Tests
echo "🔓 RPC-DEPENDENT TESTS"

if [ "$rpc_available" = true ]; then
    # Decoder Tests
    decoder_result=$(parse_test_output "/tmp/decoder_test_output.txt")
    decoder_passed=$(echo "$decoder_result" | cut -d: -f2)
    decoder_failed=$(echo "$decoder_result" | cut -d: -f3)
    decoder_status=$(check_success "/tmp/decoder_test_output.txt")

    if [ "$decoder_status" = "SUCCESS" ]; then
        echo -e "   📡 Decoder Tests: ${GREEN}✅ $decoder_passed passed${NC}"
    elif [ "$decoder_status" = "FAILED" ]; then
        echo -e "   📡 Decoder Tests: ${RED}❌ $decoder_failed failed${NC}"
    fi

    # Stage 2 Pipeline
    stage2_result=$(parse_test_output "/tmp/stage2_pipeline_output.txt")
    stage2_passed=$(echo "$stage2_result" | cut -d: -f2)
    stage2_failed=$(echo "$stage2_result" | cut -d: -f3)
    stage2_status=$(check_success "/tmp/stage2_pipeline_output.txt")

    if [ "$stage2_status" = "SUCCESS" ]; then
        echo -e "   🔧 Stage 2 Pipeline: ${GREEN}✅ $stage2_passed passed${NC}"
    elif [ "$stage2_status" = "FAILED" ]; then
        echo -e "   🔧 Stage 2 Pipeline: ${RED}❌ $stage2_failed failed${NC}"
    fi

    # ARC4 Tool
    arc4_result=$(parse_test_output "/tmp/arc4_test_output.txt")
    arc4_passed=$(echo "$arc4_result" | cut -d: -f2)
    arc4_failed=$(echo "$arc4_result" | cut -d: -f3)
    arc4_status=$(check_success "/tmp/arc4_test_output.txt")

    if [ "$arc4_status" = "SUCCESS" ]; then
        echo -e "   🔧 ARC4 Tool: ${GREEN}✅ $arc4_passed passed${NC}"
    elif [ "$arc4_status" = "FAILED" ]; then
        echo -e "   🔧 ARC4 Tool: ${RED}❌ $arc4_failed failed${NC}"
    fi
else
    echo -e "   ${YELLOW}⚠️  All RPC-dependent tests SKIPPED (Bitcoin Core not available)${NC}"
    echo "   📡 Decoder Tests: ~68 tests"
    echo "   🔧 Stage 2 Pipeline: ~15 tests"
    echo "   🔧 ARC4 Tool: ~4 tests"
fi
echo ""

# E2E Pipeline Tests
echo "🚀 E2E PIPELINE TESTS"

if [ -f "/tmp/stage1_output.txt" ]; then
    stage1_status=$(grep -q "Test complete" "/tmp/stage1_output.txt" && echo "SUCCESS" || echo "FAILED")
    if [ "$stage1_status" = "SUCCESS" ]; then
        echo -e "   📄 Stage 1 (Small): ${GREEN}✅ SUCCESS${NC}"
    else
        echo -e "   📄 Stage 1 (Small): ${RED}❌ FAILED${NC}"
    fi
else
    echo "   📄 Stage 1 (Small): ⚠️  NOT RUN"
fi

if [ -f "/tmp/stage2_output.txt" ]; then
    stage2_e2e_status=$(grep -q "Stage 2 complete" "/tmp/stage2_output.txt" && echo "SUCCESS" || echo "FAILED")
    if [ "$stage2_e2e_status" = "SUCCESS" ]; then
        echo -e "   💰 Stage 2 (Small): ${GREEN}✅ SUCCESS${NC}"
    else
        echo -e "   💰 Stage 2 (Small): ${RED}❌ FAILED${NC}"
    fi
else
    if [ "$rpc_available" = false ]; then
        echo -e "   💰 Stage 2 (Small): ${YELLOW}⚠️  SKIPPED (RPC unavailable)${NC}"
    else
        echo "   💰 Stage 2 (Small): ⚠️  NOT RUN"
    fi
fi

if [ -f "/tmp/stage3_output.txt" ]; then
    stage3_status=$(grep -q "Stage 3 complete" "/tmp/stage3_output.txt" && echo "SUCCESS" || echo "FAILED")
    if [ "$stage3_status" = "SUCCESS" ]; then
        echo -e "   🏷️  Stage 3 (Small): ${GREEN}✅ SUCCESS${NC}"
    else
        echo -e "   🏷️  Stage 3 (Small): ${RED}❌ FAILED${NC}"
    fi
else
    if [ "$rpc_available" = false ]; then
        echo -e "   🏷️  Stage 3 (Small): ${YELLOW}⚠️  SKIPPED (RPC unavailable)${NC}"
    else
        echo "   🏷️  Stage 3 (Small): ⚠️  NOT RUN"
    fi
fi
echo ""

# Overall Result
total_failed=$((unit_failed + integration_failed))
if [ "$rpc_available" = true ]; then
    total_failed=$((total_failed + decoder_failed + stage2_failed + arc4_failed))
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$total_failed" -eq 0 ]; then
    if [ "$rpc_available" = true ]; then
        echo -e "${GREEN}OVERALL RESULT: ✅ ALL TESTS PASSED${NC}"
    else
        echo -e "${YELLOW}OVERALL RESULT: ⚠️  PARTIAL SUCCESS (RPC unavailable - 87 tests skipped)${NC}"
    fi
else
    echo -e "${RED}OVERALL RESULT: ❌ $total_failed TEST(S) FAILED${NC}"
fi

# Calculate total duration
total_duration=0
for dur in "$unit_duration" "$integration_duration"; do
    if [ "$dur" != "N/A" ]; then
        # Extract numeric part
        num=$(echo "$dur" | sed 's/s//')
        total_duration=$(echo "$total_duration + $num" | bc)
    fi
done

if [ "$total_duration" != "0" ]; then
    echo "Total Test Duration: ${total_duration}s"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Show failed tests if any
if [ "$total_failed" -gt 0 ]; then
    echo ""
    echo -e "${RED}❌ FAILED TESTS:${NC}"
    extract_failures "/tmp/unit_test_output.txt"
    extract_failures "/tmp/integration_test_output.txt"
    if [ "$rpc_available" = true ]; then
        extract_failures "/tmp/decoder_test_output.txt"
        extract_failures "/tmp/stage2_pipeline_output.txt"
        extract_failures "/tmp/arc4_test_output.txt"
    fi
    echo ""
fi
