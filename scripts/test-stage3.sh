#!/usr/bin/env bash
set -euo pipefail

# Stage 3 test dispatcher
# Routes test commands to appropriate Cargo test modules
#
# Usage: ./scripts/test-stage3.sh <COMMAND> [OPTIONS...]
#
# Commands:
#   all              - Run all Stage 3 tests
#   counterparty     - Counterparty protocol tests
#   stamps           - Bitcoin Stamps protocol tests
#   omni             - Omni Layer protocol tests
#   chancecoin       - Chancecoin protocol tests
#   datastorage      - DataStorage protocol tests
#   core             - Stage 3 core functionality tests
#   decoder          - Unified decoder tests (requires RPC)
#   decoder-verbose  - Decoder tests with verbose output
#
# Examples:
#   ./scripts/test-stage3.sh all                    # All Stage 3 tests
#   ./scripts/test-stage3.sh stamps                 # Bitcoin Stamps only
#   ./scripts/test-stage3.sh decoder                # Decoder tests
#   ./scripts/test-stage3.sh decoder-verbose        # Decoder with debug logs

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <COMMAND> [OPTIONS...]"
    echo ""
    echo "Commands: all, counterparty, stamps, omni, chancecoin,"
    echo "          datastorage, core, decoder, decoder-verbose"
    echo ""
    echo "Examples:"
    echo "  $0 all               # All Stage 3 tests"
    echo "  $0 stamps            # Bitcoin Stamps only"
    echo "  $0 decoder           # Decoder tests (requires RPC)"
    exit 1
fi

COMMAND="$1"
shift

case "$COMMAND" in
    all)
        cargo test unit::stage3:: -- --nocapture "$@"
        ;;
    counterparty)
        cargo test unit::stage3::protocols::counterparty:: -- --nocapture "$@"
        ;;
    stamps)
        cargo test unit::stage3::protocols::stamps:: -- --nocapture "$@"
        ;;
    omni)
        cargo test unit::stage3::protocols::omni:: -- --nocapture "$@"
        ;;
    chancecoin)
        cargo test unit::stage3::protocols::chancecoin:: -- --nocapture "$@"
        ;;
    datastorage)
        cargo test unit::stage3::datastorage:: -- --nocapture "$@"
        ;;
    core)
        cargo test unit::stage3::core:: -- --nocapture "$@"
        ;;
    decoder)
        cargo test integration::unified_decoder:: -- --nocapture "$@"
        ;;
    decoder-verbose)
        RUST_LOG=debug cargo test integration::unified_decoder:: -- --nocapture "$@"
        ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Valid commands: all, counterparty, stamps, omni, chancecoin, datastorage, core, decoder, decoder-verbose"
        exit 1
        ;;
esac
