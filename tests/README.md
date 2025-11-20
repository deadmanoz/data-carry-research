# Test Organisation Guide

This document explains the organisation and usage of the comprehensive test suite for the Bitcoin P2MS Data-Carrying Protocol Analyser.

## Directory Structure

```
tests/
├── common/                    # Shared test utilities and fixtures
│   ├── mod.rs                 # Core fixtures, TestDatabase, JSON loaders
│   └── protocol_test_base.rs  # Standardised protocol test utilities
├── unit/                      # Unit tests organised by component
│   ├── analysis/              # Analysis module tests
│   ├── rpc/                   # Bitcoin Core RPC client tests
│   ├── stage1/                # Stage 1 P2MS extraction tests
│   ├── stage2/                # Transaction enrichment and database tests
│   │   └── database_operations.rs
│   └── stage3/                # Protocol classification tests
│       ├── core.rs            # Core classification infrastructure
│       ├── datastorage.rs     # Data Storage protocol tests
│       └── protocols/         # Individual protocol classifiers
│           ├── ascii_identifier_protocols.rs
│           ├── chancecoin.rs
│           ├── counterparty.rs
│           ├── likely_legitimate.rs
│           ├── omni.rs
│           ├── opreturn_signalled.rs
│           └── stamps.rs
├── integration/               # End-to-end integration tests
│   ├── arc4_tool.rs           # ARC4 tool tests
│   ├── cli_smoke_test.rs      # CLI command smoke tests
│   ├── content_type_queries.rs # Content type query tests
│   ├── spendability_queries.rs # Spendability analysis tests
│   ├── stage2_pipeline.rs     # Stage 2 pipeline integration
│   ├── stage3_pipeline.rs     # Stage 3 pipeline integration
│   └── unified_decoder.rs     # Unified decoder tests (68 tests, requires RPC)
├── test_data/                 # JSON fixtures and test datasets
│   ├── ascii_identifier_protocols/
│   ├── bitcoin_stamps/
│   ├── chancecoin/
│   ├── counterparty/
│   ├── datastorage/
│   ├── omni/
│   ├── opreturn_signalled/
│   ├── stamps/
│   └── utxo_1m.csv            # 1M record UTXO test dataset
└── lib.rs                     # Test library entry point
```

## Running Tests

### All Tests
```bash
cargo test
```

### By Category

**Note**: Tests in `tests/` are integration tests - don't use `--lib` flag. The `--lib` flag is only for unit tests embedded in `src/`.

```bash
# All integration tests in tests/
cargo test unit::                            # All tests in tests/unit/
cargo test integration::                     # All tests in tests/integration/

# All protocol classification tests
cargo test unit::stage3::protocols::

# Stage-specific tests
cargo test unit::stage1::
cargo test unit::stage2::
cargo test unit::stage3::

# Unit tests in src/ (use --lib flag)
cargo test processor::stage3::signature_detection --lib
cargo test crypto::arc4 --lib
```

### Specific Components
```bash
# Specific protocol tests (note trailing ::)
cargo test unit::stage3::protocols::counterparty::
cargo test unit::stage3::protocols::omni::
cargo test unit::stage3::protocols::stamps::

# RPC client tests
cargo test unit::rpc::

# Database operations
cargo test unit::stage2::database_operations::
```

### Using Justfile Commands
The project includes convenient `justfile` commands for common test scenarios:

```bash
# Comprehensive test suites
just test                # All cargo tests
just test-all            # Comprehensive suite (unit + integration + E2E)

# Protocol-specific tests (umbrella command: just stage3-test <subcommand>)
just stage3-test all                # All Stage 3 tests
just stage3-test counterparty       # Counterparty only
just stage3-test stamps             # Bitcoin Stamps only
just stage3-test omni               # Omni Layer only
just stage3-test chancecoin         # Chancecoin only
just stage3-test datastorage        # DataStorage only
just stage3-test core               # Core functionality
just stage3-test decoder            # Decoder tests (requires RPC)
just stage3-test decoder-verbose    # Decoder with debug logs
```

## Writing Tests

### Database Testing

Use the `TestDatabase` wrapper for automatic cleanup:

```rust
use crate::common::protocol_test_base::setup_protocol_test;

#[tokio::test]
async fn test_my_protocol_feature() -> anyhow::Result<()> {
    let (mut test_db, config) = setup_protocol_test("my_test")?;

    // Use test_db.database() for read operations
    let stats = test_db.database().get_database_stats()?;

    // Use test_db.database_mut() for write operations
    test_db.database_mut().insert_data(&data)?;

    // Database automatically cleaned up on drop
    Ok(())
}
```

### Test Data Creation (Enhanced)

Use the centralised fixture factories:

```rust
use crate::common::fixtures;

#[test]
fn test_protocol_classification() {
    // Use realistic protocol-specific data
    let counterparty_tx = fixtures::counterparty_issuance_tx();
    let omni_tx = fixtures::omni_usdt_send_tx();
    let stamps_tx = fixtures::stamps_src20_deploy();

    // Use burn patterns
    let stamps_burns = fixtures::stamps_burn_patterns();
    let counterparty_burns = fixtures::counterparty_burn_patterns();

    // Use minimal data for simple tests
    let minimal_tx = fixtures::create_test_enriched_transaction("test_txid", 800000);
}
```

### JSON Fixtures

Load test data from JSON files with error handling:

```rust
use crate::common::protocol_test_base::load_p2ms_outputs_from_json;

#[tokio::test]
async fn test_real_transaction_data() -> anyhow::Result<()> {
    // Load P2MS outputs from JSON (with error handling)
    let p2ms_outputs = load_p2ms_outputs_from_json(
        "tests/test_data/counterparty/example_tx.json",
        "transaction_id_here"
    )?;

    // Test gracefully skips if fixture is missing
    if p2ms_outputs.is_empty() {
        println!("⚠️  Skipping test - fixture not found");
        return Ok(());
    }

    Ok(())
}
```

### Protocol Test Structure

New protocol tests should follow established patterns. See existing protocol tests for reference:
- `tests/unit/stage3/protocols/counterparty.rs` - Comprehensive example with message types
- `tests/unit/stage3/protocols/stamps.rs` - Variant classification patterns
- `tests/unit/stage3/protocols/omni.rs` - Multi-packet decoding patterns

Use `setup_protocol_test()` for standardised initialisation and `verify_classification()` for assertions.

## Test Categories

### Unit Tests (`unit/`)

Test individual components in isolation:

- **RPC Tests** (`unit/rpc/`): Bitcoin Core RPC client functionality
- **Stage 2 Tests** (`unit/stage2/`): Transaction enrichment and database operations
- **Stage 3 Tests** (`unit/stage3/`): Protocol classification logic
  - **Protocol Tests** (`unit/stage3/protocols/`): Individual protocol classifiers
  - **Core Tests** (`unit/stage3/core.rs`): Core classification infrastructure

### Integration Tests (`integration/`)

Test complete workflows:

- **Pipeline Tests**: Full Stage 1→2→3 processing
- **RPC Integration**: End-to-end Bitcoin Core connectivity
- **Database Migration**: Schema evolution testing

## Best Practices

### Test Naming
- Use descriptive names: `test_counterparty_issuance_classification`
- Include the scenario: `test_omni_multi_packet_decoding`
- Indicate expected outcome: `test_stamps_burn_pattern_detection_succeeds`

### Test Data
- Use realistic transaction data from `fixtures::` functions
- Load real Bitcoin transaction data via JSON fixtures
- Use minimal test data only for simple unit tests
- Never hardcode transaction IDs in test logic

### Database Testing
- Always use `TestDatabase` for automatic cleanup
- Use unique test names to avoid conflicts
- Test both success and failure scenarios
- Verify database state after operations

### Error Testing
- Test error conditions explicitly
- Use `#[should_panic]` sparingly - prefer `Result` assertion
- Test edge cases and boundary conditions
- Include regression tests for fixed bugs

## Adding New Tests

### For New Protocols
1. Create test file: `tests/unit/stage3/protocols/my_protocol.rs`
2. Add to module: Update `tests/unit/stage3/protocols/mod.rs`
3. Add justfile command: `stage3-test-my-protocol`
4. Create fixtures: Add realistic test data to `fixtures::`
5. Add JSON data: Create `tests/test_data/my_protocol/` directory

### For New Features
1. Choose appropriate location based on component
2. Use `TestDatabase` for database operations
3. Use existing fixtures or create new ones
4. Follow naming conventions
5. Add justfile command if needed

## Debugging Tests

### Running Individual Tests
```bash
# Run specific test function
cargo test test_function_name -- --nocapture

# Run with debug output
RUST_LOG=debug cargo test test_name -- --nocapture

# Run specific protocol test
cargo test unit::stage3::protocols::counterparty::<test_name> -- --nocapture
```

### Test Database Inspection
```bash
# View test database (before cleanup)
sqlite3 test_output/unit_tests/test_name_*.db ".schema"
sqlite3 test_output/unit_tests/test_name_*.db "SELECT * FROM table_name;"
```

### Available Fixtures
```rust
// List available JSON fixtures
let fixtures = json_fixtures::list_fixtures(Some("counterparty"))?;
println!("Available fixtures: {:?}", fixtures);
```

## Maintenance

### Cleaning Up
```bash
# Remove test artifacts
just clean

# Remove specific test databases
rm -f test_output/unit_tests/*.db
```

### Updating Tests
When modifying types or APIs:
1. Update fixture factories in `tests/common/mod.rs`
2. Update protocol-specific test data
3. Run full test suite to check for breakage
4. Update this documentation if structure changes

## Test Data Sources

- **Real Transactions**: JSON fixtures contain actual Bitcoin mainnet transaction data
- **Synthetic Data**: Fixture factories create realistic but artificial test data
- **Minimal Data**: Basic test data for simple unit tests

All real transaction data is sourced from Bitcoin Core RPC and represents authentic protocol usage.
