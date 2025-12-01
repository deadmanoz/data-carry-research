# Test Organisation Guide

This document explains the organisation and usage of the comprehensive test suite for the Bitcoin P2MS Data-Carrying Protocol Analyser.

## Directory Structure

```
tests/
├── common/                          # Shared test utilities and infrastructure
│   ├── mod.rs                       # Core exports: TestDatabase, fixtures, database module
│   ├── fixture_registry.rs          # Centralised fixture metadata (59 fixtures across 8 protocols)
│   ├── protocol_test_base.rs        # ProtocolTestBuilder, JSON loaders, verification helpers
│   ├── db_seeding.rs                # FK-safe database seeding helpers
│   ├── analysis_test_setup.rs       # Analysis module test setup utilities
│   ├── assertion_helpers.rs         # Custom assertion macros and helpers
│   ├── rpc_helpers.rs               # Bitcoin Core RPC test utilities
│   └── test_output.rs               # Test output directory management
├── unit/                            # Component tests organised by stage
│   ├── analysis/                    # Analysis module tests
│   │   ├── content_type_consistency.rs
│   │   ├── data_size_stats.rs
│   │   ├── dust_analysis.rs
│   │   ├── multisig_config_stats.rs
│   │   ├── p2ms_output_count_analysis.rs
│   │   ├── stamps_weekly_fee_analysis.rs
│   │   ├── test_ec_diagnostic.rs
│   │   ├── test_validator_vs_direct.rs
│   │   └── tx_size_analysis.rs
│   ├── rpc/                         # Bitcoin Core RPC client tests
│   │   └── client.rs
│   ├── stage1/                      # Stage 1 P2MS extraction tests
│   │   ├── csv_processor.rs
│   │   └── schema_operations.rs
│   ├── stage2/                      # Transaction enrichment tests
│   │   └── database_operations.rs
│   └── stage3/                      # Protocol classification tests
│       ├── core.rs                  # Core classification infrastructure
│       ├── datastorage.rs           # DataStorage content detection tests
│       └── protocols/               # Individual protocol classifier tests
│           ├── ascii_identifier_protocols.rs
│           ├── chancecoin.rs
│           ├── counterparty.rs
│           ├── likely_legitimate.rs
│           ├── omni.rs
│           ├── opreturn_signalled.rs
│           ├── ppk.rs
│           ├── stamps.rs
│           └── wikileaks_cablegate.rs
├── integration/                     # End-to-end integration tests
│   ├── arc4_tool.rs                 # ARC4 encryption tool tests
│   ├── cli_smoke_test.rs            # CLI command smoke tests
│   ├── content_type_queries.rs      # Content type query tests
│   ├── ppk_decoder.rs               # PPk protocol decoder tests
│   ├── spendability_queries.rs      # Spendability analysis tests
│   ├── stage2_pipeline.rs           # Stage 2 pipeline integration
│   ├── stage3_pipeline.rs           # Stage 3 pipeline integration
│   └── unified_decoder.rs           # Unified decoder tests (68 tests, requires RPC)
├── test_data/                       # JSON fixtures and test datasets
│   ├── ascii_identifier_protocols/
│   ├── bitcoin_stamps/
│   ├── chancecoin/                  # 7 fixtures
│   ├── counterparty/                # 11 fixtures
│   ├── datastorage/                 # 7 fixtures
│   ├── likely_legitimate/           # 1 fixture (real multisig transactions)
│   ├── omni/                        # 16 fixtures (includes inputs/ subdirectory)
│   ├── opreturn_signalled/          # 3 fixtures
│   ├── ppk/                         # 5 fixtures
│   ├── stamps/                      # 9 fixtures
│   └── utxo_1m.csv                  # 1M record UTXO test dataset
└── lib.rs                           # Test library entry point
```

## Key Test Infrastructure

### Fixture Registry (`common/fixture_registry.rs`)

The fixture registry provides centralised metadata for all 59 protocol test fixtures:

```rust
use crate::common::fixture_registry::{stamps, counterparty, omni, ProtocolFixture};

// Access individual fixtures
let fixture = &stamps::SRC20_DEPLOY;
assert_eq!(fixture.protocol, ProtocolType::BitcoinStamps);
assert_eq!(fixture.variant, Some("StampsSRC20"));
assert_eq!(fixture.content_type, Some("application/json"));

// Iterate all fixtures for a protocol
for fixture in counterparty::all() {
    println!("{}: {}", fixture.txid, fixture.description);
}

// Get all fixtures across all protocols
let all = fixture_registry::all_fixtures();
assert_eq!(all.len(), 59);
```

**Available fixture modules**: `stamps`, `counterparty`, `omni`, `ppk`, `chancecoin`, `opreturn_signalled`, `likely_legitimate`, `datastorage`

### ProtocolTestBuilder (`common/protocol_test_base.rs`)

The unified test builder for fixture-based protocol tests:

```rust
use crate::common::fixture_registry::counterparty;
use crate::common::protocol_test_base::ProtocolTestBuilder;

#[tokio::test]
async fn test_counterparty_issuance() -> anyhow::Result<()> {
    ProtocolTestBuilder::from_fixture(&counterparty::MODERN_1OF3)
        .execute()
        .await?;
    Ok(())
}

// With options
ProtocolTestBuilder::from_fixture(&omni::USDT_GRANT_TOKENS)
    .with_all_outputs()     // Load ALL outputs (P2MS, OP_RETURN, P2PKH, etc.)
    .with_inputs()          // Load transaction inputs (for deobfuscation)
    .execute()
    .await?;

// Skip content type verification (for non-data-carrying protocols)
ProtocolTestBuilder::from_fixture(&likely_legitimate::MULTISIG_2OF3_CD27C9)
    .skip_content_type()
    .execute()
    .await?;
```

### Database Seeding (`common/db_seeding.rs`)

FK-safe seeding helpers that handle the correct insertion order:

```rust
use crate::common::db_seeding::{seed_enriched_transaction, build_and_seed_from_p2ms};
use crate::common::protocol_test_base::load_p2ms_outputs_from_json;

// Simple seeding (transaction with P2MS outputs)
seed_enriched_transaction(&mut test_db, &tx, inputs)?;

// Build and seed from fixture
let p2ms_outputs = load_p2ms_outputs_from_json(fixture.path, fixture.txid)?;
let tx = build_and_seed_from_p2ms(&mut test_db, txid, p2ms_outputs, input_txid)?;
```

**Critical**: Always use these helpers instead of direct database operations. They ensure:
1. Stage 1 outputs seeded first (`is_spent = 0`)
2. Stage 2 UPSERT preserves `is_spent` flags
3. Foreign key constraints satisfied

## Running Tests

### All Tests
```bash
cargo test
```

### By Category

**Note**: Tests in `tests/` are integration tests - don't use `--lib` flag. The `--lib` flag is only for unit tests embedded in `src/`.

```bash
# All tests in tests/
cargo test unit::                            # All tests in tests/unit/
cargo test integration::                     # All tests in tests/integration/

# All protocol classification tests
cargo test unit::stage3::protocols::

# Stage-specific tests
cargo test unit::stage1::
cargo test unit::stage2::
cargo test unit::stage3::

# Analysis module tests
cargo test unit::analysis::

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
cargo test unit::stage3::protocols::likely_legitimate::

# RPC client tests
cargo test unit::rpc::

# Database operations
cargo test unit::stage2::database_operations::

# Fixture registry validation
cargo test fixture_registry::
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
just stage3-test ppk                # PPk only
just stage3-test datastorage        # DataStorage only
just stage3-test core               # Core functionality
just stage3-test decoder            # Decoder tests (requires RPC)
just stage3-test decoder-verbose    # Decoder with debug logs
```

## Writing Tests

### When to Use Fixtures vs Synthetic Data

**Use fixtures (real blockchain data)** for:
- Primary protocol classification tests
- Testing production code paths
- Validating real-world transaction patterns
- Regression tests against known transactions

**Use synthetic data** for:
- **Negative tests** - Testing what should NOT match (e.g., PPk without marker)
- **Boundary tests** - Testing exact thresholds (e.g., ASCII percentage limits)
- **Position tests** - Testing pubkey positions (ASCII identifier protocols)
- **Edge cases** - Testing encoding/decoding edge cases
- **Bug-fix regression** - Ensuring old heuristics don't trigger
- **Helper function unit tests** - Testing utility functions in isolation

### Standard Protocol Test (Fixture-Based)

```rust
use crate::common::fixture_registry::counterparty;
use crate::common::protocol_test_base::ProtocolTestBuilder;

#[tokio::test]
#[serial]
async fn test_counterparty_issuance() -> anyhow::Result<()> {
    ProtocolTestBuilder::from_fixture(&counterparty::TYPE20_ISSUANCE)
        .execute()
        .await?;
    Ok(())
}
```

### Custom Verification Test

```rust
use crate::common::fixture_registry::likely_legitimate;
use crate::common::protocol_test_base::{
    setup_protocol_test, load_p2ms_outputs_from_json, run_stage3_processor,
    verify_classification, verify_output_spendability,
};
use crate::common::db_seeding::build_and_seed_from_p2ms;

#[tokio::test]
#[serial]
async fn test_with_custom_verification() -> anyhow::Result<()> {
    let fixture = &likely_legitimate::MULTISIG_2OF3_CD27C9;
    let (mut test_db, config) = setup_protocol_test("custom_verification")?;

    // Load and seed
    let p2ms_outputs = load_p2ms_outputs_from_json(fixture.path, fixture.txid)?;
    build_and_seed_from_p2ms(&mut test_db, fixture.txid, p2ms_outputs, "input_txid")?;

    // Run classification
    run_stage3_processor(test_db.path(), config).await?;

    // Standard verification
    verify_classification(&test_db, fixture.txid, ProtocolType::LikelyLegitimateMultisig, None)?;
    verify_output_spendability(&test_db, fixture.txid, ProtocolType::LikelyLegitimateMultisig)?;

    // Custom verification
    let conn = rusqlite::Connection::open(test_db.path())?;
    // ... custom queries ...

    Ok(())
}
```

### Synthetic Test (Negative/Boundary Testing)

```rust
use crate::common::protocol_test_base::{setup_protocol_test, seed_stage3_test_data};
use crate::common::fixtures;

#[tokio::test]
#[serial]
async fn test_ppk_no_marker_negative() -> anyhow::Result<()> {
    // This test uses SYNTHETIC data because we're testing what should NOT match
    let (mut test_db, config) = setup_protocol_test("ppk_no_marker")?;

    // Create synthetic transaction WITHOUT PPk marker
    let tx = fixtures::create_test_enriched_transaction("synthetic_txid");
    // ... customize transaction ...

    seed_enriched_transaction(&mut test_db, &tx, vec![])?;
    run_stage3_processor(test_db.path(), config).await?;

    // Verify it was NOT classified as PPk
    // ...

    Ok(())
}
```

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

## Test Categories

### Unit Tests (`unit/`)

Test individual components:

- **Analysis Tests** (`unit/analysis/`): Statistics, content type, spendability analysis
- **RPC Tests** (`unit/rpc/`): Bitcoin Core RPC client functionality
- **Stage 1 Tests** (`unit/stage1/`): P2MS extraction, schema operations
- **Stage 2 Tests** (`unit/stage2/`): Transaction enrichment, database operations
- **Stage 3 Tests** (`unit/stage3/`): Protocol classification
  - **Protocol Tests** (`unit/stage3/protocols/`): Individual protocol classifiers
  - **Core Tests** (`unit/stage3/core.rs`): Classification infrastructure
  - **DataStorage Tests** (`unit/stage3/datastorage.rs`): Content detection

### Integration Tests (`integration/`)

Test complete workflows:

- **Pipeline Tests**: Full Stage 1→2→3 processing
- **Decoder Tests**: Protocol-specific decoding (Stamps, Counterparty, Omni, PPk)
- **Query Tests**: Content type and spendability queries
- **CLI Tests**: Command-line interface smoke tests

## Best Practices

### Test Data Selection

| Scenario | Data Type | Rationale |
|----------|-----------|-----------|
| Primary classification | Fixture | Tests real blockchain data |
| Edge case encoding | Synthetic | Fixtures can't cover all variants |
| Negative verification | Synthetic | Need to test absence of patterns |
| Threshold boundaries | Synthetic | Need precise control over values |
| Bug-fix regression | Synthetic | Reproduce exact failing conditions |

### Test Naming
- Use descriptive names: `test_counterparty_issuance_classification`
- Include the scenario: `test_omni_multi_packet_decoding`
- Indicate expected outcome: `test_ppk_no_marker_negative`

### Database Testing
- Always use `TestDatabase` for automatic cleanup
- Use unique test names to avoid conflicts
- Use FK-safe seeding helpers (`seed_enriched_transaction`, `build_and_seed_from_p2ms`)
- Never bypass the seeding helpers with direct database operations

### Content Type Testing
- Verify content types for data-carrying protocols
- Use `.skip_content_type()` for non-data-carrying protocols (e.g., `LikelyLegitimateMultisig`)

## Adding New Tests

### For New Protocols

1. **Create fixture file**: Add JSON to `tests/test_data/<protocol>/`
2. **Register fixture**: Add entry to `tests/common/fixture_registry.rs`
3. **Create test file**: `tests/unit/stage3/protocols/<protocol>.rs`
4. **Update module**: Add to `tests/unit/stage3/protocols/mod.rs`
5. **Add justfile command**: `stage3-test-<protocol>`

### For New Fixtures

1. Fetch transaction JSON from Bitcoin Core RPC
2. Add to appropriate `tests/test_data/<protocol>/` directory
3. Create `ProtocolFixture` entry in `fixture_registry.rs`
4. Update fixture count in `fixture_count_matches_expected()` test
5. Write test using `ProtocolTestBuilder::from_fixture()`

## Debugging Tests

### Running Individual Tests
```bash
# Run specific test function
cargo test test_function_name -- --nocapture

# Run with debug output
RUST_LOG=debug cargo test test_name -- --nocapture

# Run specific protocol test
cargo test unit::stage3::protocols::counterparty::test_name -- --nocapture
```

### Test Database Inspection
```bash
# View test database (before cleanup)
sqlite3 test_output/unit_tests/test_name_*.db ".schema"
sqlite3 test_output/unit_tests/test_name_*.db "SELECT * FROM table_name;"
```

### Fixture Validation
```bash
# Verify all fixture paths exist
cargo test fixture_registry::tests::all_fixture_paths_exist

# Check fixture counts
cargo test fixture_registry::tests::fixture_count_matches_expected
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
1. Update fixture registry if fixture format changes
2. Update `ProtocolTestBuilder` if test patterns change
3. Run full test suite to check for breakage
4. Update this documentation if structure changes

## Test Data Sources

- **Real Transactions**: JSON fixtures contain actual Bitcoin mainnet transaction data
- **Synthetic Data**: Fixture factories create realistic but artificial test data for edge cases
- **Production Database**: Real classified transactions can be used for fixture creation

All real transaction data is sourced from Bitcoin Core RPC and represents authentic protocol usage.
