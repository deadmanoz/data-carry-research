# Research: Analyse Value Command Architecture & Variant-Level Breakdown

## Executive Summary

The `analyse value` command provides comprehensive value distribution analysis across Bitcoin P2MS protocols. The research reveals a mature architecture with reusable patterns (particularly from `stamps_variant_temporal`) that can be adapted for variant-level value breakdown. The implementation uses a clean separation between analysis logic, type definitions, and report formatting.

---

## 1. CLI Command Structure

### Entry Point: `src/cli/commands/analysis.rs`

**Command Definition** (lines 139-147):
```rust
Value {
    /// Database path (overrides config.toml)
    #[arg(long)]
    database_path: Option<PathBuf>,

    /// Output format (console or json)
    #[arg(long, default_value = "console")]
    format: String,
},
```

**Command Wiring** (lines 488-497):
```rust
AnalysisCommands::Value {
    database_path,
    format,
} => run_simple_analysis(
    database_path,
    format,
    &app_config,
    |e| e.analyse_value(),                    // 1. Analysis execution
    ReportFormatter::format_value_analysis,   // 2. Output formatting
),
```

**Key Pattern**: Uses generic `run_simple_analysis<T, F, G>()` helper (lines 45-63):
- Accepts analysis function `F: FnOnce(&AnalysisEngine) -> AppResult<T>`
- Accepts format function `G: FnOnce(&T, &OutputFormat) -> AppResult<String>`
- Handles database resolution, analysis execution, and output routing
- Supports console and JSON output formats

**Output Handling** (lines 87-95):
- Console: printed to stdout
- JSON/Plotly: auto-written to `./output_data/plots/` if no `--output` specified
- Can override with explicit `--output` path using `run_analysis_with_file_output()`

---

## 2. Type Definitions

### Location: `src/types/analysis_results/value.rs`

#### Core Types

**1. `ValueAnalysisReport`** (lines 9-14):
```rust
pub struct ValueAnalysisReport {
    pub protocol_value_breakdown: Vec<ProtocolValueStats>,  // Per-protocol stats
    pub overall_statistics: OverallValueStats,              // Global aggregates
    pub fee_context: FeeAnalysisReport,                     // Fee analysis for context
}
```

**2. `ProtocolValueStats`** (lines 18-28) - **KEY TYPE FOR VARIANT EXTENSION**:
```rust
pub struct ProtocolValueStats {
    pub protocol: ProtocolType,              // Protocol enum (Bitcoin Stamps, etc.)
    pub output_count: usize,                 // Unspent P2MS output count
    pub transaction_count: usize,            // Distinct txid count
    pub total_btc_value_sats: u64,          // Total value in satoshis (SUM)
    pub average_btc_per_output: f64,        // Arithmetic mean per output
    pub min_btc_value_sats: u64,            // Minimum individual output
    pub max_btc_value_sats: u64,            // Maximum individual output
    pub percentage_of_total_value: f64,     // Value % of all protocols
    pub fee_stats: ProtocolFeeStats,        // Associated fee context
}
```

**3. `OverallValueStats`** (lines 32-36):
```rust
pub struct OverallValueStats {
    pub total_outputs_analysed: usize,       // Sum of all protocol outputs
    pub total_btc_locked_in_p2ms: u64,      // Sum of all protocol values
    pub total_protocols: usize,              // Count of distinct protocols
}
```

**4. `ProtocolValueDistribution`** (lines 40-46) - For histogram/bucketing:
```rust
pub struct ProtocolValueDistribution {
    pub protocol: ProtocolType,
    pub total_outputs: usize,
    pub total_value_sats: u64,
    pub buckets: Vec<ValueBucket>,          // Histogram buckets
    pub percentiles: ValuePercentiles,      // p25, p50, p75, p90, p95, p99
}
```

**5. Common Type: `ValueBucket`** (lines 78 in common.rs):
```rust
pub type ValueBucket = DistributionBucket<u64>;

// Where DistributionBucket is generic (lines 17-30 in common.rs):
pub struct DistributionBucket<T: Copy> {
    pub range_min: T,              // Lower bound (inclusive)
    pub range_max: T,              // Upper bound (exclusive)
    pub count: usize,              // Output count in bucket
    pub value: u64,                // Total satoshis in bucket
    pub pct_count: f64,            // Percentage of total outputs
    pub pct_value: f64,            // Percentage of total value
}
```

**6. Distribution Report** (lines 61-65):
```rust
pub struct ValueDistributionReport {
    pub global_distribution: GlobalValueDistribution,
    pub protocol_distributions: Vec<ProtocolValueDistribution>,
    pub bucket_ranges: Vec<(u64, u64)>,  // Standard bucket ranges for consistency
}
```

---

## 3. Existing Variant Types (Pattern for Reuse)

### Location: `src/types/analysis_results/stamps.rs`

#### `VariantTotal` (lines 199-212) - **CRITICAL PATTERN**:
```rust
pub struct VariantTotal {
    pub variant: String,              // e.g., "Classic", "SRC-20", "SRC-721"
    pub count: usize,                 // Total output count
    pub percentage: f64,              // % of total variant outputs
    pub total_value_sats: u64,        // VALUE FIELD - KEY FOR EXTENSION!
}
```

**Key Insight**: `VariantTotal` already includes `total_value_sats` (line 211)! This is the **existing pattern** we can extend for variant breakdown.

#### `WeeklyVariantStats` (lines 218-236) - **TEMPORAL PATTERN**:
```rust
pub struct WeeklyVariantStats {
    pub week_bucket: i64,
    pub week_start_iso: String,
    pub week_end_iso: String,
    pub variant: String,
    pub count: usize,
    pub value_sats: u64,             // Per-week value for temporal analysis
}
```

#### `StampsVariantTemporalReport` (lines 172-196) - **REPORT PATTERN**:
```rust
pub struct StampsVariantTemporalReport {
    pub total_outputs: usize,
    pub total_value_sats: u64,       // Top-level aggregate
    pub date_range_start: String,
    pub date_range_end: String,
    pub variant_totals: Vec<VariantTotal>,       // Aggregate per variant
    pub weekly_data: Vec<WeeklyVariantStats>,    // Time-series detail
    pub first_appearances: Vec<VariantFirstSeen>,
    pub null_variant_count: usize,
}
```

**Pattern**: Hierarchical aggregation - Overall stats → Variant totals → Weekly detail

---

## 4. Database Schema & Query Patterns

### Critical Tables

#### `transaction_classifications` (Stage 3):
- **Primary Key**: `txid` (text)
- **Columns**: 
  - `protocol` (TEXT) - Protocol name from classification
  - `variant` (TEXT) - Protocol-specific variant (NULL for most, set for Stamps)
  - `transport_protocol` (TEXT) - For Stamps (Pure vs Counterparty)
  - `content_type` (TEXT) - MIME type of extracted data
  - `protocol_signature_found` (BOOLEAN)
- **Indexes**: 
  - `idx_tc_protocol` - Protocol filtering
  - `idx_tc_variant` - Variant filtering
  - `idx_tc_protocol_txid` - Combined protocol+txid lookups

#### `p2ms_output_classifications` (Stage 3):
- **Primary Key**: `(txid, vout)`
- **Columns**: Same as `transaction_classifications` (protocol, variant, etc.)
- **FK Constraint**: `txid → transaction_classifications(txid)`
- **Indexes**: 
  - `idx_poc_protocol`, `idx_poc_variant` for filtering
  - `idx_poc_txid_vout` for output-level lookups
- **Key Property**: Output-level detail (not tx-level)

#### `transaction_outputs` (Stage 1 seeded, Stage 2 enriched):
- **Key Columns**: 
  - `txid`, `vout` (PK)
  - `amount` (INTEGER) - satoshis
  - `script_type` (TEXT) - "multisig" for P2MS
  - `is_spent` (BOOLEAN) - **CRITICAL: 0 = UTXO, 1 = spent**
  - `height` (INTEGER) - Block height

### Current Query Pattern (value_analysis.rs, lines 44-59):

```sql
SELECT
    tc.protocol,
    COUNT(*) as output_count,
    COUNT(DISTINCT tc.txid) as tx_count,
    SUM(to1.amount) as total_value_sats,
    AVG(to1.amount) as avg_value_sats,
    MIN(to1.amount) as min_value_sats,
    MAX(to1.amount) as max_value_sats
FROM transaction_classifications tc
JOIN transaction_outputs to1 ON tc.txid = to1.txid
WHERE to1.script_type = 'multisig'
  AND to1.is_spent = 0           -- CRITICAL: unspent only
GROUP BY tc.protocol
ORDER BY output_count DESC
```

**Key Patterns**:
- Uses `transaction_classifications` for protocol filtering
- JOINs to `transaction_outputs` for amount values
- Filters `script_type = 'multisig'` and `is_spent = 0`
- Aggregates with COUNT(*), SUM(), AVG(), MIN(), MAX()
- Groups by single dimension (protocol)

### Variant-Level Query Pattern (Needed):

For variant breakdown within each protocol:
```sql
SELECT
    tc.protocol,
    poc.variant,           -- OUTPUT-LEVEL variant (Key difference!)
    COUNT(*) as output_count,
    COUNT(DISTINCT tc.txid) as tx_count,
    SUM(to1.amount) as total_value_sats,
    AVG(to1.amount) as avg_value_sats,
    MIN(to1.amount) as min_value_sats,
    MAX(to1.amount) as max_value_sats
FROM p2ms_output_classifications poc  -- Output-level table!
JOIN transaction_classifications tc ON poc.txid = tc.txid
JOIN transaction_outputs to1 ON poc.txid = to1.txid AND poc.vout = to1.vout
WHERE to1.script_type = 'multisig'
  AND to1.is_spent = 0
GROUP BY tc.protocol, poc.variant      -- Two-level grouping
ORDER BY tc.protocol, output_count DESC
```

**Differences from Current Pattern**:
- Uses `p2ms_output_classifications` (output-level) instead of `transaction_classifications` (tx-level)
- Includes `variant` in SELECT and GROUP BY
- Requires `(txid, vout)` join for output-level matching
- Can have NULL variants (must be excluded or reported separately)

---

## 5. Report Formatting Architecture

### Location: `src/analysis/reports/value.rs`

#### Console Formatting (lines 17-107):

**Structure**:
1. Header: "=== PROTOCOL VALUE DISTRIBUTION ===" (line 26)
2. Table headers with column widths (lines 29-32)
3. Data rows with formatting helpers (lines 36-46):
   - `format_number()` - comma-separated thousands
   - `format_sats_as_btc()` - satoshis → BTC with units
   - `format_sats_as_btc_f64()` - float satoshis → BTC
4. Fee breakdown section (lines 64-83)
5. Overall fee summary (lines 86-101)

**Key Column Layout**:
```
Protocol/Use | Outputs | Total BTC | Avg BTC/Output | Min BTC | Max BTC
```

#### JSON Formatting (line 105):
```rust
OutputFormat::Json | OutputFormat::Plotly => export_json(report)
```
- Delegates to `export_json()` helper (from utils)
- Automatically serialises entire report structure via serde

#### Value Distribution Formatting (lines 110-203):

**Console Mode** (lines 115-192):
- Global summary stats
- Percentile breakdown (p25, p50, p75, p90, p95, p99)
- Top 5 buckets by count
- Suggests `--format json` for full data

**JSON Mode** (lines 194-196):
- Full structure with all buckets and percentiles

**Plotly Mode** (lines 198-330):
- Generates Plotly-native chart JSON
- Creates bar chart with bucket labels (X-axis), counts (Y-axis)
- One trace per protocol (grouped/hidden by default)
- Log scale toggle, legend positioning, etc.

**Plotly Implementation** (lines 206-330):
```rust
fn export_plotly_value_distributions(report: &ValueDistributionReport) -> AppResult<String> {
    // Helper to format value labels with K/M/BTC abbreviations
    let format_value_label = |sats: u64| -> String { ... };
    
    // Create bucket labels (X-axis)
    let bucket_labels: Vec<String> = ...;
    
    // Create traces (one per protocol)
    let mut traces = Vec::new();
    
    // Global distribution trace
    traces.push(PlotlyTrace::bar(..., "All P2MS Outputs", ...));
    
    // Per-protocol traces (sorted by canonical enum order)
    for protocol_dist in &sorted_protocol_dists {
        traces.push(PlotlyTrace::bar(..., display_name, colour).hidden_by_default());
    }
    
    // Layout configuration
    let layout = PlotlyLayout::basic(...)
        .with_title_font_size(16)
        .with_legend(...)
        .with_log_toggle();
    
    // Create typed PlotlyChart and serialise
    let chart = PlotlyChart { data: traces, layout };
    serde_json::to_string_pretty(&chart)
}
```

---

## 6. Data Flow Architecture

### Complete Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│ 1. CLI Layer: src/cli/commands/analysis.rs                  │
│    - Parse arguments (database_path, format)                │
│    - Call run_simple_analysis() helper                      │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Engine Layer: src/analysis/mod.rs::AnalysisEngine        │
│    - Create database connection                             │
│    - Call specific analyse_value() method                   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Analysis Layer: src/analysis/value_analysis.rs           │
│    - analyse_value_distribution()                           │
│      - Query protocol-level stats from DB                   │
│      - Parse protocol strings to enums                      │
│      - Build ProtocolValueStats structures                  │
│      - Calculate percentages                                │
│    - analyse_value_distributions()                          │
│      - Query global distribution                            │
│      - Query per-protocol distributions                     │
│      - Calculate bucket histograms                          │
│      - Calculate percentiles                                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Type Layer: src/types/analysis_results/value.rs          │
│    - ValueAnalysisReport                                    │
│    - ProtocolValueStats                                     │
│    - OverallValueStats                                      │
│    - ValueDistributionReport                                │
│    - ProtocolValueDistribution                              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Formatter Layer: src/analysis/reports/value.rs           │
│    - format_value_analysis()                                │
│      - Console: formatted table                             │
│      - JSON: serde serialisation                            │
│    - format_value_distributions()                           │
│      - Console: summary view                                │
│      - Plotly: TypedPlotlyChart with traces                 │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Output Layer: CLI stdout or ./output_data/plots/         │
│    - Console: human-readable table                          │
│    - JSON: full data structure                              │
│    - Plotly: interactive web-compatible chart               │
└─────────────────────────────────────────────────────────────┘
```

### Data at Each Stage

**After Step 2 (Engine)**:
- Returns `ValueAnalysisReport` or `ValueDistributionReport`

**After Step 3 (Analysis)**:
- Queries executed, aggregations computed
- Values in satoshis, counts in usize
- ProtocolType enums assigned

**After Step 4 (Types)**:
- Strongly-typed Rust structures with serde support
- Ready for serialisation or formatting

**After Step 5 (Formatter)**:
- String output (console formatting code or JSON/Plotly JSON)

**After Step 6 (Output)**:
- Printed to stdout or written to file

---

## 7. Key Implementation Patterns

### 1. Percentage Calculation Pattern

```rust
// In value_analysis.rs, lines 116-120
let percentage_of_total_value = if total_value_sats > 0 {
    (total_sats as f64 / total_value_sats as f64) * 100.0
} else {
    0.0
};
```

**Usage**: Avoid division-by-zero with conditional check

### 2. Protocol Enum Parsing at DB Boundary

```rust
// In value_analysis.rs, lines 125-126
let protocol = ProtocolType::from_str(&protocol_str)
    .unwrap_or_default();
```

**Pattern**: Parse string from DB to enum once, use enum throughout analysis

### 3. Sorting for Consistent Output

```rust
// In value_analysis.rs, lines 144
protocol_value_breakdown.sort_by_key(|p| p.protocol as u8);
```

**Pattern**: Sort by canonical ProtocolType enum order (derived from `u8` repr)

### 4. Optional Fee Stats Fallback

```rust
// In value_analysis.rs, lines 122-123
let protocol_fee_stats = fee_stats.get(&protocol_str)
    .cloned()
    .unwrap_or_default();
```

**Pattern**: Use Option::get() with cloned values and default fallback

### 5. Memory Safety in Percentile Calculation

```rust
// In value_analysis.rs, lines 373-387
if count > MAX_VALUES_IN_MEMORY {
    tracing::warn!("Dataset too large...");
    return Ok(ValuePercentiles { p25: 0, p50: 0, ... });
}
```

**Pattern**: Check memory limits, warn if exceeded, return safe defaults

### 6. Bucket Calculation with Streaming

```rust
// In value_analysis.rs, lines 459-510
for (range_min, range_max) in bucket_ranges {
    // Query count and sum for this bucket
    // Create ValueBucket::new() with percentages
}
```

**Pattern**: Stream buckets sequentially, calculate percentages in one pass

---

## 8. Gaps & Considerations for Variant Breakdown

### Identified Gaps

1. **No Variant-Level Support in Value Analysis**:
   - Current: Aggregates by protocol only
   - Needed: Protocol → Variant hierarchy
   - `VariantTotal` type already exists but unused in value analysis

2. **Output-Level vs Transaction-Level**:
   - Current: Uses `transaction_classifications` (tx-level)
   - For variants: Must use `p2ms_output_classifications` (output-level)
   - Requires output-level joins on `(txid, vout)` pairs

3. **NULL Variant Handling**:
   - `VariantTotal` in `stamps_variant_temporal` handles NULLs explicitly
   - Current value analysis doesn't filter/report variants at all

4. **No Temporal Variant Analysis**:
   - `stamps_variant_temporal` provides `weekly_data: Vec<WeeklyVariantStats>`
   - Value analysis has no temporal dimension (only global/per-protocol)
   - Consider whether variant temporal value analysis is needed

5. **Sorting Strategy**:
   - Current: Protocol sorted by enum (canonical order)
   - For variants: Within each protocol, sort by count descending (pattern from `stamps_variant_temporal`)

### Type Design Considerations

**Option A: Extend ProtocolValueStats with Variant Detail**
```rust
pub struct ProtocolValueStats {
    pub protocol: ProtocolType,
    pub output_count: usize,
    pub total_btc_value_sats: u64,
    // ... existing fields ...
    pub variant_breakdown: Option<Vec<VariantValueStats>>, // NEW
}

pub struct VariantValueStats {
    pub variant: String,
    pub output_count: usize,
    pub total_value_sats: u64,
    pub average_btc_per_output: f64,
    pub percentage_within_protocol: f64,
}
```
**Pros**: Nested structure mirrors report hierarchy
**Cons**: Complicates JSON output, variant_breakdown is NULL for most protocols

**Option B: Create Separate Report Type**
```rust
pub struct VariantValueAnalysisReport {
    pub protocol_variant_breakdown: Vec<ProtocolVariantValueStats>,
    pub overall_statistics: OverallValueStats,
}

pub struct ProtocolVariantValueStats {
    pub protocol: ProtocolType,
    pub variants: Vec<VariantValueStats>,
    pub protocol_total: ProtocolValueStats,
}
```
**Pros**: Clear separation, can be invoked independently
**Cons**: Duplicate data, new CLI command needed

**Recommendation**: Option B (new command) for modularity, follows pattern of `analyse value` vs `analyse value-distributions`

### Query Optimization Considerations

1. **Index Usage**:
   - `idx_poc_protocol` on variant queries
   - `idx_poc_variant` for within-protocol filtering
   - Compound index `(protocol, variant)` would optimize GROUP BY

2. **NULL Variant Handling**:
   - `WHERE poc.variant IS NOT NULL` to exclude classifications without variant data
   - Separate query for null counts (pattern from `stamps_variant_temporal`)

3. **Memory Limits**:
   - Percentile calculation loads values into memory
   - With many variants, this could exceed MAX_VALUES_IN_MEMORY
   - Consider bucketing approach or sampling

---

## 9. Reusable Code Patterns from Stamps Variant Temporal

### Pattern 1: Variant Aggregation Loop

```rust
// From stamps_variant_temporal.rs, lines 97-103
let mut variant_totals_map: HashMap<String, (usize, u64)> = HashMap::new();
for row_result in rows {
    let entry = variant_totals_map.entry(variant.clone()).or_insert((0, 0));
    entry.0 += count;    // Output count
    entry.1 += value;    // Total value sats
    total_outputs += count;
    total_value_sats += value;
}
```

**Can reuse for**: Variant value aggregation

### Pattern 2: Variant Total Construction

```rust
// From stamps_variant_temporal.rs, lines 192-207
let mut variant_totals: Vec<VariantTotal> = variant_totals_map
    .into_iter()
    .map(|(variant, (count, value))| {
        let percentage = if total_outputs > 0 {
            (count as f64 / total_outputs as f64) * 100.0
        } else {
            0.0
        };
        VariantTotal {
            variant,
            count,
            percentage,
            total_value_sats: value,
        }
    })
    .collect();
variant_totals.sort_by(|a, b| b.count.cmp(&a.count));
```

**Can reuse for**: Building variant totals with sorting

### Pattern 3: Empty Result Handling

```rust
// From stamps_variant_temporal.rs, lines 132-137
if weekly_data.is_empty() {
    return Ok(StampsVariantTemporalReport {
        null_variant_count: null_variant_count as usize,
        ..Default::default()
    });
}
```

**Can reuse for**: Early exit when no data, but preserve metadata

---

## 10. Output Formats Summary

### Console Format

**Current Value Report**:
```
=== PROTOCOL VALUE DISTRIBUTION ===

Protocol/Use   | Outputs  | Total BTC | Avg BTC/Output | Min BTC | Max BTC
===============================================================================
BitcoinStamps  | 1,234,567| 12.34 BTC | 0.00001 BTC    | 0 BTC   | 10 BTC
Counterparty   | 234,567  | 2.34 BTC  | 0.00001 BTC    | 0 BTC   | 5 BTC
...
```

**Enhanced with Variants** (suggested):
```
=== PROTOCOL VALUE DISTRIBUTION (Variant Breakdown) ===

Protocol: BitcoinStamps (12.34 BTC total)
  Classic          | 500,000 outputs | 5.00 BTC | 40.5%
  SRC-20           | 400,000 outputs | 4.00 BTC | 32.4%
  SRC-721          | 334,567 outputs | 3.34 BTC | 27.1%

Protocol: Counterparty (2.34 BTC total)
  ...
```

### JSON Format

Current structure fully serialisable via serde. Variant breakdown would add optional field or new top-level report type.

### Plotly Format

Would extend with per-variant traces (similar to `stamps_variant_temporal` stacked bar chart):
- X-axis: Variants within protocol
- Y-axis: Output count or value
- Grouping: One section per protocol
- Legend: All variants across all protocols

---

## 11. File Location Summary

### Core Implementation
- **CLI Command**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/src/cli/commands/analysis.rs` (lines 139-147, 488-497)
- **Analysis Logic**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/src/analysis/value_analysis.rs` (entire file, ~759 lines)
- **Report Formatting**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/src/analysis/reports/value.rs` (~331 lines)

### Type Definitions
- **Value Types**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/src/types/analysis_results/value.rs` (lines 1-79)
- **Stamps Variant Types** (pattern): `/Users/anthonymilton/dev/data-carry-all/data-carry-research/src/types/analysis_results/stamps.rs` (lines 165-252)
- **Common Types**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/src/types/analysis_results/common.rs` (lines 1-85)

### Engine & Dispatcher
- **AnalysisEngine**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/src/analysis/mod.rs` (lines 123-192 for value analysis methods)

### Supporting References
- **Database Schema**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/agent_docs/database_schema.md`
- **Analysis Reference**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/agent_docs/database_analysis.md`
- **Protocol Detection**: `/Users/anthonymilton/dev/data-carry-all/data-carry-research/agent_docs/protocol_detection.md`

---

## 12. Summary Table: Current vs Variant-Level Architecture

| Aspect | Current | Variant-Level |
|--------|---------|---------------|
| **Grouping Level** | Protocol only | Protocol → Variant |
| **Data Source** | `transaction_classifications` | `p2ms_output_classifications` + join |
| **Join Key** | `txid` | `(txid, vout)` |
| **Type Used** | `ProtocolValueStats` | New: `VariantValueStats` or extend |
| **Sorting** | By protocol enum | By count DESC within protocol |
| **NULL Handling** | N/A | Exclude or report separately |
| **Report Type** | `ValueAnalysisReport` | New: `VariantValueAnalysisReport` (recommended) |
| **CLI Command** | `analyse value` | New: `analyse value-variants` (suggested) |
| **Console Output** | Single-level table | Protocol sections with variant sub-rows |
| **JSON Output** | Flat protocol list | Nested protocol → variants |
| **Plotly Output** | Bar chart by protocol | Grouped/stacked by variant within protocol |

---

## Conclusion

The `analyse value` command uses a clean, modular architecture with:
1. **Clear separation of concerns**: CLI → Engine → Analysis → Types → Formatting
2. **Reusable patterns**: Particularly from `stamps_variant_temporal` for variant aggregation
3. **Type safety**: Strong typing from ProtocolType enum through output
4. **Multiple output formats**: Console, JSON, Plotly with shared logic
5. **Query optimization**: Proper indexing, aggregation at DB level, filtering for unspent outputs

For variant-level breakdown:
- Extend with output-level queries using `p2ms_output_classifications`
- Create parallel report type (VariantValueAnalysisReport)
- Leverage existing `VariantTotal` pattern from stamps analysis
- Add new CLI subcommand (`analyse value-variants` or similar)
- Implement variant-specific console, JSON, and Plotly formatting

The existing codebase provides strong precedent (stamps_variant_temporal) for implementing variant-level breakdown without major architectural changes.
