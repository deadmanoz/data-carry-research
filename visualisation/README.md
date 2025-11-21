# P2MS Data Visualisation

Python-based visualisation tools for Bitcoin P2MS data-carrying protocol analysis.

## Setup

### 1. Python Environment

```bash
# Virtual environment is already set up at project root
# Dependencies: pandas, matplotlib, click
.venv/bin/python --version  # Should be Python 3.9+
```

### 2. Build Block Timestamp Reference Dataset (ONE-TIME, ~2-3 hours)

**REQUIRED BEFORE PLOTTING**: This builds a complete reference dataset of actual block timestamps from Bitcoin Core.

```bash
# Ensure Bitcoin Core is running with RPC enabled
# Then build the complete dataset (genesis → chain tip, ~920K blocks)
just build-block-times

# This creates: visualisation/bitcoin_block_times.csv (~15 MB)
# Resumable with checkpoints every 10,000 blocks
```

**Why CSV not JSON?**
- 50% smaller file size (15MB vs 27MB)
- Faster to load with pandas
- Simpler structure for tabular data
- Better for large datasets

**Dataset stats:**
- ~920,000 blocks (genesis to current tip)
- ~15 MB file size
- ~2-3 hours to build (RPC limited)
- Resumable with `just resume-block-times`

## Quick Start

```bash
# 1. Build block times dataset (one-time)
just build-block-times

# 2. Generate plots
just viz-stats p2ms_analysis_production_copy.db
just plot-temporal p2ms_analysis_production_copy.db
just plot-temporal-monthly p2ms_analysis_production_copy.db
```

## Available Commands

### Building Block Times Reference

```bash
# Full chain from genesis to tip
just build-block-times

# Limit to specific height (for testing)
just build-block-times 500000

# Resume interrupted build
just resume-block-times

# Direct Python CLI
.venv/bin/python visualisation/build_block_time_dataset.py --help
```

### Generating Visualisations

```bash
# Show database statistics
just viz-stats test_output/stage1_small.db

# Generate basic temporal distribution plot
just plot-temporal test_output/stage1_small.db

# Generate monthly aggregated plot
just plot-temporal-monthly test_output/stage1_small.db

# Generate logarithmic scale plot
just plot-temporal-log test_output/stage1_small.db

# Custom options via Python CLI
.venv/bin/python -m visualisation.cli temporal \
    --database test_output/stage1_small.db \
    --bin monthly \
    --log-scale \
    --format svg \
    --output output_data/plots/custom.svg \
    --title "Custom Title"
```

### CLI Options

```bash
# Show all visualisation CLI options
just viz-help

# temporal command options:
#   --database, -d      Database path (required)
#   --output, -o        Output file path
#   --bin              Aggregate by: daily, monthly, yearly
#   --log-scale        Use logarithmic Y-axis
#   --no-dual-axis     Disable dual X-axis (date + height)
#   --format, -f       Output format: png, svg, pdf
#   --dpi              DPI for raster output (default: 300)
#   --title, -t        Custom plot title
#   --stats            Show database statistics before plotting
```

## Output

All plots saved to `output_data/plots/` directory (gitignored).

Plot types generated:
- Temporal distribution (raw, daily, monthly, yearly bins)
- Bar charts showing discrete P2MS output counts
- High-resolution (300 DPI) publication-ready images

## Troubleshooting

### Error: "Block timestamp dataset not found"

```bash
# You need to build the reference dataset first
just build-block-times
```

### Error: "Block height X not in dataset"

```bash
# Your database contains blocks beyond the reference dataset
# Rebuild to include current chain tip
just build-block-times
```
