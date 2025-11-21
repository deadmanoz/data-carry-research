"""Centralised output path configuration for visualisation tools.

This module provides path constants for all visualisation and analysis outputs,
ensuring consistent output organisation across the project.
"""

from pathlib import Path

# Base output directory for all generated data
OUTPUT_DATA_BASE = Path("./output_data")

# Decoded blockchain protocol data (Stage 4)
DECODED_DIR = OUTPUT_DATA_BASE / "decoded"

# Fetched raw transactions from Bitcoin Core RPC
FETCHED_DIR = OUTPUT_DATA_BASE / "fetched"

# Visualisation outputs (plots, charts)
PLOTS_DIR = OUTPUT_DATA_BASE / "plots"

# Statistical analysis exports
ANALYSIS_DIR = OUTPUT_DATA_BASE / "analysis"
