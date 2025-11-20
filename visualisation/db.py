"""Database query functions for P2MS data extraction."""

import sqlite3
from pathlib import Path
from typing import Dict, Optional

import pandas as pd


# Cache for loaded block timestamps
_BLOCK_TIMES_CACHE: Dict[int, int] = None


def load_block_timestamps() -> Dict[int, int]:
    """Load actual block timestamps from CSV file.

    Returns:
        Dictionary mapping height→timestamp

    Raises:
        FileNotFoundError: If bitcoin_block_times.csv doesn't exist
    """
    global _BLOCK_TIMES_CACHE

    if _BLOCK_TIMES_CACHE is not None:
        return _BLOCK_TIMES_CACHE

    csv_path = Path(__file__).parent / 'bitcoin_block_times.csv'

    if not csv_path.exists():
        raise FileNotFoundError(
            f"Block timestamp dataset not found: {csv_path}\n"
            f"Run 'just build-block-times' to create it (one-time operation, ~2-3 hours)"
        )

    # Use pandas for fast CSV loading
    df = pd.read_csv(csv_path, dtype={'height': int, 'timestamp': int})
    _BLOCK_TIMES_CACHE = dict(zip(df['height'], df['timestamp']))

    return _BLOCK_TIMES_CACHE


def get_block_timestamp(height: int) -> int:
    """Get actual timestamp for block height from reference dataset.

    Args:
        height: Block height

    Returns:
        Unix timestamp

    Raises:
        FileNotFoundError: If block times dataset hasn't been built
        KeyError: If height not in dataset
    """
    block_times = load_block_timestamps()

    if height not in block_times:
        raise KeyError(
            f"Block height {height} not in dataset (range: {min(block_times)}-{max(block_times)})\n"
            f"Run 'just build-block-times' to rebuild with current chain tip"
        )

    return block_times[height]


def get_temporal_distribution(
    db_path: str,
    script_type: str = "multisig",
    bin_by: Optional[str] = None
) -> pd.DataFrame:
    """Extract temporal distribution of P2MS outputs from database.

    Args:
        db_path: Path to SQLite database
        script_type: Script type to filter (default: "multisig")
        bin_by: Optional aggregation: "daily", "monthly", "yearly", or None for raw

    Returns:
        DataFrame with columns: height, count, timestamp (and date if binned)

    Raises:
        FileNotFoundError: If database doesn't exist
        sqlite3.Error: If query fails
    """
    db_file = Path(db_path)
    if not db_file.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    # Connect and query
    conn = sqlite3.connect(db_path)
    try:
        query = """
            SELECT height, COUNT(*) as count
            FROM transaction_outputs
            WHERE script_type = ?
            GROUP BY height
            ORDER BY height
        """

        df = pd.read_sql_query(query, conn, params=(script_type,))

        if df.empty:
            raise ValueError(f"No {script_type} outputs found in database")

        # Add actual timestamps from reference dataset
        df['timestamp'] = df['height'].apply(get_block_timestamp)
        df['date'] = pd.to_datetime(df['timestamp'], unit='s')

        # Apply binning if requested
        if bin_by:
            df = _apply_binning(df, bin_by)

        return df

    finally:
        conn.close()


def _apply_binning(df: pd.DataFrame, bin_by: str) -> pd.DataFrame:
    """Apply temporal binning to the data.

    Args:
        df: DataFrame with 'date' and 'count' columns
        bin_by: Binning strategy: "daily", "monthly", or "yearly"

    Returns:
        Binned DataFrame
    """
    freq_map = {
        'daily': 'D',
        'monthly': 'ME',  # Month end frequency
        'yearly': 'YE'    # Year end frequency
    }

    if bin_by not in freq_map:
        raise ValueError(f"Invalid bin_by: {bin_by}. Must be one of {list(freq_map.keys())}")

    # Resample by date and sum counts
    # Also keep track of height range for each bin
    df_binned = df.set_index('date').resample(freq_map[bin_by]).agg({
        'count': 'sum',
        'height': 'first',  # Use first height in bin for reference
    }).reset_index()

    # Add timestamp from date
    df_binned['timestamp'] = df_binned['date'].astype(int) // 10**9

    return df_binned[['height', 'count', 'timestamp', 'date']]


def get_database_stats(db_path: str) -> dict:
    """Get basic statistics about the database.

    Args:
        db_path: Path to SQLite database

    Returns:
        Dictionary with stats: total_outputs, min_height, max_height, date_range
    """
    conn = sqlite3.connect(db_path)
    try:
        query = """
            SELECT
                COUNT(*) as total,
                MIN(height) as min_height,
                MAX(height) as max_height
            FROM transaction_outputs
            WHERE script_type = 'multisig'
        """
        result = conn.execute(query).fetchone()

        return {
            'total_outputs': result[0],
            'min_height': result[1],
            'max_height': result[2],
            'min_date': pd.to_datetime(get_block_timestamp(result[1]), unit='s'),
            'max_date': pd.to_datetime(get_block_timestamp(result[2]), unit='s'),
        }
    finally:
        conn.close()


def get_protocol_distribution(
    db_path: str,
    bin_by: Optional[str] = None
) -> pd.DataFrame:
    """Extract protocol distribution over time (P2MS output level).

    Args:
        db_path: Path to SQLite database
        bin_by: Optional aggregation: "monthly", "yearly", or None for raw

    Returns:
        DataFrame with columns: height, protocol, count, timestamp, date
        (pivoted for easy stacking in plots)

    Raises:
        FileNotFoundError: If database doesn't exist
        sqlite3.Error: If query fails
    """
    db_file = Path(db_path)
    if not db_file.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    try:
        # Query P2MS outputs per protocol per height
        query = """
            SELECT
                tout.height,
                tc.protocol,
                COUNT(tout.id) as count
            FROM transaction_classifications tc
            JOIN transaction_outputs tout ON tc.txid = tout.txid
            WHERE tout.script_type = 'multisig'
            GROUP BY tout.height, tc.protocol
            ORDER BY tout.height, tc.protocol
        """

        df = pd.read_sql_query(query, conn)

        if df.empty:
            raise ValueError("No protocol classification data found in database")

        # Add actual timestamps from reference dataset
        df['timestamp'] = df['height'].apply(get_block_timestamp)
        df['date'] = pd.to_datetime(df['timestamp'], unit='s')

        # Apply binning if requested
        if bin_by:
            df = _apply_protocol_binning(df, bin_by)

        return df

    finally:
        conn.close()


def _apply_protocol_binning(df: pd.DataFrame, bin_by: str) -> pd.DataFrame:
    """Apply temporal binning to protocol distribution data.

    Args:
        df: DataFrame with 'date', 'protocol', 'count' columns
        bin_by: Binning strategy: "monthly" or "yearly"

    Returns:
        Binned DataFrame with same structure
    """
    freq_map = {
        'monthly': 'ME',  # Month end frequency
        'yearly': 'YE'    # Year end frequency
    }

    if bin_by not in freq_map:
        raise ValueError(f"Invalid bin_by: {bin_by}. Must be one of {list(freq_map.keys())}")

    # Resample by date and protocol, sum counts
    df_binned = (
        df.set_index('date')
        .groupby(['protocol', pd.Grouper(freq=freq_map[bin_by])])
        ['count']
        .sum()
        .reset_index()
    )

    # Add timestamp and height (use first height in bin as reference)
    df_binned['timestamp'] = df_binned['date'].astype(int) // 10**9

    # Add representative height (first height in bin)
    df_binned = df_binned.merge(
        df.groupby('protocol')['height'].first().reset_index(),
        on='protocol',
        how='left'
    )

    return df_binned[['height', 'protocol', 'count', 'timestamp', 'date']]


def get_spendability_distribution(db_path: str, bin_by: Optional[str] = None) -> pd.DataFrame:
    """Get spendability distribution over time.

    Args:
        db_path: Path to SQLite database
        bin_by: Optional temporal binning ('monthly' or 'yearly')

    Returns:
        DataFrame with columns: height, is_spendable, count, timestamp, date
    """
    conn = sqlite3.connect(db_path)

    # Query spendability counts by height
    query = """
        SELECT
            tout.height,
            poc.is_spendable,
            COUNT(poc.id) as count
        FROM p2ms_output_classifications poc
        JOIN transaction_outputs tout ON poc.txid = tout.txid AND poc.vout = tout.vout
        WHERE tout.script_type = 'multisig'
        GROUP BY tout.height, poc.is_spendable
        ORDER BY tout.height, poc.is_spendable
    """

    df = pd.read_sql_query(query, conn)
    conn.close()

    if df.empty:
        return df

    # Add timestamps
    df['timestamp'] = df['height'].apply(get_block_timestamp)
    df['date'] = pd.to_datetime(df['timestamp'], unit='s')

    # Apply temporal binning if requested
    if bin_by:
        df = _apply_spendability_binning(df, bin_by)

    return df


def _apply_spendability_binning(df: pd.DataFrame, bin_by: str) -> pd.DataFrame:
    """Aggregate spendability data by time period.

    Args:
        df: DataFrame with height, is_spendable, count, timestamp, date
        bin_by: 'monthly' or 'yearly'

    Returns:
        Aggregated DataFrame
    """
    freq_map = {'monthly': 'ME', 'yearly': 'YE'}

    if bin_by not in freq_map:
        raise ValueError(f"bin_by must be one of {list(freq_map.keys())}, got {bin_by}")

    # Group by is_spendable and time period, sum counts
    df_binned = (
        df.set_index('date')
        .groupby(['is_spendable', pd.Grouper(freq=freq_map[bin_by])])
        ['count']
        .sum()
        .reset_index()
    )

    # Add timestamp and height (use first height in bin as reference)
    df_binned['timestamp'] = df_binned['date'].astype(int) // 10**9

    # Add representative height (first height in bin)
    df_binned = df_binned.merge(
        df.groupby('is_spendable')['height'].first().reset_index(),
        on='is_spendable',
        how='left'
    )

    return df_binned[['height', 'is_spendable', 'count', 'timestamp', 'date']]
