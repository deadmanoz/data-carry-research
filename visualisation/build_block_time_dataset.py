#!/usr/bin/env python3
"""Build complete block height→timestamp dataset from Bitcoin Core.

This is a ONE-TIME operation that fetches timestamps for ALL blocks from
genesis to chain tip, creating a definitive reference dataset in CSV format.
"""

import csv
import json
import subprocess
import sys
from pathlib import Path

import click


def get_blockchain_info() -> dict:
    """Get blockchain info from Bitcoin Core."""
    result = subprocess.run(
        [
            'bitcoin-cli',
            '-rpcconnect=localhost',
            '-rpcuser=bitcoin',
            '-rpcpassword=bitcoin',
            'getblockchaininfo'
        ],
        capture_output=True,
        text=True,
        check=True
    )
    return json.loads(result.stdout)


def get_block_timestamp(height: int) -> int:
    """Fetch block timestamp from Bitcoin Core RPC."""
    # Get block hash
    result = subprocess.run(
        [
            'bitcoin-cli',
            '-rpcconnect=localhost',
            '-rpcuser=bitcoin',
            '-rpcpassword=bitcoin',
            'getblockhash',
            str(height)
        ],
        capture_output=True,
        text=True,
        check=True
    )
    block_hash = result.stdout.strip()

    # Get block header
    result = subprocess.run(
        [
            'bitcoin-cli',
            '-rpcconnect=localhost',
            '-rpcuser=bitcoin',
            '-rpcpassword=bitcoin',
            'getblockheader',
            block_hash
        ],
        capture_output=True,
        text=True,
        check=True
    )
    block_header = json.loads(result.stdout)
    return block_header['time']


@click.command()
@click.option(
    '--output', '-o',
    default='visualisation/bitcoin_block_times.csv',
    help='Output CSV file (default: visualisation/bitcoin_block_times.csv)'
)
@click.option(
    '--max-height',
    type=int,
    default=None,
    help='Maximum block height to fetch (default: chain tip)'
)
@click.option(
    '--no-resume',
    is_flag=True,
    help='Start fresh (delete existing file and rebuild from scratch)'
)
def main(output: str, max_height: int, no_resume: bool):
    """Build complete Bitcoin block height→timestamp reference dataset in CSV.

    This fetches actual block timestamps from Bitcoin Core for ALL blocks
    from genesis to chain tip. This is a one-time operation that creates
    a definitive reference dataset for accurate visualisations.

    AUTOMATICALLY RESUMES if interrupted - every block is written immediately.

    Format: CSV with columns: height,timestamp (appends each block)

    Examples:

        \b
        # Fetch all blocks from genesis to tip (auto-resumes if interrupted)
        python visualisation/build_block_time_dataset.py

        \b
        # Fetch up to block 500,000
        python visualisation/build_block_time_dataset.py --max-height 500000

        \b
        # Start fresh (delete existing file and rebuild from scratch)
        python visualisation/build_block_time_dataset.py --no-resume
    """
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Get blockchain info
    click.echo("Fetching blockchain info...")
    try:
        info = get_blockchain_info()
        chain_tip = info['blocks']
        click.echo(f"  Chain: {info['chain']}")
        click.echo(f"  Current tip: {chain_tip:,}")
    except Exception as e:
        click.echo(click.style(f"✗ Failed to connect to Bitcoin Core: {e}", fg='red'), err=True)
        sys.exit(1)

    # Determine height range
    if max_height is None:
        max_height = chain_tip
    else:
        max_height = min(max_height, chain_tip)

    # Check for existing data (auto-resume unless --no-resume specified)
    start_height = 0

    if no_resume and output_path.exists():
        click.echo(f"--no-resume specified: deleting {output_path}")
        output_path.unlink()

    if output_path.exists():
        # Read last line to find where to resume
        click.echo(f"Found existing dataset at {output_path}")
        with open(output_path, 'rb') as f:
            # Seek to end and read last line efficiently
            try:
                f.seek(-2, 2)  # Jump to second last byte
                while f.read(1) != b'\n':  # Until EOL is found
                    f.seek(-2, 1)
                last_line = f.readline().decode()
                last_height = int(last_line.split(',')[0])
                start_height = last_height + 1
                click.echo(f"  Last entry: block {last_height:,}")
                click.echo(f"  Auto-resuming from height {start_height:,}\n")
            except (OSError, ValueError, IndexError):
                # File too small or corrupted, start from beginning
                click.echo("  Warning: Could not read last entry, starting from genesis")
                start_height = 0
                output_path.unlink()

    # Create or open file for appending
    file_mode = 'a' if output_path.exists() else 'w'
    file_handle = open(output_path, file_mode, newline='')
    writer = csv.writer(file_handle)

    # Write header if new file
    if file_mode == 'w':
        writer.writerow(['height', 'timestamp'])

    total_blocks = max_height - start_height + 1
    click.echo(f"Fetching {total_blocks:,} blocks (height {start_height:,} → {max_height:,})\n")

    # Fetch timestamps (write each immediately)
    try:
        with click.progressbar(
            range(start_height, max_height + 1),
            label='Progress',
            length=total_blocks
        ) as bar:
            for height in bar:
                try:
                    timestamp = get_block_timestamp(height)
                    writer.writerow([height, timestamp])
                    file_handle.flush()  # Ensure written to disk immediately

                except Exception as e:
                    click.echo(f"\n✗ Error at height {height}: {e}", err=True)
                    file_handle.close()
                    raise

    except KeyboardInterrupt:
        click.echo("\n\n⚠ Interrupted by user")
        file_handle.close()
        click.echo(f"✓ Progress saved to {output_path}")
        click.echo("Run again to auto-resume (or use --no-resume to start fresh)")
        sys.exit(0)

    # Close file
    file_handle.close()

    total_written = max_height - 0 + 1  # Assuming we have all blocks from 0
    click.echo(f"\n✓ Complete! Saved {total_written:,} block timestamps to {output_path}")

    # Statistics
    click.echo(f"\nDataset statistics:")
    click.echo(f"  Blocks: {total_written:,}")
    click.echo(f"  Height range: 0 → {max_height:,}")

    # File size
    file_size_mb = output_path.stat().st_size / (1024 * 1024)
    click.echo(f"  File size: {file_size_mb:.1f} MB")


if __name__ == '__main__':
    main()
