"""Plotting functions for P2MS data visualisation."""
# cspell:ignore color colors bgcolor fillcolor facecolor edgecolor bordercolor

from pathlib import Path
from typing import Optional, Tuple

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
from matplotlib.figure import Figure


# Default styling
DEFAULT_FIGSIZE = (14, 8)
DEFAULT_DPI = 300
DEFAULT_STYLE = 'seaborn-v0_8-darkgrid'


def plot_temporal_distribution(
    df: pd.DataFrame,
    output_path: Optional[str] = None,
    title: str = "P2MS Outputs Temporal Distribution",
    log_scale: bool = False,
    figsize: Tuple[int, int] = DEFAULT_FIGSIZE,
    dpi: int = DEFAULT_DPI,
    show_dual_axis: bool = True,
    format: str = 'png'
) -> Figure:
    """Plot temporal distribution of P2MS outputs.

    Args:
        df: DataFrame with 'height', 'count', 'date' columns
        output_path: Path to save plot (optional, shows if None)
        title: Plot title
        log_scale: Use logarithmic Y-axis
        figsize: Figure size (width, height) in inches
        dpi: Dots per inch for saved figure
        show_dual_axis: Show both block height and date on X-axis
        format: Output format ('png', 'svg', 'pdf')

    Returns:
        Matplotlib Figure object
    """
    # Set style
    plt.style.use(DEFAULT_STYLE)

    # Create figure
    fig, ax1 = plt.subplots(figsize=figsize, dpi=dpi)

    # Plot data as bar chart (discrete data, no interpolation)
    if 'date' in df.columns:
        # Calculate appropriate bar width based on data density
        if len(df) > 1:
            # Use median time delta for bar width
            time_deltas = df['date'].diff().dropna()
            bar_width = time_deltas.median() * 0.8  # 80% of median spacing
        else:
            bar_width = pd.Timedelta(days=1)

        ax1.bar(df['date'], df['count'], width=bar_width,
                color='#1f77b4', alpha=0.7, edgecolor='#1f77b4', linewidth=0.5)
        ax1.set_xlabel('Date', fontsize=12, fontweight='bold')
    else:
        # For height-only data, use unit bar width
        ax1.bar(df['height'], df['count'], width=1.0,
                color='#1f77b4', alpha=0.7, edgecolor='#1f77b4', linewidth=0.5)
        ax1.set_xlabel('Block Height', fontsize=12, fontweight='bold')

    # Y-axis configuration
    ax1.set_ylabel('P2MS Output Count', fontsize=12, fontweight='bold')
    if log_scale:
        ax1.set_yscale('log')
        ax1.set_ylabel('P2MS Output Count (log scale)', fontsize=12, fontweight='bold')

    # Title and grid
    ax1.set_title(title, fontsize=14, fontweight='bold', pad=20)
    ax1.grid(True, alpha=0.3, linestyle='--')

    # Dual X-axis (block heights on top) if requested
    if show_dual_axis and 'date' in df.columns and 'height' in df.columns:
        ax2 = ax1.twiny()  # Create second X-axis on top
        ax2.set_xlim(df['date'].iloc[0], df['date'].iloc[-1])

        # Sample ~10 evenly spaced points for height labels
        step = max(1, len(df) // 10)
        sample_indices = df.iloc[::step].index

        ax2.set_xticks(df.loc[sample_indices, 'date'])
        ax2.set_xticklabels([f"{int(h):,}" for h in df.loc[sample_indices, 'height']], fontsize=10)
        ax2.set_xlabel('Block Height', fontsize=12, fontweight='bold')

    # Format date axis if present
    if 'date' in df.columns:
        ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
        ax1.xaxis.set_major_locator(mdates.YearLocator())
        ax1.xaxis.set_minor_locator(mdates.MonthLocator((1, 4, 7, 10)))
        plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')

    # Add statistics text box
    total_outputs = df['count'].sum()
    date_range = f"{df['date'].min().strftime('%Y-%m-%d')} to {df['date'].max().strftime('%Y-%m-%d')}" if 'date' in df.columns else "N/A"

    stats_text = f"Total P2MS Outputs: {total_outputs:,}\n"
    if 'height' in df.columns:
        stats_text += f"Height Range: {df['height'].min():,} - {df['height'].max():,}\n"
    if 'date' in df.columns:
        stats_text += f"Date Range: {date_range}"

    ax1.text(
        0.02, 0.98, stats_text,
        transform=ax1.transAxes,
        fontsize=10,
        verticalalignment='top',
        bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    )

    # Tight layout
    plt.tight_layout()

    # Save or show
    if output_path:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Support multiple formats
        if not output_file.suffix:
            output_file = output_file.with_suffix(f'.{format}')

        plt.savefig(output_file, dpi=dpi, bbox_inches='tight')
        print(f"Plot saved to: {output_file}")
    else:
        plt.show()

    return fig


# Protocol display name mapping (database name -> display name)
PROTOCOL_DISPLAY_NAMES = {
    'BitcoinStamps': 'Bitcoin Stamps',
    'Counterparty': 'Counterparty',
    'OmniLayer': 'Omni Layer',
    'LikelyLegitimateMultisig': 'Likely Legitimate Multisig',
    'DataStorage': 'Data Storage',
    'Chancecoin': 'Chancecoin',
    'AsciiIdentifierProtocols': 'ASCII Identifier Protocols',
    'PPk': 'PPk',
    'LikelyDataStorage': 'Likely Data Storage',
    'OpReturnSignalled': 'OP_RETURN Signalled',
    'Unknown': 'Unknown',
}

# Protocol colour mapping (uses display names)
PROTOCOL_COLOURS = {
    'Bitcoin Stamps': '#E74C3C',             # Red (dominant)
    'Counterparty': '#3498DB',               # Blue (second)
    'Omni Layer': '#9B59B6',                 # Purple
    'Likely Legitimate Multisig': '#2ECC71', # Green
    'Data Storage': '#F39C12',               # Orange
    'Chancecoin': '#1ABC9C',                 # Teal
    'ASCII Identifier Protocols': '#E67E22', # Dark orange
    'PPk': '#FF6B9D',                        # Pink
    'Likely Data Storage': '#7F8C8D',        # Slate grey
    'OP_RETURN Signalled': '#D4A574',        # Tan
    'Unknown': '#95A5A6',                    # Gray
}


def get_display_name(protocol: str) -> str:
    """Convert database protocol name to display name."""
    return PROTOCOL_DISPLAY_NAMES.get(protocol, protocol)


def plot_protocol_distribution(
    df: pd.DataFrame,
    output_path: Optional[str] = None,
    title: str = "P2MS Protocol Distribution Over Time",
    figsize: Tuple[int, int] = DEFAULT_FIGSIZE,
    dpi: int = DEFAULT_DPI,
    format: str = 'png',
    log_scale: bool = False
) -> Figure:
    """Plot protocol distribution over time as stacked bar chart.

    Args:
        df: DataFrame with 'date', 'protocol', 'count' columns
        output_path: Path to save plot (optional, shows if None)
        title: Plot title
        figsize: Figure size (width, height) in inches
        dpi: Dots per inch for saved figure
        format: Output format ('png', 'svg', 'pdf')

    Returns:
        Matplotlib Figure object
    """
    # Set style
    plt.style.use(DEFAULT_STYLE)

    # Pivot data for stacking (dates as rows, protocols as columns)
    df_pivot = df.pivot(index='date', columns='protocol', values='count').fillna(0)

    # Ensure all protocols are present (even if zero)
    for protocol in PROTOCOL_COLOURS.keys():
        if protocol not in df_pivot.columns:
            df_pivot[protocol] = 0

    # Sort protocols by total count (descending) for better visual
    protocol_totals = df_pivot.sum().sort_values(ascending=False)
    df_pivot = df_pivot[protocol_totals.index]

    # Create figure
    fig, ax = plt.subplots(figsize=figsize, dpi=dpi)

    # Calculate bar width based on data density
    if len(df_pivot) > 1:
        time_deltas = df_pivot.index.to_series().diff().dropna()
        bar_width = time_deltas.median() * 0.8
    else:
        bar_width = pd.Timedelta(days=30)

    # Plot stacked bars
    bottom = pd.Series(0, index=df_pivot.index)

    for protocol in df_pivot.columns:
        color = PROTOCOL_COLOURS.get(protocol, '#CCCCCC')
        ax.bar(
            df_pivot.index,
            df_pivot[protocol],
            width=bar_width,
            bottom=bottom,
            label=protocol,
            color=color,
            alpha=0.9,
            edgecolor='white',
            linewidth=0.5
        )
        bottom += df_pivot[protocol]

    # Formatting
    ax.set_xlabel('Date', fontsize=12, fontweight='bold')
    ax.set_ylabel('P2MS Output Count', fontsize=12, fontweight='bold')
    ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    ax.grid(True, alpha=0.3, linestyle='--', axis='y')

    # Set logarithmic scale if requested
    if log_scale:
        ax.set_yscale('log')
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f'{int(y):,}'))

    # Format date axis
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    ax.xaxis.set_major_locator(mdates.YearLocator())
    ax.xaxis.set_minor_locator(mdates.MonthLocator((1, 4, 7, 10)))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')

    # Legend (outside plot area, sorted by total)
    ax.legend(
        loc='upper left',
        bbox_to_anchor=(1.02, 1),
        frameon=True,
        fancybox=True,
        shadow=True
    )

    # Statistics text box
    total_outputs = df_pivot.sum().sum()
    date_range = f"{df_pivot.index.min().strftime('%Y-%m')} to {df_pivot.index.max().strftime('%Y-%m')}"

    stats_text = f"Total P2MS Outputs: {int(total_outputs):,}\n"
    stats_text += f"Date Range: {date_range}\n"
    stats_text += f"Protocols: {len(df_pivot.columns)}"

    ax.text(
        0.02, 0.98, stats_text,
        transform=ax.transAxes,
        fontsize=9,
        verticalalignment='top',
        bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    )

    # Tight layout to accommodate legend
    plt.tight_layout()

    # Save or show
    if output_path:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if not output_file.suffix:
            output_file = output_file.with_suffix(f'.{format}')

        plt.savefig(output_file, dpi=dpi, bbox_inches='tight')
        print(f"Plot saved to: {output_file}")
    else:
        plt.show()

    return fig


def plot_spendability_percentage(
    df: pd.DataFrame,
    output_path: Optional[str] = None,
    format: str = 'png',
    dpi: int = 300,
    title: Optional[str] = None
) -> plt.Figure:
    """Plot spendability percentage over time (stacked area chart).

    Args:
        df: DataFrame with height, is_spendable, count, timestamp, date columns
        output_path: Optional path to save plot
        format: Output format ('png', 'svg', 'pdf')
        dpi: DPI for raster output
        title: Custom plot title

    Returns:
        matplotlib Figure object
    """
    if df.empty:
        raise ValueError("No spendability data to plot")

    # Pivot data to calculate percentages
    # is_spendable: 0 = unspendable, 1 = spendable
    df_pivot = df.pivot_table(
        index='date',
        columns='is_spendable',
        values='count',
        fill_value=0
    )

    # Calculate total outputs per time period
    df_pivot['total'] = df_pivot.sum(axis=1)

    # Calculate percentages
    spendable_pct = (df_pivot.get(1, 0) / df_pivot['total'] * 100).fillna(0)
    unspendable_pct = (df_pivot.get(0, 0) / df_pivot['total'] * 100).fillna(0)

    # Create figure
    fig, ax = plt.subplots(figsize=(14, 8))

    # Create stacked area chart
    ax.fill_between(
        spendable_pct.index,
        0,
        spendable_pct,
        label='Spendable',
        color='#2ECC71',  # Green
        alpha=0.7
    )
    ax.fill_between(
        spendable_pct.index,
        spendable_pct,
        spendable_pct + unspendable_pct,
        label='Unspendable',
        color='#E74C3C',  # Red
        alpha=0.7
    )

    # Set y-axis to 0-100%
    ax.set_ylim(0, 100)
    ax.set_ylabel('Percentage of P2MS Outputs', fontsize=12, fontweight='bold')
    ax.set_xlabel('Date', fontsize=12, fontweight='bold')

    # Format y-axis as percentages
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f'{y:.0f}%'))

    # Grid
    ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
    ax.set_axisbelow(True)

    # Title
    if title:
        ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
    else:
        ax.set_title(
            'Bitcoin P2MS Output Spendability Over Time',
            fontsize=14,
            fontweight='bold',
            pad=20
        )

    # Legend
    ax.legend(loc='upper right', framealpha=0.9, fontsize=11)

    # Statistics box
    total_outputs = int(df_pivot['total'].sum())
    avg_spendable = float(spendable_pct.mean())
    avg_unspendable = float(unspendable_pct.mean())

    stats_text = (
        f'Total P2MS Outputs: {total_outputs:,}\n'
        f'Avg Spendable: {avg_spendable:.1f}%\n'
        f'Avg Unspendable: {avg_unspendable:.1f}%'
    )

    ax.text(
        0.02, 0.02,
        stats_text,
        transform=ax.transAxes,
        verticalalignment='bottom',
        horizontalalignment='left',
        bbox=dict(boxstyle='round', facecolor='white', alpha=0.8, edgecolor='gray'),
        fontsize=10,
        family='monospace'
    )

    # Format x-axis dates
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    fig.autofmt_xdate()

    plt.tight_layout()

    # Save or show
    if output_path:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if not output_file.suffix:
            output_file = output_file.with_suffix(f'.{format}')

        plt.savefig(output_file, dpi=dpi, bbox_inches='tight')
        print(f"Plot saved to: {output_file}")
    else:
        plt.show()

    return fig
