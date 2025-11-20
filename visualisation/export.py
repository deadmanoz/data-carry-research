"""Export visualisation data to Plotly-compatible JSON format."""
# cspell:ignore color colors bgcolor fillcolor facecolor edgecolor bordercolor

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import pandas as pd


def export_protocol_distribution_plotly(
    df: pd.DataFrame,
    output_path: str,
    title: str = "P2MS Protocol Distribution Over Time",
    log_scale: bool = False
) -> None:
    """Export protocol distribution data as Plotly JSON.

    Args:
        df: DataFrame with 'date', 'protocol', 'count' columns
        output_path: Path to save JSON file
        title: Plot title
        log_scale: Whether to use logarithmic Y-axis
    """
    # Pivot data for stacking
    df_pivot = df.pivot(index='date', columns='protocol', values='count').fillna(0)
    
    # Sort protocols by total count (descending)
    protocol_totals = df_pivot.sum().sort_values(ascending=False)
    df_pivot = df_pivot[protocol_totals.index]
    
    # Protocol colours matching matplotlib implementation
    PROTOCOL_COLOURS = {
        'BitcoinStamps': '#E74C3C',
        'Counterparty': '#3498DB',
        'OmniLayer': '#9B59B6',
        'LikelyLegitimateMultisig': '#2ECC71',
        'DataStorage': '#F39C12',
        'Chancecoin': '#1ABC9C',
        'AsciiIdentifierProtocols': '#E67E22',
        'Protocol47930': '#BB3A00',
        'Unknown': '#95A5A6',
    }
    
    # Create traces for stacked bar chart
    traces: List[Dict[str, Any]] = []
    
    for protocol in df_pivot.columns:
        trace = {
            "x": df_pivot.index.strftime('%Y-%m-%d').tolist(),
            "y": df_pivot[protocol].tolist(),
            "name": protocol,
            "type": "bar",
            "marker": {
                "color": PROTOCOL_COLOURS.get(protocol, '#CCCCCC')
            }
        }
        traces.append(trace)
    
    # Create layout
    layout = {
        "title": {
            "text": title,
            "font": {"size": 16}
        },
        "xaxis": {
            "title": "Date",
            "type": "date"
        },
        "yaxis": {
            "title": "P2MS Output Count",
            "type": "log" if log_scale else "linear"
        },
        "barmode": "stack",
        "legend": {
            "orientation": "v",
            "x": 1.02,
            "y": 1,
            "xanchor": "left"
        },
        "hovermode": "x unified"
    }
    
    # Combine into Plotly format
    plotly_data = {
        "data": traces,
        "layout": layout
    }
    
    # Save to file
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(plotly_data, f, indent=2)
    
    print(f"Plotly JSON saved to: {output_file}")
    print(f"  - {len(traces)} protocols")
    print(f"  - {len(df_pivot)} time points")
    print(f"  - Total outputs: {int(df_pivot.sum().sum()):,}")


def export_spendability_plotly(
    df: pd.DataFrame,
    output_path: str,
    title: str = "P2MS Output Spendability Over Time"
) -> None:
    """Export spendability distribution data as Plotly JSON.

    Args:
        df: DataFrame with 'date', 'is_spendable', 'count' columns
        output_path: Path to save JSON file
        title: Plot title
    """
    # Pivot data to calculate percentages
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
    
    # Create traces for stacked area chart
    traces = [
        {
            "x": spendable_pct.index.strftime('%Y-%m-%d').tolist(),
            "y": spendable_pct.tolist(),
            "name": "Spendable",
            "type": "scatter",
            "mode": "lines",
            "fill": "tozeroy",
            "line": {"color": "#2ECC71", "width": 0},
            "fillcolor": "rgba(46, 204, 113, 0.7)",
            "stackgroup": "one"
        },
        {
            "x": unspendable_pct.index.strftime('%Y-%m-%d').tolist(),
            "y": unspendable_pct.tolist(),
            "name": "Unspendable",
            "type": "scatter",
            "mode": "lines",
            "fill": "tonexty",
            "line": {"color": "#E74C3C", "width": 0},
            "fillcolor": "rgba(231, 76, 60, 0.7)",
            "stackgroup": "one"
        }
    ]
    
    # Create layout
    layout = {
        "title": {
            "text": title,
            "font": {"size": 16}
        },
        "xaxis": {
            "title": "Date",
            "type": "date"
        },
        "yaxis": {
            "title": "Percentage of P2MS Outputs",
            "range": [0, 100],
            "ticksuffix": "%"
        },
        "hovermode": "x unified",
        "legend": {
            "orientation": "v",
            "x": 1.02,
            "y": 1,
            "xanchor": "left"
        }
    }
    
    # Add statistics as annotation
    total_outputs = int(df_pivot['total'].sum())
    avg_spendable = float(spendable_pct.mean())
    avg_unspendable = float(unspendable_pct.mean())
    
    layout["annotations"] = [{
        "text": (
            f"Total P2MS Outputs: {total_outputs:,}<br>"
            f"Avg Spendable: {avg_spendable:.1f}%<br>"
            f"Avg Unspendable: {avg_unspendable:.1f}%"
        ),
        "xref": "paper",
        "yref": "paper",
        "x": 0.02,
        "y": 0.02,
        "xanchor": "left",
        "yanchor": "bottom",
        "showarrow": False,
        "bgcolor": "rgba(255, 255, 255, 0.8)",
        "bordercolor": "gray",
        "borderwidth": 1,
        "borderpad": 4,
        "font": {"family": "monospace", "size": 10}
    }]
    
    # Combine into Plotly format
    plotly_data = {
        "data": traces,
        "layout": layout
    }
    
    # Save to file
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(plotly_data, f, indent=2)
    
    print(f"Plotly JSON saved to: {output_file}")
    print(f"  - {len(df_pivot)} time points")
    print(f"  - Total outputs: {total_outputs:,}")
    print(f"  - Avg spendable: {avg_spendable:.1f}%")
