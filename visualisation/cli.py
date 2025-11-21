"""Command-line interface for P2MS data visualisation."""

import sys
from pathlib import Path

import click

from visualisation.config import PLOTS_DIR
from visualisation.db import get_temporal_distribution, get_database_stats, get_protocol_distribution, get_spendability_distribution
from visualisation.plotting import plot_temporal_distribution, plot_protocol_distribution, plot_spendability_percentage
from visualisation.export import export_protocol_distribution_plotly, export_spendability_plotly


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """P2MS Data Visualisation CLI.

    Tools for visualising Bitcoin Pay-to-Multisig data-carrying protocol analysis.
    """
    pass


@cli.command()
@click.option(
    '--database', '-d',
    required=True,
    type=click.Path(exists=True),
    help='Path to SQLite database'
)
@click.option(
    '--output', '-o',
    default=str(PLOTS_DIR / 'temporal_distribution.png'),
    help='Output file path (default: output_data/plots/temporal_distribution.png)'
)
@click.option(
    '--bin',
    'bin_by',
    type=click.Choice(['daily', 'monthly', 'yearly'], case_sensitive=False),
    default=None,
    help='Aggregate data by time period'
)
@click.option(
    '--log-scale',
    is_flag=True,
    help='Use logarithmic Y-axis scale'
)
@click.option(
    '--no-dual-axis',
    is_flag=True,
    help='Disable dual X-axis (date + block height)'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['png', 'svg', 'pdf'], case_sensitive=False),
    default='png',
    help='Output format (default: png)'
)
@click.option(
    '--dpi',
    type=int,
    default=300,
    help='DPI for raster output (default: 300)'
)
@click.option(
    '--title', '-t',
    default='P2MS Outputs Temporal Distribution',
    help='Plot title'
)
@click.option(
    '--stats',
    is_flag=True,
    help='Show database statistics before plotting'
)
def temporal(
    database: str,
    output: str,
    bin_by: str,
    log_scale: bool,
    no_dual_axis: bool,
    format: str,
    dpi: int,
    title: str,
    stats: bool
):
    """Generate temporal distribution plot of P2MS outputs.

    This command creates a visualisation showing when P2MS outputs were created
    over Bitcoin's history, by block height and/or date.

    Examples:

        \b
        # Basic usage
        python -m visualisation.cli temporal -d test_output/stage1_small.db

        \b
        # Monthly aggregation with log scale
        python -m visualisation.cli temporal -d test_output/stage1_small.db \\
            --bin monthly --log-scale

        \b
        # Save as SVG with custom title
        python -m visualisation.cli temporal -d test_output/stage1_small.db \\
            --format svg --title "Bitcoin P2MS Evolution" \\
            --output output_data/plots/p2ms_evolution.svg
    """
    try:
        # Show stats if requested
        if stats:
            click.echo("Database Statistics:")
            click.echo("-" * 50)
            db_stats = get_database_stats(database)
            for key, value in db_stats.items():
                click.echo(f"  {key}: {value}")
            click.echo("-" * 50)
            click.echo()

        # Extract data
        click.echo(f"Extracting temporal distribution from {database}...")
        df = get_temporal_distribution(database, bin_by=bin_by)

        click.echo(f"Found {len(df)} data points")
        if bin_by:
            click.echo(f"Aggregated by: {bin_by}")

        # Generate plot
        click.echo(f"Generating plot...")
        plot_temporal_distribution(
            df,
            output_path=output,
            title=title,
            log_scale=log_scale,
            show_dual_axis=not no_dual_axis,
            format=format,
            dpi=dpi
        )

        click.echo(click.style("✓ Success!", fg='green', bold=True))

    except FileNotFoundError as e:
        click.echo(click.style(f"Error: {e}", fg='red'), err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(click.style(f"Error: {e}", fg='red'), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Unexpected error: {e}", fg='red'), err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option(
    '--database', '-d',
    required=True,
    type=click.Path(exists=True),
    help='Path to SQLite database'
)
def stats(database: str):
    """Show database statistics.

    Display basic statistics about P2MS outputs in the database.
    """
    try:
        stats = get_database_stats(database)

        click.echo("\n" + "=" * 60)
        click.echo("  P2MS Database Statistics")
        click.echo("=" * 60 + "\n")

        click.echo(f"  Total P2MS Outputs:  {stats['total_outputs']:,}")
        click.echo(f"  Block Height Range:  {stats['min_height']:,} → {stats['max_height']:,}")
        click.echo(f"  Date Range:          {stats['min_date'].strftime('%Y-%m-%d')} → {stats['max_date'].strftime('%Y-%m-%d')}")
        click.echo(f"  Time Span:           {(stats['max_date'] - stats['min_date']).days:,} days")

        click.echo("\n" + "=" * 60 + "\n")

    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg='red'), err=True)
        sys.exit(1)


@cli.command()
@click.option(
    '--database', '-d',
    required=True,
    type=click.Path(exists=True),
    help='Path to SQLite database'
)
@click.option(
    '--output', '-o',
    default=str(PLOTS_DIR / 'protocol_distribution.png'),
    help='Output file path (default: output_data/plots/protocol_distribution.png)'
)
@click.option(
    '--bin',
    'bin_by',
    type=click.Choice(['monthly', 'yearly'], case_sensitive=False),
    default='monthly',
    help='Aggregate data by time period (default: monthly)'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['png', 'svg', 'pdf'], case_sensitive=False),
    default='png',
    help='Output format (default: png)'
)
@click.option(
    '--dpi',
    type=int,
    default=300,
    help='DPI for raster output (default: 300)'
)
@click.option(
    '--title', '-t',
    default='P2MS Protocol Distribution Over Time',
    help='Plot title'
)
@click.option(
    '--log',
    is_flag=True,
    help='Use logarithmic Y-axis scale'
)
def protocols(
    database: str,
    output: str,
    bin_by: str,
    format: str,
    dpi: int,
    title: str,
    log: bool
):
    """Generate protocol distribution stacked bar chart.

    This command creates a visualisation showing how different protocols
    (Bitcoin Stamps, Counterparty, Omni, etc.) have created P2MS outputs
    over Bitcoin's history.

    Examples:

        \b
        # Basic usage (monthly bars)
        python -m visualisation.cli protocols -d p2ms_analysis_production.db

        \b
        # Yearly aggregation for cleaner view
        python -m visualisation.cli protocols -d p2ms_analysis_production.db \\
            --bin yearly

        \b
        # Save as SVG with custom title
        python -m visualisation.cli protocols -d p2ms_analysis_production.db \\
            --format svg --title "Bitcoin P2MS Protocols" \\
            --output output_data/plots/protocols.svg
    """
    try:
        # Extract data
        click.echo(f"Extracting protocol distribution from {database}...")
        df = get_protocol_distribution(database, bin_by=bin_by)

        click.echo(f"Found {len(df)} data points across {df['protocol'].nunique()} protocols")
        click.echo(f"Aggregated by: {bin_by}")

        # Generate plot
        click.echo(f"Generating stacked bar chart...")
        plot_protocol_distribution(
            df,
            output_path=output,
            title=title,
            format=format,
            dpi=dpi,
            log_scale=log
        )

        click.echo(click.style("✓ Success!", fg='green', bold=True))

    except FileNotFoundError as e:
        click.echo(click.style(f"Error: {e}", fg='red'), err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(click.style(f"Error: {e}", fg='red'), err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Unexpected error: {e}", fg='red'), err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('-d', '--database', required=True, type=click.Path(exists=True),
              help='Path to SQLite database')
@click.option('-o', '--output', default=str(PLOTS_DIR / 'spendability_percentage.png'),
              help='Output file path (default: output_data/plots/spendability_percentage.png)')
@click.option('--bin', 'bin_by', type=click.Choice(['monthly', 'yearly']),
              help='Aggregate data by time period (default: monthly)')
@click.option('-f', '--format', 'format', type=click.Choice(['png', 'svg', 'pdf']),
              default='png', help='Output format (default: png)')
@click.option('--dpi', default=300, type=int,
              help='DPI for raster output (default: 300)')
@click.option('-t', '--title', help='Plot title')
def spendability(database, output, bin_by, format, dpi, title):
    """Generate spendability percentage plot over time.

    This command creates a stacked area chart showing the percentage of
    P2MS outputs that are spendable vs unspendable over Bitcoin's history.

    Examples:

        \b
        # Basic usage (monthly aggregation)
        python -m visualisation.cli spendability -d p2ms_analysis_production.db

        \b
        # Yearly aggregation for cleaner view
        python -m visualisation.cli spendability -d p2ms_analysis_production.db \\
            --bin yearly

        \b
        # Save as SVG with custom title
        python -m visualisation.cli spendability -d p2ms_analysis_production.db \\
            --format svg --title "P2MS Spendability Analysis" \\
            --output output_data/plots/spendability.svg
    """
    try:
        click.echo(f"Loading spendability data from {database}...")
        df = get_spendability_distribution(database, bin_by=bin_by)

        if df.empty:
            click.echo(click.style("No spendability data found in database", fg='yellow'))
            sys.exit(1)

        click.echo(f"Generating spendability percentage plot...")
        plot_spendability_percentage(
            df,
            output_path=output,
            format=format,
            dpi=dpi,
            title=title
        )
        click.echo(click.style("✓ Spendability plot generated successfully", fg='green'))
    except FileNotFoundError as e:
        click.echo(click.style(f"Database file not found: {e}", fg='red'), err=True)
        sys.exit(1)
    except KeyError as e:
        click.echo(click.style(f"Block timestamp missing: {e}", fg='red'), err=True)
        click.echo(click.style("Run 'just build-block-times' to build complete dataset", fg='yellow'))
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Unexpected error: {e}", fg='red'), err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('-d', '--database', required=True, type=click.Path(exists=True),
              help='Path to SQLite database')
@click.option('-o', '--output', default=str(PLOTS_DIR / 'protocol_distribution.json'),
              help='Output JSON file path (default: output_data/plots/protocol_distribution.json)')
@click.option('--bin', 'bin_by', type=click.Choice(['monthly', 'yearly']),
              default='monthly', help='Aggregate data by time period (default: monthly)')
@click.option('-t', '--title', default='P2MS Protocol Distribution Over Time',
              help='Plot title')
@click.option('--log', is_flag=True, help='Use logarithmic Y-axis scale')
def export_protocols(database, output, bin_by, title, log):
    """Export protocol distribution data as Plotly JSON.

    This command generates Plotly-compatible JSON for protocol distribution
    over time, suitable for embedding in websites or documentation.

    Examples:

        \b
        # Basic export (monthly aggregation)
        python -m visualisation.cli export-protocols -d p2ms_analysis_production.db

        \b
        # Yearly aggregation with log scale
        python -m visualisation.cli export-protocols -d p2ms_analysis_production.db \\
            --bin yearly --log \\
            --output output_data/plots/protocols_yearly_log.json

        \b
        # Custom title
        python -m visualisation.cli export-protocols -d p2ms_analysis_production.db \\
            --title "Bitcoin P2MS Protocols" \\
            --output public/assets/blog/p2ms/protocols.json
    """
    try:
        click.echo(f"Loading protocol distribution from {database}...")
        df = get_protocol_distribution(database, bin_by=bin_by)

        if df.empty:
            click.echo(click.style("No protocol data found in database", fg='yellow'))
            sys.exit(1)

        click.echo(f"Exporting {len(df)} data points to Plotly JSON...")
        export_protocol_distribution_plotly(
            df,
            output_path=output,
            title=title,
            log_scale=log
        )
        click.echo(click.style("✓ Export complete!", fg='green'))
    except FileNotFoundError as e:
        click.echo(click.style(f"Database file not found: {e}", fg='red'), err=True)
        sys.exit(1)
    except KeyError as e:
        click.echo(click.style(f"Block timestamp missing: {e}", fg='red'), err=True)
        click.echo(click.style("Run 'just build-block-times' to build complete dataset", fg='yellow'))
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Unexpected error: {e}", fg='red'), err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option('-d', '--database', required=True, type=click.Path(exists=True),
              help='Path to SQLite database')
@click.option('-o', '--output', default=str(PLOTS_DIR / 'spendability.json'),
              help='Output JSON file path (default: output_data/plots/spendability.json)')
@click.option('--bin', 'bin_by', type=click.Choice(['monthly', 'yearly']),
              default='monthly', help='Aggregate data by time period (default: monthly)')
@click.option('-t', '--title', default='P2MS Output Spendability Over Time',
              help='Plot title')
def export_spendability(database, output, bin_by, title):
    """Export spendability data as Plotly JSON.

    This command generates Plotly-compatible JSON for spendability analysis
    over time, suitable for embedding in websites or documentation.

    Examples:

        \b
        # Basic export (monthly aggregation)
        python -m visualisation.cli export-spendability -d p2ms_analysis_production.db

        \b
        # Yearly aggregation
        python -m visualisation.cli export-spendability -d p2ms_analysis_production.db \\
            --bin yearly \\
            --output output_data/plots/spendability_yearly.json

        \b
        # For website
        python -m visualisation.cli export-spendability -d p2ms_analysis_production.db \\
            --title "P2MS Spendability Analysis" \\
            --output public/assets/blog/p2ms/spendability.json
    """
    try:
        click.echo(f"Loading spendability data from {database}...")
        df = get_spendability_distribution(database, bin_by=bin_by)

        if df.empty:
            click.echo(click.style("No spendability data found in database", fg='yellow'))
            sys.exit(1)

        click.echo(f"Exporting to Plotly JSON...")
        export_spendability_plotly(
            df,
            output_path=output,
            title=title
        )
        click.echo(click.style("✓ Export complete!", fg='green'))
    except FileNotFoundError as e:
        click.echo(click.style(f"Database file not found: {e}", fg='red'), err=True)
        sys.exit(1)
    except KeyError as e:
        click.echo(click.style(f"Block timestamp missing: {e}", fg='red'), err=True)
        click.echo(click.style("Run 'just build-block-times' to build complete dataset", fg='yellow'))
        sys.exit(1)
    except Exception as e:
        click.echo(click.style(f"Unexpected error: {e}", fg='red'), err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    cli()
