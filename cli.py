"""CLI interface for SecureAPI Analyzer.

Provides commands for running security scans and generating reports.

Usage:
    python cli.py analyze --target https://api.example.com
    python cli.py report --input results/scan.json --format html
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from src import __version__
from src.analyzer import Analyzer
from src.config import Config
from src.reporter import Reporter
from src.utils import ScanResult, normalize_url


console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="SecureAPI Analyzer")
def cli() -> None:
    """SecureAPI Analyzer - REST API Security Testing Tool.

    Automated testing for authentication, authorization, and injection
    vulnerabilities in REST APIs. Maps findings to OWASP API Security Top 10.
    """
    pass


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target API base URL (e.g., https://api.example.com)",
)
@click.option(
    "--config", "-c",
    default="configs/default.yaml",
    help="Path to YAML configuration file",
)
@click.option(
    "--spec", "-s",
    default=None,
    help="Path to OpenAPI/Swagger specification (JSON or YAML)",
)
@click.option(
    "--token",
    default=None,
    help="Bearer token for authenticated requests",
)
@click.option(
    "--suite",
    multiple=True,
    help="Run specific test suites (can be repeated). Options: auth_bypass, broken_access, rate_limiting, input_validation",
)
@click.option(
    "--output", "-o",
    default="results",
    help="Output directory for results",
)
@click.option(
    "--timeout",
    default=None,
    type=int,
    help="Request timeout in seconds (overrides config)",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress all output except errors",
)
def analyze(
    target: str,
    config: str,
    spec: Optional[str],
    token: Optional[str],
    suite: tuple[str, ...],
    output: str,
    timeout: Optional[int],
    verbose: bool,
    quiet: bool,
) -> None:
    """Run security analysis against a target API."""
    if not quiet:
        console.print(
            Panel(
                f"[bold]SecureAPI Analyzer[/bold] v{__version__}\n"
                f"Target: {target}",
                title="Security Scan",
                border_style="blue",
            )
        )

    # Load configuration
    config_path = Path(config)
    if config_path.exists():
        cfg = Config.from_yaml(config)
        if verbose and not quiet:
            console.print(f"[dim]Loaded config from {config}[/dim]")
    else:
        cfg = Config()
        if verbose and not quiet:
            console.print("[dim]Using default configuration[/dim]")

    # Apply CLI overrides
    cfg.merge_cli_args(
        target=target,
        token=token,
        spec=spec,
        timeout=timeout,
        output_dir=output,
    )

    # Determine suites
    suites_list = list(suite) if suite else None
    if suites_list and not quiet:
        console.print(f"[dim]Suites: {', '.join(suites_list)}[/dim]")
    elif not quiet:
        console.print("[dim]Suites: all enabled[/dim]")

    console.print()

    # Run the scan
    analyzer = Analyzer(cfg)
    try:
        results = asyncio.run(analyzer.run(suites=suites_list))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Scan failed: {exc}[/red]")
        if verbose:
            console.print_exception()
        sys.exit(1)

    # Display results
    if not quiet:
        _display_results(results, verbose)

    # Save results
    try:
        result_path = analyzer.save_results(output)
        if not quiet:
            console.print(f"\n[green]Results saved to: {result_path}[/green]")
    except Exception as exc:
        console.print(f"[red]Failed to save results: {exc}[/red]")

    # Summary
    summary = analyzer.get_summary()
    if not quiet:
        _display_summary(summary)

    # Exit with non-zero code if critical/high findings exist
    if summary["findings"]["critical"] > 0 or summary["findings"]["high"] > 0:
        sys.exit(2)


@cli.command()
@click.option(
    "--input", "-i",
    "input_path",
    required=True,
    help="Path to saved scan results JSON file",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["json", "html", "markdown", "md"]),
    default="html",
    help="Report output format",
)
@click.option(
    "--output", "-o",
    default=None,
    help="Output file path (auto-generated if not specified)",
)
def report(
    input_path: str,
    output_format: str,
    output: Optional[str],
) -> None:
    """Generate a report from saved scan results."""
    path = Path(input_path)
    if not path.exists():
        console.print(f"[red]Results file not found: {input_path}[/red]")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    # Reconstruct ScanResult objects from saved data
    target = data.get("summary", {}).get("target", "unknown")
    results: list[ScanResult] = []

    for result_data in data.get("results", []):
        sr = ScanResult(
            target=target,
            suite_name=result_data.get("suite_name", "unknown"),
            endpoints_tested=result_data.get("endpoints_tested", 0),
        )
        # Reconstruct findings (simplified - uses dict representation)
        from src.utils import Finding
        for finding_data in result_data.get("findings", []):
            sr.findings.append(
                Finding(
                    title=finding_data.get("title", ""),
                    severity=finding_data.get("severity", "INFO"),
                    owasp_category=finding_data.get("owasp_category", ""),
                    description=finding_data.get("description", ""),
                    endpoint=finding_data.get("endpoint", ""),
                    method=finding_data.get("method", "GET"),
                    evidence=finding_data.get("evidence", ""),
                    remediation=finding_data.get("remediation", ""),
                    cvss_score=finding_data.get("cvss_score", 0.0),
                    response_status=finding_data.get("response_status"),
                    response_snippet=finding_data.get("response_snippet", ""),
                )
            )
        results.append(sr)

    reporter = Reporter(results, target)

    # Determine output path
    if not output:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        ext = "html" if output_format == "html" else ("md" if output_format in ("markdown", "md") else "json")
        output = f"reports/report_{timestamp}.{ext}"

    # Generate report
    if output_format == "html":
        report_path = reporter.generate_html(output)
    elif output_format in ("markdown", "md"):
        report_path = reporter.generate_markdown(output)
    else:
        report_path = reporter.generate_json(output)

    console.print(f"[green]Report generated: {report_path}[/green]")


def _display_results(results: list[ScanResult], verbose: bool) -> None:
    """Display scan results in the terminal."""
    severity_styles = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }

    for result in results:
        suite_label = result.suite_name.upper().replace("_", " ")
        console.print(f"[bold cyan][{suite_label}][/bold cyan]", end=" ")
        console.print(
            f"Tested {result.endpoints_tested} endpoints, "
            f"found {len(result.findings)} issues "
            f"({result.duration:.1f}s)"
        )

        for finding in result.findings:
            style = severity_styles.get(finding.severity, "dim")
            console.print(f"  [{style}][{finding.severity}][/{style}] {finding.title}")
            if verbose:
                console.print(f"    [dim]{finding.endpoint}[/dim]")
                if finding.evidence:
                    console.print(f"    [dim]Evidence: {finding.evidence}[/dim]")

        console.print()


def _display_summary(summary: dict) -> None:
    """Display scan summary table."""
    console.print()
    table = Table(title="Scan Summary", show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Target", summary["target"])
    table.add_row("Suites Executed", str(summary["suites_executed"]))
    table.add_row("Endpoints Tested", str(summary["endpoints_tested"]))
    table.add_row("Duration", f"{summary['total_duration_seconds']}s")
    table.add_row("Critical", f"[bold red]{summary['findings']['critical']}[/bold red]")
    table.add_row("High", f"[red]{summary['findings']['high']}[/red]")
    table.add_row("Medium", f"[yellow]{summary['findings']['medium']}[/yellow]")
    table.add_row("Low", f"[blue]{summary['findings']['low']}[/blue]")
    table.add_row("Total Findings", str(summary["findings"]["total"]))

    console.print(table)


if __name__ == "__main__":
    cli()
