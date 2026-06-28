"""
VibeSafe — CLI Entry Point

The main command-line interface for VibeSafe security scanner.

Usage:
    vibesafe scan <path> [--url URL] [--phase N] [--skip N] [--skip-guided] [--output DIR]
    vibesafe init
    vibesafe report <path>
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from vibesafe import __version__
from vibesafe.config import VibesafeConfig, load_config, generate_default_config
from vibesafe.engine import run_scan, run_single_phase
from vibesafe.ui import print_banner, print_error, print_success, print_info

app = typer.Typer(
    name="vibesafe",
    help="🛡️ VibeSafe — Security Testing for Vibe-Coded Websites",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()


@app.command()
def scan(
    path: str = typer.Argument(
        ...,
        help="Path to the project directory to scan",
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url", "-u",
        help="Live URL to test (e.g. https://mysite.com)",
    ),
    phase: Optional[int] = typer.Option(
        None,
        "--phase", "-p",
        help="Run only a specific phase (1-20)",
    ),
    skip: Optional[str] = typer.Option(
        None,
        "--skip", "-s",
        help="Comma-separated list of phases to skip (e.g. --skip 17,18)",
    ),
    skip_guided: bool = typer.Option(
        False,
        "--skip-guided",
        help="Skip all interactive/guided phases (run automated only)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output directory for reports (default: project directory)",
    ),
    report_format: Optional[str] = typer.Option(
        None,
        "--format", "-f",
        help="Report format: markdown, html, or both (default: both)",
    ),
):
    """
    🔍 Run a security scan on a vibe-coded project.

    Scans the project directory for security issues across 20 phases
    including SAST, dependency audit, config review, and more.

    Examples:
        vibesafe scan ./my-nextjs-app
        vibesafe scan ./my-app --url https://mysite.com
        vibesafe scan ./my-app --phase 4
        vibesafe scan ./my-app --skip-guided
    """
    # Resolve project path
    project_path = str(Path(path).resolve())

    if not os.path.isdir(project_path):
        print_error(f"Directory not found: {project_path}")
        raise typer.Exit(1)

    # Load config
    config = load_config(project_path, url)

    # Apply CLI overrides
    if skip:
        config.skip_phases = [int(p.strip()) for p in skip.split(",") if p.strip().isdigit()]
    if skip_guided:
        config.skip_guided = True
    if output:
        config.output_dir = output
    if report_format:
        if report_format == "both":
            config.report_formats = ["markdown", "html"]
        else:
            config.report_formats = [report_format]

    # Run scan
    try:
        if phase:
            scan_result = run_single_phase(phase, config)
        else:
            scan_result = run_scan(config)
    except KeyboardInterrupt:
        console.print("\n\n  [yellow]⚠️  Scan interrupted by user[/yellow]\n")
        raise typer.Exit(0)

    # Exit with non-zero if critical findings
    critical_count = scan_result.severity_counts.get(
        __import__("vibesafe.models", fromlist=["Severity"]).Severity.CRITICAL, 0
    )
    if critical_count > 0:
        raise typer.Exit(1)


@app.command()
def init():
    """
    📝 Create a .vibesafe.yml config file in the current directory.
    """
    config_path = Path(".vibesafe.yml")

    if config_path.exists():
        print_error(".vibesafe.yml already exists in this directory")
        raise typer.Exit(1)

    config_path.write_text(generate_default_config(), encoding="utf-8")
    print_success(f"Created .vibesafe.yml in {Path('.').resolve()}")
    print_info("Edit this file to customize your scan settings.")


@app.command()
def version():
    """
    📦 Show VibeSafe version.
    """
    console.print(f"  VibeSafe v{__version__}")


@app.command()
def phases():
    """
    📋 List all 20 security testing phases.
    """
    from rich.table import Table
    from rich import box
    from vibesafe.models import PHASE_REGISTRY, PhaseType

    print_banner()

    table = Table(
        title="📋 VibeSafe Security Testing Phases",
        box=box.ROUNDED,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("#", justify="center", min_width=4, style="cyan")
    table.add_column("Phase Name", min_width=32)
    table.add_column("Type", justify="center", min_width=12)
    table.add_column("Description", min_width=40)

    descriptions = {
        1: "Detect frameworks, databases, services, and dependencies",
        2: "Generate threat model based on detected attack surfaces",
        3: "Map system architecture and identify security gaps",
        4: "Scan source code for secrets, injections, and unsafe patterns",
        5: "Audit dependencies for known vulnerabilities",
        6: "Check HTTP headers, cookies, TLS, and server config",
        7: "Test login, sessions, password handling, and MFA",
        8: "Test access controls, IDOR, and privilege escalation",
        9: "Verify input validation across forms, APIs, and queries",
        10: "Review file upload security and storage",
        11: "Audit API routes for auth, validation, and exposure",
        12: "Check database security, hashing, and access controls",
        13: "Test business-specific logic flaws and edge cases",
        14: "Map findings to OWASP Top 10 categories",
        15: "Guided manual penetration testing checklist",
        16: "Scan live URL for exposed paths and vulnerabilities",
        17: "Check rate limiting, caching, and resilience",
        18: "Review cloud provider security configuration",
        19: "Verify logging, monitoring, and alerting setup",
        20: "Generate comprehensive security report",
    }

    type_labels = {
        PhaseType.AUTOMATED: "[green]⚡ Auto[/green]",
        PhaseType.GUIDED: "[yellow]👤 Guided[/yellow]",
        PhaseType.HYBRID: "[blue]🔄 Hybrid[/blue]",
    }

    for phase in PHASE_REGISTRY:
        table.add_row(
            str(phase["number"]),
            phase["name"],
            type_labels[phase["type"]],
            descriptions.get(phase["number"], ""),
        )

    console.print(table)
    console.print()
    console.print("  [dim]⚡ Auto = Fully automated  │  👤 Guided = Interactive checklist  │  🔄 Hybrid = Both[/dim]")
    console.print()


if __name__ == "__main__":
    app()
