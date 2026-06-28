"""
VibeSafe — Rich Terminal UI Components

Beautiful terminal output: banners, progress bars, finding panels,
summary tables, and the security score gauge.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import box

from vibesafe.models import Finding, PhaseResult, ScanResult, Severity, PhaseType

import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

console = Console()


# ─── Banner ──────────────────────────────────────────────────────────────────────

BANNER = r"""
[bold cyan]
 ██╗   ██╗██╗██████╗ ███████╗███████╗ █████╗ ███████╗███████╗
 ██║   ██║██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝
 ██║   ██║██║██████╔╝█████╗  ███████╗███████║█████╗  █████╗
 ╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════██║██╔══██║██╔══╝  ██╔══╝
  ╚████╔╝ ██║██████╔╝███████╗███████║██║  ██║██║     ███████╗
   ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝
[/bold cyan]
[dim]       Security Testing for Vibe-Coded Websites • v1.0.0[/dim]
"""


def print_banner():
    """Print the VibeSafe ASCII art banner."""
    console.print(BANNER)


def print_scan_target(project_path: str, url: Optional[str] = None):
    """Print what we're scanning."""
    console.print()
    console.print(f"  🔍 [bold]Scanning:[/bold] [cyan]{project_path}[/cyan]")
    if url:
        console.print(f"  🌐 [bold]Live URL:[/bold] [cyan]{url}[/cyan]")
    console.print()


# ─── Phase Headers ───────────────────────────────────────────────────────────────

def print_phase_header(phase_number: int, phase_name: str, phase_type: PhaseType):
    """Print a phase section header."""
    type_badge = {
        PhaseType.AUTOMATED: "[green]⚡ AUTO[/green]",
        PhaseType.GUIDED: "[yellow]👤 GUIDED[/yellow]",
        PhaseType.HYBRID: "[blue]🔄 HYBRID[/blue]",
    }[phase_type]

    console.print()
    console.print(Rule(
        f"[bold white] Phase {phase_number}/20 │ {phase_name} [/bold white] {type_badge}",
        style="cyan",
    ))


def print_phase_complete(result: PhaseResult):
    """Print phase completion status."""
    if result.skipped:
        console.print(f"  ⏭️  [dim]Skipped[/dim]")
        return

    status = result.status_emoji
    findings_text = ""
    if result.total_findings > 0:
        parts = []
        for sev in Severity:
            count = sum(1 for f in result.findings if f.severity == sev)
            if count > 0:
                parts.append(f"[{sev.color}]{sev.emoji} {count}[/{sev.color}]")
        findings_text = " │ ".join(parts)
    else:
        findings_text = "[green]No issues found[/green]"

    duration = f"[dim]{result.duration_seconds:.1f}s[/dim]"
    console.print(f"  {status}  {findings_text}  {duration}")

    if result.summary:
        console.print(f"  [dim]{result.summary}[/dim]")


# ─── Finding Display ─────────────────────────────────────────────────────────────

def print_finding(finding: Finding):
    """Print a single finding as a styled panel."""
    sev = finding.severity

    # Build content
    lines = []
    if finding.file_path:
        loc = f"{finding.file_path}"
        if finding.line_number:
            loc += f":{finding.line_number}"
        lines.append(f"[dim]📁 {loc}[/dim]")

    lines.append(f"\n{finding.description}")

    if finding.evidence:
        lines.append(f"\n[dim]Evidence:[/dim] [italic]{finding.evidence}[/italic]")

    if finding.remediation:
        lines.append(f"\n[green]💡 Fix:[/green] {finding.remediation}")

    if finding.owasp_category:
        lines.append(f"\n[dim]OWASP: {finding.owasp_category.value}[/dim]")

    if finding.cwe_id:
        lines.append(f"[dim]CWE: {finding.cwe_id}[/dim]")

    content = "\n".join(lines)

    panel = Panel(
        content,
        title=f"{sev.emoji} [{sev.color}]{sev.value.upper()}[/{sev.color}] │ {finding.title}",
        border_style=sev.color,
        padding=(0, 2),
    )
    console.print(panel)


def print_findings_summary(findings: list[Finding]):
    """Print all findings for a phase grouped by severity."""
    if not findings:
        return

    # Sort by severity (critical first)
    severity_order = list(Severity)
    sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity))

    for finding in sorted_findings:
        print_finding(finding)


# ─── Tech Stack Display ─────────────────────────────────────────────────────────

def print_tech_stack(stack_dict: dict):
    """Print detected tech stack as a table."""
    table = Table(
        title="🔍 Detected Tech Stack",
        box=box.ROUNDED,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Component", style="cyan", min_width=16)
    table.add_column("Technology", style="white")

    for key, value in stack_dict.items():
        table.add_row(key, str(value))

    console.print(table)


# ─── Checklist Display ──────────────────────────────────────────────────────────

def print_checklist_item(description: str, passed: Optional[bool] = None):
    """Print a checklist item with status."""
    if passed is None:
        icon = "⬜"
        style = "dim"
    elif passed:
        icon = "✅"
        style = "green"
    else:
        icon = "❌"
        style = "red"

    console.print(f"  {icon} [{style}]{description}[/{style}]")


def ask_checklist(description: str) -> Optional[bool]:
    """Ask user to verify a checklist item. Loops until a valid input is received."""
    console.print(f"\n  ⬜ [bold]{description}[/bold]")
    
    while True:
        console.print("    [dim](y=pass, n=fail, s=skip, q=skip remaining)[/dim]", end=" ")
        try:
            response = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if response in ("y", "yes", "pass", "p"):
            console.print(f"  ✅ [green]{description}[/green]")
            return True
        elif response in ("n", "no", "fail", "f"):
            console.print(f"  ❌ [red]{description}[/red]")
            return False
        elif response in ("s", "skip"):
            console.print(f"  ⏭️  [dim]Skipped: {description}[/dim]")
            return None
        elif response in ("q", "quit", "exit"):
            console.print("  ⏭️  [dim]Skipping remaining checks in this phase...[/dim]")
            # We raise a custom KeyboardInterrupt or return a special status.
            # To keep it simple, returning a special flag or None is enough,
            # but we can return False/None. Let's return "QUIT" token or None.
            # We can use "q" to skip the whole phase, let's return None and let the phase know.
            # To support "q" (skip remaining), returning "quit" string is a good idea.
            return "quit"
        else:
            console.print("    [red]⚠ Invalid input. Please type 'y' for pass, 'n' for fail, 's' to skip, or 'q' to quit phase checks.[/red]")


# ─── Final Report Display ───────────────────────────────────────────────────────

def print_score_gauge(score: int, grade: str, label: str):
    """Print the security score as a visual gauge."""
    # Color based on score
    if score >= 90:
        color = "green"
    elif score >= 70:
        color = "yellow"
    elif score >= 50:
        color = "dark_orange"
    else:
        color = "red"

    # Build gauge bar
    filled = int(score / 100 * 30)
    empty = 30 - filled
    bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"

    gauge_text = f"""
  ╔══════════════════════════════════════╗
  ║     SECURITY SCORE: [{color}]{score:>3}/100[/{color}]        ║
  ║     {bar}  ║
  ║            [{color}]{grade} — {label}[/{color}]             ║
  ╚══════════════════════════════════════╝
"""
    console.print(gauge_text)


def print_severity_table(scan_result: ScanResult):
    """Print a summary table of findings by severity."""
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Severity", justify="center", min_width=14)
    table.add_column("Count", justify="center", min_width=8)

    counts = scan_result.severity_counts
    for sev in Severity:
        count = counts[sev]
        style = sev.color if count > 0 else "dim"
        table.add_row(
            f"{sev.emoji} {sev.value.capitalize()}",
            f"[{style}]{count}[/{style}]",
        )

    table.add_row(
        "[bold]Total[/bold]",
        f"[bold]{len(scan_result.all_findings)}[/bold]",
    )

    console.print(table)


def print_phase_summary_table(scan_result: ScanResult):
    """Print a summary table of all phases and their results."""
    table = Table(
        title="📋 Phase Summary",
        box=box.ROUNDED,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("#", justify="center", min_width=4)
    table.add_column("Phase", min_width=30)
    table.add_column("Status", justify="center", min_width=8)
    table.add_column("Findings", justify="center", min_width=10)
    table.add_column("Time", justify="right", min_width=8)

    for pr in scan_result.phase_results:
        status = pr.status_emoji
        findings_str = str(pr.total_findings) if pr.total_findings > 0 else "[dim]0[/dim]"
        time_str = f"{pr.duration_seconds:.1f}s" if not pr.skipped else "[dim]—[/dim]"

        table.add_row(
            str(pr.phase_number),
            pr.phase_name,
            status,
            findings_str,
            time_str,
        )

    console.print(table)


def print_report_saved(paths: list[str]):
    """Print the saved report paths."""
    console.print()
    for path in paths:
        ext = path.rsplit(".", 1)[-1].upper()
        icon = "📄" if ext == "MD" else "📊"
        console.print(f"  {icon} Report saved: [bold cyan]{path}[/bold cyan]")
    console.print()


def print_owasp_coverage(coverage: dict[str, int]):
    """Print OWASP Top 10 coverage matrix."""
    table = Table(
        title="🛡️ OWASP Top 10 Coverage",
        box=box.ROUNDED,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Category", min_width=45)
    table.add_column("Findings", justify="center", min_width=10)
    table.add_column("Status", justify="center", min_width=8)

    for category, count in coverage.items():
        if count > 0:
            status = f"[red]⚠ {count} issue{'s' if count != 1 else ''}[/red]"
        else:
            status = "[green]✅ Clear[/green]"
        table.add_row(category, str(count), status)

    console.print(table)


# ─── Progress Spinner ────────────────────────────────────────────────────────────

def create_spinner(description: str = "Scanning...") -> Progress:
    """Create a Rich progress spinner."""
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    )


# ─── Misc ────────────────────────────────────────────────────────────────────────

def print_error(message: str):
    """Print an error message."""
    console.print(f"  [red]❌ Error:[/red] {message}")


def print_warning(message: str):
    """Print a warning message."""
    console.print(f"  [yellow]⚠️  Warning:[/yellow] {message}")


def print_info(message: str):
    """Print an info message."""
    console.print(f"  [blue]ℹ️  {message}[/blue]")


def print_success(message: str):
    """Print a success message."""
    console.print(f"  [green]✅ {message}[/green]")


def print_passed_check(message: str):
    """Print a passed check."""
    console.print(f"    [green]✓[/green] [dim]{message}[/dim]")


def print_failed_check(message: str):
    """Print a failed check."""
    console.print(f"    [red]✗[/red] {message}")
