"""
VibeSafe — External Tool Integrations Layer

Aggregates findings from CodeQL, Semgrep, Gitleaks, Trivy, and Nuclei.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from rich.console import Console

from vibesafe.models import Finding
from vibesafe.integrations import codeql, semgrep, gitleaks, trivy, nuclei

if TYPE_CHECKING:
    from vibesafe.config import VibesafeConfig
    from vibesafe.models import ScanResult

console = Console()

def run_all_integrations(config: VibesafeConfig, scan_result: ScanResult) -> list[Finding]:
    """Run all enabled and available external tools."""
    findings = []
    
    # 1. CodeQL
    if config.enable_integrations.get("codeql", True):
        try:
            start = time.time()
            console.print("  [blue]🔍 Running CodeQL CLI Integration...[/blue]")
            c_findings = codeql.run(config, scan_result)
            findings.extend(c_findings)
            console.print(f"  [green]✅ CodeQL scan finished in {time.time() - start:.1f}s (found {len(c_findings)} findings)[/green]")
        except Exception as e:
            console.print(f"  [red]❌ CodeQL integration failed: {e}[/red]")

    # 2. Semgrep
    if config.enable_integrations.get("semgrep", True):
        try:
            start = time.time()
            console.print("  [blue]🔍 Running Semgrep Integration...[/blue]")
            s_findings = semgrep.run(config, scan_result)
            findings.extend(s_findings)
            console.print(f"  [green]✅ Semgrep scan finished in {time.time() - start:.1f}s (found {len(s_findings)} findings)[/green]")
        except Exception as e:
            console.print(f"  [red]❌ Semgrep integration failed: {e}[/red]")

    # 3. Gitleaks
    if config.enable_integrations.get("gitleaks", True):
        try:
            start = time.time()
            console.print("  [blue]🔍 Running Gitleaks Integration...[/blue]")
            g_findings = gitleaks.run(config, scan_result)
            findings.extend(g_findings)
            console.print(f"  [green]✅ Gitleaks scan finished in {time.time() - start:.1f}s (found {len(g_findings)} findings)[/green]")
        except Exception as e:
            console.print(f"  [red]❌ Gitleaks integration failed: {e}[/red]")

    # 4. Trivy
    if config.enable_integrations.get("trivy", True):
        try:
            start = time.time()
            console.print("  [blue]🔍 Running Trivy Integration...[/blue]")
            t_findings = trivy.run(config, scan_result)
            findings.extend(t_findings)
            console.print(f"  [green]✅ Trivy scan finished in {time.time() - start:.1f}s (found {len(t_findings)} findings)[/green]")
        except Exception as e:
            console.print(f"  [red]❌ Trivy integration failed: {e}[/red]")

    # 5. Nuclei
    if config.enable_integrations.get("nuclei", True):
        try:
            start = time.time()
            console.print("  [blue]🔍 Running Nuclei Integration...[/blue]")
            n_findings = nuclei.run(config, scan_result)
            findings.extend(n_findings)
            console.print(f"  [green]✅ Nuclei scan finished in {time.time() - start:.1f}s (found {len(n_findings)} findings)[/green]")
        except Exception as e:
            console.print(f"  [red]❌ Nuclei integration failed: {e}[/red]")

    return findings
