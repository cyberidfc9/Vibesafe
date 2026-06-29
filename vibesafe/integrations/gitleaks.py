"""
VibeSafe — Gitleaks Integration Wrapper
"""

from __future__ import annotations

import shutil
import subprocess
import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from rich.console import Console

from vibesafe.models import Finding, Severity, OWASPCategory
from vibesafe.cwe_database import get_cwe_owasp, get_default_exploitability

if TYPE_CHECKING:
    from vibesafe.config import VibesafeConfig
    from vibesafe.models import ScanResult

console = Console()

def run(config: VibesafeConfig, scan_result: ScanResult) -> list[Finding]:
    """Run Gitleaks secret detection and convert JSON results to Findings."""
    findings = []
    
    # 1. Check if Gitleaks is installed
    if not shutil.which("gitleaks"):
        console.print("  [dim]ℹ️  Gitleaks CLI not found on PATH. Skipping Gitleaks integration.[/dim]")
        return findings

    # Check if this is a Git repository (Gitleaks needs Git unless in --no-git mode)
    project_root = Path(config.project_path).resolve()
    is_git = (project_root / ".git").is_dir()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        report_file = Path(tmpdir) / "gitleaks-report.json"
        
        cmd = [
            "gitleaks", "detect",
            "--source", str(project_root),
            "--report-format", "json",
            "--report-path", str(report_file),
            "--no-banner"
        ]
        
        if not is_git:
            # Run in filesystem mode if it's not a git repository
            cmd.append("--no-git")
            
        try:
            # Gitleaks exit codes: 0 = no leaks, 1 = leaks found, 126/others = error
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=60
            )
            
            # Gitleaks returns exit code 1 if secrets were found, so we check report file
            if report_file.exists() and report_file.stat().st_size > 0:
                with open(report_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                for item in data:
                    file_path = item.get("File")
                    line_number = item.get("StartLine")
                    rule_id = item.get("RuleID", "exposed-secret")
                    description = item.get("Description", "Potential exposed secret or API credential")
                    match = item.get("Match", "")
                    commit_sha = item.get("Commit", "")
                    
                    evidence = f"Match: {match}"
                    if commit_sha:
                        evidence += f" (in Commit: {commit_sha[:8]})"
                        
                    remediation = (
                        "1. Revoke the exposed API key or credential immediately.\n"
                        "2. Remove the secret from Git history (e.g., using git-filter-repo).\n"
                        "3. Add the containing file to your `.gitignore` or use environment variables."
                    )
                    
                    # Secrets fall under CWE-798 or CWE-321
                    cwe_id = "CWE-798"
                    owasp = OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
                    
                    findings.append(Finding(
                        title=f"Gitleaks: {rule_id.replace('-', ' ').title()}",
                        severity=Severity.CRITICAL,  # Exposed credentials are always critical
                        phase=0,
                        phase_name="External Tool Integration",
                        description=description,
                        file_path=file_path,
                        line_number=line_number,
                        evidence=evidence,
                        remediation=remediation,
                        owasp_category=owasp,
                        cwe_id=cwe_id,
                        exploitability_score=9.5,  # Secrets are highly exploitable
                        source_tool="gitleaks"
                    ))
                    
        except subprocess.TimeoutExpired:
            console.print("  [dim]⚠️  Gitleaks scan timed out[/dim]")
        except Exception as e:
            console.print(f"  [dim]⚠️  Gitleaks integration error: {e}[/dim]")

    return findings
