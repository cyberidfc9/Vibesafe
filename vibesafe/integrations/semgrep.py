"""
VibeSafe — Semgrep Integration Wrapper
"""

from __future__ import annotations

import shutil
import subprocess
import json
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
    """Run Semgrep scan and convert JSON results to Findings."""
    findings = []
    
    # 1. Check if Semgrep is installed
    if not shutil.which("semgrep"):
        console.print("  [dim]ℹ️  Semgrep CLI not found on PATH. Skipping Semgrep integration.[/dim]")
        return findings

    project_root = Path(config.project_path).resolve()
    
    # 2. Run semgrep scan
    cmd = [
        "semgrep", "scan",
        "--config", "auto",
        "--json",
        "--quiet",
        str(project_root)
    ]
    
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,  # Semgrep returns non-zero if findings are found
            timeout=120
        )
        
        # Parse JSON
        if res.stdout:
            data = json.loads(res.stdout)
            results = data.get("results", [])
            for item in results:
                path = item.get("path")
                start = item.get("start", {})
                line_number = start.get("line")
                
                extra = item.get("extra", {})
                message = extra.get("message", "Semgrep security finding")
                metadata = extra.get("metadata", {})
                
                # Check for CWE
                cwe_raw = metadata.get("cwe")
                cwe_id = None
                if cwe_raw:
                    if isinstance(cwe_raw, list) and cwe_raw:
                        cwe_raw = cwe_raw[0]
                    # Format e.g., 'CWE-79: Cross-site Scripting'
                    if ":" in cwe_raw:
                        cwe_id = cwe_raw.split(":")[0].strip().upper()
                    else:
                        cwe_id = cwe_raw.strip().upper()
                
                # Extract OWASP
                owasp = get_cwe_owasp(cwe_id) if cwe_id else OWASPCategory.A05_SECURITY_MISCONFIGURATION
                
                # Title
                check_id = item.get("check_id", "semgrep-finding")
                title = check_id.split(".")[-1].replace("-", " ").title()
                
                # Severity
                semgrep_severity = extra.get("severity", "WARNING").upper()
                severity = Severity.MEDIUM
                if semgrep_severity == "ERROR":
                    severity = Severity.HIGH
                elif semgrep_severity == "INFO":
                    severity = Severity.LOW
                
                # Evidence
                evidence = extra.get("lines", "").strip()
                
                # Remediation / fix advice
                remediation = metadata.get("remediation", "Review Semgrep rules for fixing this vulnerability.")
                
                # Normalize relative path
                try:
                    rel_path = Path(path).relative_to(project_root)
                except ValueError:
                    rel_path = path

                findings.append(Finding(
                    title=f"Semgrep: {title}",
                    severity=severity,
                    phase=0,
                    phase_name="External Tool Integration",
                    description=message,
                    file_path=str(rel_path),
                    line_number=line_number,
                    evidence=evidence,
                    remediation=remediation,
                    owasp_category=owasp,
                    cwe_id=cwe_id,
                    exploitability_score=get_default_exploitability(cwe_id) if cwe_id else 5.0,
                    source_tool="semgrep"
                ))
                
    except subprocess.TimeoutExpired:
        console.print("  [dim]⚠️  Semgrep scan timed out[/dim]")
    except Exception as e:
        console.print(f"  [dim]⚠️  Semgrep integration error: {e}[/dim]")

    return findings
