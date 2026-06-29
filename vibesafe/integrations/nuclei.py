"""
VibeSafe — Nuclei Integration Wrapper
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
    """Run Nuclei live network vulnerability scanning on target URL."""
    findings = []
    
    # 1. Check if Nuclei is installed
    if not shutil.which("nuclei"):
        console.print("  [dim]ℹ️  Nuclei CLI not found on PATH. Skipping Nuclei integration.[/dim]")
        return findings

    # 2. Check if a live target URL is configured
    if not config.url:
        console.print("  [dim]ℹ️  No live target URL provided (--url). Skipping Nuclei integration.[/dim]")
        return findings

    target_url = config.url
    
    # 3. Run Nuclei
    cmd = [
        "nuclei",
        "-u", target_url,
        "-t", "cves/",
        "-t", "exposures/",
        "-t", "misconfiguration/",
        "-jsonl",
        "-silent"
    ]
    
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=180
        )
        
        # Parse JSONL output
        if res.stdout:
            for line in res.stdout.split("\n"):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    template_id = item.get("template-id", "nuclei-finding")
                    
                    info = item.get("info", {})
                    name = info.get("name", template_id)
                    description = info.get("description", "Nuclei scanner discovery")
                    matched_at = item.get("matched-at", target_url)
                    
                    nuclei_severity = info.get("severity", "medium").lower()
                    severity = Severity.MEDIUM
                    if nuclei_severity == "critical":
                        severity = Severity.CRITICAL
                    elif nuclei_severity == "high":
                        severity = Severity.HIGH
                    elif nuclei_severity == "low":
                        severity = Severity.LOW
                    elif nuclei_severity == "info":
                        severity = Severity.INFO
                        
                    # Retrieve classification
                    classification = info.get("classification", {})
                    cwe_ids = classification.get("cwe-id", [])
                    cwe_id = None
                    if cwe_ids:
                        cwe_id = cwe_ids[0].upper() if isinstance(cwe_ids, list) else cwe_ids.upper()
                        
                    owasp = get_cwe_owasp(cwe_id) if cwe_id else OWASPCategory.A05_SECURITY_MISCONFIGURATION
                    
                    remediation = info.get("remediation", f"Review configuration/code to patch vulnerability rule '{template_id}'.")
                    
                    findings.append(Finding(
                        title=f"Nuclei: {name}",
                        severity=severity,
                        phase=0,
                        phase_name="External Tool Integration",
                        description=description,
                        file_path=matched_at,
                        evidence=f"Matched URL: {matched_at}\nTemplate ID: {template_id}",
                        remediation=remediation,
                        owasp_category=owasp,
                        cwe_id=cwe_id,
                        exploitability_score=get_default_exploitability(cwe_id) if cwe_id else 5.0,
                        source_tool="nuclei"
                    ))
                except (json.JSONDecodeError, ValueError):
                    continue
                    
    except subprocess.TimeoutExpired:
        console.print("  [dim]⚠️  Nuclei scan timed out[/dim]")
    except Exception as e:
        console.print(f"  [dim]⚠️  Nuclei integration error: {e}[/dim]")

    return findings
