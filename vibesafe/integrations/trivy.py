"""
VibeSafe — Trivy Integration Wrapper
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
    """Run Trivy scan (dependency & configuration) and convert to Findings."""
    findings = []
    
    # 1. Check if Trivy is installed
    if not shutil.which("trivy"):
        console.print("  [dim]ℹ️  Trivy CLI not found on PATH. Skipping Trivy integration.[/dim]")
        return findings

    project_root = Path(config.project_path).resolve()
    
    # 2. Run Trivy filesystem scan
    cmd = [
        "trivy", "fs",
        "--format", "json",
        "--quiet",
        str(project_root)
    ]
    
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=120
        )
        
        # Parse JSON
        if res.stdout:
            data = json.loads(res.stdout)
            results = data.get("Results", [])
            
            for result in results:
                target = result.get("Target", "")
                
                # Check for dependencies/vulnerabilities
                vulnerabilities = result.get("Vulnerabilities", [])
                for vuln in vulnerabilities:
                    vuln_id = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
                    pkg_name = vuln.get("PkgName", "unknown")
                    installed = vuln.get("InstalledVersion", "unknown")
                    fixed = vuln.get("FixedVersion", "N/A")
                    title = vuln.get("Title", f"Vulnerability in {pkg_name}")
                    description = vuln.get("Description", "")
                    
                    trivy_severity = vuln.get("Severity", "MEDIUM").upper()
                    severity = map_trivy_severity(trivy_severity)
                    
                    cwe_ids = vuln.get("CweIDs", [])
                    cwe_id = cwe_ids[0] if cwe_ids else "CWE-1104"  # Default unmaintained/outdated comp
                    
                    owasp = get_cwe_owasp(cwe_id) if cwe_id else OWASPCategory.A06_VULNERABLE_COMPONENTS
                    
                    # Target path relative to root
                    try:
                        rel_target = Path(target).relative_to(project_root)
                    except ValueError:
                        rel_target = target
                        
                    evidence = f"Dependency: {pkg_name}@{installed}\nFixed Version: {fixed}"
                    remediation = f"Update package '{pkg_name}' to version {fixed} or later to fix {vuln_id}."
                    
                    findings.append(Finding(
                        title=f"Trivy: {vuln_id} ({pkg_name})",
                        severity=severity,
                        phase=0,
                        phase_name="External Tool Integration",
                        description=f"{title}\n\n{description}",
                        file_path=str(rel_target),
                        evidence=evidence,
                        remediation=remediation,
                        owasp_category=owasp,
                        cwe_id=cwe_id,
                        exploitability_score=get_default_exploitability(cwe_id),
                        source_tool="trivy"
                    ))
                
                # Check for config misconfigurations
                misconfigs = result.get("Misconfigurations", [])
                for misconfig in misconfigs:
                    misconfig_id = misconfig.get("ID", "UNKNOWN")
                    title = misconfig.get("Title", "Configuration issue")
                    description = misconfig.get("Description", "")
                    msg = misconfig.get("Message", "")
                    resolution = misconfig.get("Resolution", "Fix config rule.")
                    
                    trivy_severity = misconfig.get("Severity", "MEDIUM").upper()
                    severity = map_trivy_severity(trivy_severity)
                    
                    cwe_id = "CWE-16"  # Configuration
                    owasp = OWASPCategory.A05_SECURITY_MISCONFIGURATION
                    
                    # Target path relative to root
                    try:
                        rel_target = Path(target).relative_to(project_root)
                    except ValueError:
                        rel_target = target
                        
                    findings.append(Finding(
                        title=f"Trivy: Config {misconfig_id}",
                        severity=severity,
                        phase=0,
                        phase_name="External Tool Integration",
                        description=f"{title}\n\n{description}\n\nDetail: {msg}",
                        file_path=str(rel_target),
                        remediation=resolution,
                        owasp_category=owasp,
                        cwe_id=cwe_id,
                        exploitability_score=5.0,
                        source_tool="trivy"
                    ))
                    
    except subprocess.TimeoutExpired:
        console.print("  [dim]⚠️  Trivy scan timed out[/dim]")
    except Exception as e:
        console.print(f"  [dim]⚠️  Trivy integration error: {e}[/dim]")

    return findings

def map_trivy_severity(trivy_severity: str) -> Severity:
    """Map Trivy severity level to VibeSafe Severity enum."""
    if trivy_severity == "CRITICAL":
        return Severity.CRITICAL
    elif trivy_severity == "HIGH":
        return Severity.HIGH
    elif trivy_severity == "MEDIUM":
        return Severity.MEDIUM
    elif trivy_severity == "LOW":
        return Severity.LOW
    return Severity.INFO
