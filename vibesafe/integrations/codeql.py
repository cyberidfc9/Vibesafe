"""
VibeSafe — CodeQL CLI Integration Wrapper
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
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
    """Create a CodeQL database, run analysis, parse SARIF results."""
    findings = []
    
    # 1. Check if CodeQL is installed
    if not shutil.which("codeql"):
        console.print("  [dim]ℹ️  CodeQL CLI not found on PATH. Skipping CodeQL integration.[/dim]")
        return findings

    # 2. Detect language based on codebase files
    root = Path(config.project_path).resolve()
    language = None
    
    if (root / "package.json").exists():
        language = "javascript"
    elif (root / "requirements.txt").exists() or (root / "setup.py").exists() or list(root.glob("**/*.py")):
        language = "python"
    elif (root / "go.mod").exists():
        language = "go"
    elif (root / "pom.xml").exists() or (root / "build.gradle").exists():
        language = "java"
    else:
        # Default fallback
        language = "javascript"

    # 3. Setup temporary folder for database and results
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "codeql-db"
        sarif_file = Path(tmpdir) / "results.sarif"
        
        # Build command for database creation
        create_cmd = [
            "codeql", "database", "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={config.project_path}",
            "--overwrite"
        ]
        
        try:
            # Create DB
            subprocess.run(
                create_cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300
            )
            
            # Analyze DB using extended security suite
            suite = f"{language}-security-extended.qls"
            analyze_cmd = [
                "codeql", "database", "analyze",
                str(db_path),
                suite,
                "--format=sarif-latest",
                f"--output={sarif_file}"
            ]
            
            subprocess.run(
                analyze_cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300
            )
            
            # Parse SARIF file
            if sarif_file.exists():
                findings = parse_sarif(sarif_file, root)
                
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            console.print(f"  [dim]⚠️  CodeQL run failed or timed out: {e}[/dim]")
        except Exception as e:
            console.print(f"  [dim]⚠️  CodeQL unexpected error: {e}[/dim]")

    return findings

def parse_sarif(sarif_file: Path, project_root: Path) -> list[Finding]:
    """Parse SARIF report file and extract Finding objects."""
    findings = []
    
    try:
        with open(sarif_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        runs = data.get("runs", [])
        for run in runs:
            # Build rules dictionary
            rules = {}
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rules[rule["id"]] = rule
                
            results = run.get("results", [])
            for res in results:
                rule_id = res.get("ruleId")
                rule = rules.get(rule_id, {})
                
                title = rule.get("name", rule_id)
                description = res.get("message", {}).get("text", rule.get("shortDescription", {}).get("text", "CodeQL finding"))
                
                # Retrieve severity
                codeql_severity = res.get("level", "warning")
                severity = Severity.MEDIUM
                if codeql_severity == "error":
                    severity = Severity.HIGH
                elif codeql_severity == "note":
                    severity = Severity.LOW
                
                # Retrieve CWE from rule tags
                cwe_id = None
                tags = rule.get("properties", {}).get("tags", [])
                for tag in tags:
                    if tag.startswith("external/cwe/cwe-"):
                        cwe_id = tag.split("/")[-1].upper()
                        break
                    elif tag.startswith("cwe/"):
                        cwe_id = f"CWE-{tag.split('/')[-1]}".upper()
                        break
                
                # Map OWASP category from CWE
                owasp = get_cwe_owasp(cwe_id) if cwe_id else OWASPCategory.A05_SECURITY_MISCONFIGURATION
                
                # Get file location
                locations = res.get("locations", [])
                file_path = None
                line_number = None
                evidence = ""
                
                if locations:
                    loc = locations[0]
                    physical = loc.get("physicalLocation", {})
                    artifact = physical.get("artifactLocation", {})
                    uri = artifact.get("uri", "")
                    
                    # Normalize file path
                    if uri:
                        file_path = uri
                        
                    region = physical.get("region", {})
                    line_number = region.get("startLine")
                    
                    # Retrieve matching source line if possible
                    if file_path and line_number:
                        try:
                            abs_path = project_root / file_path
                            if abs_path.exists():
                                lines = abs_path.read_text(encoding="utf-8", errors="replace").split("\n")
                                if 1 <= line_number <= len(lines):
                                    evidence = lines[line_number - 1].strip()
                        except Exception:
                            pass
                
                # Remediation advice
                remediation = rule.get("help", {}).get("text", "Review CodeQL security query documentation for fixing this flaw.")
                
                findings.append(Finding(
                    title=f"CodeQL: {title}",
                    severity=severity,
                    phase=0,
                    phase_name="External Tool Integration",
                    description=description,
                    file_path=file_path,
                    line_number=line_number,
                    evidence=evidence,
                    remediation=remediation,
                    owasp_category=owasp,
                    cwe_id=cwe_id,
                    exploitability_score=get_default_exploitability(cwe_id) if cwe_id else 5.0,
                    source_tool="codeql"
                ))
    except Exception as e:
        console.print(f"  [dim]⚠️  Error parsing CodeQL SARIF: {e}[/dim]")
        
    return findings
