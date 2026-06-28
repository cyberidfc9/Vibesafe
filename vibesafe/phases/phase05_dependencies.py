"""
Phase 5: Dependency Security
"""

import time
import subprocess
import json
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import find_files_by_name, read_json_file
from vibesafe.ui import print_finding

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []

    package_json_files = find_files_by_name(config, ["package.json"])
    
    # Try running npm audit if package.json exists
    if package_json_files:
        pkg_dir = package_json_files[0].parent
        
        # Check if lockfile exists
        lockfile_exists = (pkg_dir / "package-lock.json").exists() or (pkg_dir / "yarn.lock").exists() or (pkg_dir / "pnpm-lock.yaml").exists()
        
        if lockfile_exists:
            try:
                # Run npm audit --json
                # Use powershell or cmd on Windows
                proc = subprocess.run(
                    ["npm", "audit", "--json"],
                    cwd=str(pkg_dir),
                    capture_output=True,
                    text=True,
                    shell=True
                )
                
                # npm audit returns non-zero when vulns are found, so we check stdout
                if proc.stdout:
                    try:
                        audit_data = json.loads(proc.stdout)
                        
                        # Parse audit data based on npm audit format (v7+ or v6)
                        # In newer npm versions, audit_data has 'vulnerabilities' or 'metadata'
                        vulns = audit_data.get("vulnerabilities", {})
                        for pkg_name, details in vulns.items():
                            severity_str = details.get("severity", "medium").lower()
                            sev = Severity.MEDIUM
                            if severity_str == "critical":
                                sev = Severity.CRITICAL
                            elif severity_str == "high":
                                sev = Severity.HIGH
                            elif severity_str == "low":
                                sev = Severity.LOW

                            via_list = details.get("via", [])
                            via_desc = []
                            for via in via_list:
                                if isinstance(via, dict):
                                    via_desc.append(f"{via.get('title')} ({via.get('url')})")
                                else:
                                    via_desc.append(str(via))

                            finding = Finding(
                                title=f"Vulnerable Dependency: {pkg_name}",
                                severity=sev,
                                phase=5,
                                phase_name="Dependency Security",
                                description=f"Package `{pkg_name}` is vulnerable. Details: {', '.join(via_desc)}",
                                file_path="package.json",
                                evidence=f"Package: {pkg_name}@{details.get('range')}",
                                remediation=f"Run `npm audit fix` or upgrade `{pkg_name}` to a secure version.",
                                owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS
                            )
                            findings.append(finding)
                            print_finding(finding)

                    except json.JSONDecodeError:
                        pass
            except Exception:
                # npm not installed or command failed
                pass

        # Fallback / manual checks on known insecure or deprecated packages in package.json
        pkg_data = read_json_file(package_json_files[0])
        if pkg_data:
            dependencies = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
            
            # Common problematic packages
            insecure_packages = {
                "axios": ("<1.6.0", "Axios versions < 1.6.0 are vulnerable to SSRF and cookie leaks. Upgrade to axios@^1.6.0."),
                "lodash": ("<4.17.21", "Lodash < 4.17.21 is vulnerable to prototype pollution. Upgrade to lodash@^4.17.21."),
                "express": ("<4.19.2", "Express < 4.19.2 is vulnerable to open redirect and body-parser vulnerability. Upgrade to express@^4.19.2."),
                "jsonwebtoken": ("<9.0.0", "jsonwebtoken < 9.0.0 is vulnerable to key confusion attacks. Upgrade to jsonwebtoken@^9.0.0."),
                "nokogiri": ("*", "Check if Nokogiri is outdated (often has security CVEs)."),
            }

            for pkg, (ver_range, fix) in insecure_packages.items():
                if pkg in dependencies:
                    # To keep it simple, if package exists, alert user to review it
                    finding = Finding(
                        title=f"Review Third-Party Dependency: {pkg}",
                        severity=Severity.LOW,
                        phase=5,
                        phase_name="Dependency Security",
                        description=f"Project uses `{pkg}` dependency. Please ensure it is updated to its latest secure version.",
                        file_path="package.json",
                        evidence=f"Package: {pkg}@{dependencies.get(pkg)}",
                        remediation=fix,
                        owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS
                    )
                    findings.append(finding)
                    print_finding(finding)

    # Return results
    return PhaseResult(
        phase_number=5,
        phase_name="Dependency Security",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        summary=f"Dependency audit completed. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
