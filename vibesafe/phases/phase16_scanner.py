"""
Phase 16: Automated Vulnerability Scan
"""

import time
import httpx
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.ui import print_finding, print_passed_check, print_failed_check, print_info

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    passed_checks = []
    failed_checks = []

    if config.url:
        print_info(f"Scanning {config.url} for exposed files, config backups, and debug routes...")

        # Paths to scan
        paths_to_check = {
            "/.env": ("Exposed Environment Config", "Env file containing database URLs, API secrets, and encryption keys is accessible publicly.", Severity.CRITICAL),
            "/.git/config": ("Exposed Git Repository", "Git repository config directory is exposed, allowing attackers to download source code.", Severity.CRITICAL),
            "/.git/HEAD": ("Exposed Git Repository", "Git HEAD file is exposed, indicating Git folder is public.", Severity.CRITICAL),
            "/robots.txt": ("Robots.txt check", "Read robots.txt to verify it doesn't expose sensitive admin or test directories.", Severity.INFO),
            "/admin": ("Admin login route", "Check if admin portal is accessible and review auth strength.", Severity.INFO),
            "/wp-config.php.bak": ("Exposed backup file", "Backup configuration file containing credentials is publicly accessible.", Severity.CRITICAL),
            "/package.json": ("Exposed package.json", "Exposes project dependencies and build script versions.", Severity.LOW),
        }

        try:
            with httpx.Client(timeout=5.0, follow_redirects=False, verify=False) as client:
                for path, (title, desc, sev) in paths_to_check.items():
                    target_url = config.url.rstrip("/") + path
                    try:
                        res = client.get(target_url)
                        
                        # A 200 OK response on sensitive files indicates they are public
                        if res.status_code == 200:
                            # Verify if it's not a generic HTML custom 404 page returning 200
                            is_html = "html" in res.headers.get("content-type", "").lower()
                            if path in [".env", ".git/config", ".git/HEAD"] and is_html:
                                # Likely a custom 404 page returning 200, skip it
                                continue

                            failed_checks.append(f"Exposed path: {path}")
                            print_failed_check(f"Exposed: {path} (HTTP {res.status_code})")
                            
                            findings.append(Finding(
                                title=title,
                                severity=sev,
                                phase=16,
                                phase_name="Automated Vulnerability Scan",
                                description=f"The URL endpoint `{target_url}` is publicly accessible and returned HTTP {res.status_code}. {desc}",
                                evidence=f"URL: {target_url}\nResponse length: {len(res.text)}",
                                remediation="Block public access to this path using web server configuration (Nginx/Apache), middleware, or Next.js redirects.",
                                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
                            ))
                        else:
                            passed_checks.append(f"Secure path: {path}")
                            print_passed_check(f"Blocked/Missing: {path} (HTTP {res.status_code})")
                    except httpx.RequestError:
                        pass
        except Exception as e:
            failed_checks.append(f"Vulnerability scan connection failed: {e}")

    return PhaseResult(
        phase_number=16,
        phase_name="Automated Vulnerability Scan",
        phase_type=PhaseType.HYBRID,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Automated URL scan completed. Found {len(findings)} exposed resources.",
        duration_seconds=time.time() - start_time
    )
