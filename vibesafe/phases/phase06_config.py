"""
Phase 6: Server Configuration Review
"""

import time
import httpx
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import find_files_by_name, read_file_safe
from vibesafe.ui import print_finding, print_passed_check, print_failed_check, print_info

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    passed_checks = []
    failed_checks = []

    # 1. Source Code Config Checks
    next_config = find_files_by_name(config, ["next.config.js", "next.config.mjs"])
    if next_config:
        content = read_file_safe(next_config[0]) or ""
        if "headers" not in content:
            finding = Finding(
                title="Missing Next.js Security Headers",
                severity=Severity.MEDIUM,
                phase=6,
                phase_name="Server Configuration",
                description="Next.js config file does not define custom security headers.",
                file_path=str(next_config[0].name),
                evidence=content[:100],
                remediation="Add security headers (CSP, HSTS, X-Frame-Options, etc.) using the headers() config option in next.config.js.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            )
            findings.append(finding)
            print_finding(finding)

    # 2. Live HTTP Scan (if URL is provided)
    if config.url:
        print_info(f"Connecting to live URL: {config.url} for server configuration checks...")
        try:
            # We use follow_redirects=True to follow login redirects
            with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
                res = client.get(config.url)
                headers = res.headers

                # Security Headers Checklist
                security_headers = {
                    "Content-Security-Policy": (
                        "CSP protects against Cross-Site Scripting (XSS) and data injection attacks.",
                        "Add a Content-Security-Policy header restricting source loading."
                    ),
                    "X-Frame-Options": (
                        "X-Frame-Options prevents clickjacking by restricting framing.",
                        "Add X-Frame-Options: DENY or SAMEORIGIN header."
                    ),
                    "Strict-Transport-Security": (
                        "HSTS enforces HTTPS connections, preventing SSL stripping.",
                        "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload."
                    ),
                    "X-Content-Type-Options": (
                        "Prevents browser from MIME-sniffing away from declared Content-Type.",
                        "Add X-Content-Type-Options: nosniff header."
                    ),
                    "Referrer-Policy": (
                        "Controls how much referrer info is passed with requests.",
                        "Add Referrer-Policy: strict-origin-when-cross-origin header."
                    ),
                    "Permissions-Policy": (
                        "Restricts access to browser features (camera, geolocation, etc.).",
                        "Add Permissions-Policy: camera=(), microphone=(), geolocation=()."
                    )
                }

                for h_name, (desc, fix) in security_headers.items():
                    # Case insensitive header lookup
                    if h_name.lower() in [h.lower() for h in headers.keys()]:
                        passed_checks.append(f"Header {h_name} is configured")
                        print_passed_check(f"Header: {h_name} = {headers.get(h_name)[:30]}...")
                    else:
                        failed_checks.append(f"Header {h_name} is missing")
                        print_failed_check(f"Header: {h_name} is missing")
                        
                        findings.append(Finding(
                            title=f"Missing Security Header: {h_name}",
                            severity=Severity.MEDIUM,
                            phase=6,
                            phase_name="Server Configuration",
                            description=desc,
                            evidence="HTTP Response Headers",
                            remediation=fix,
                            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
                        ))

                # Cookie Checks
                cookies = res.cookies
                if cookies:
                    for cookie in cookies:
                        # Check secure flag
                        if not cookie.secure:
                            findings.append(Finding(
                                title=f"Insecure Cookie Flag: {cookie.name}",
                                severity=Severity.HIGH,
                                phase=6,
                                phase_name="Server Configuration",
                                description=f"Cookie `{cookie.name}` is set without the Secure flag.",
                                evidence=f"Cookie: {cookie.name}",
                                remediation=f"Set the `Secure` attribute on the `{cookie.name}` cookie to ensure it is only transmitted over HTTPS.",
                                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
                            ))
                        # Check httponly flag
                        # Note: httpx doesn't always expose httponly directly on Cookie object,
                        # but we can look for it in Set-Cookie headers
                        set_cookie_headers = headers.get_list("set-cookie")
                        for sc in set_cookie_headers:
                            if cookie.name in sc and "httponly" not in sc.lower():
                                findings.append(Finding(
                                    title=f"Cookie Missing HttpOnly Flag: {cookie.name}",
                                    severity=Severity.HIGH,
                                    phase=6,
                                    phase_name="Server Configuration",
                                    description=f"Cookie `{cookie.name}` lacks HttpOnly attribute, making it accessible to client-side scripts.",
                                    evidence=f"Set-Cookie: {sc}",
                                    remediation=f"Set the `HttpOnly` attribute on the `{cookie.name}` cookie to prevent XSS-based access.",
                                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
                                ))

                # TLS / SSL check
                if config.url.startswith("https://"):
                    passed_checks.append("HTTPS is enabled")
                    print_passed_check("HTTPS is enabled")
                else:
                    failed_checks.append("HTTPS is not enabled")
                    print_failed_check("Using insecure HTTP protocol")
                    findings.append(Finding(
                        title="Insecure Protocol (HTTP)",
                        severity=Severity.HIGH,
                        phase=6,
                        phase_name="Server Configuration",
                        description="The site uses HTTP instead of HTTPS, exposing all traffic to interception.",
                        evidence=f"URL: {config.url}",
                        remediation="Redirect all HTTP traffic to HTTPS. Enable SSL/TLS certificate.",
                        owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
                    ))

        except Exception as e:
            failed_checks.append(f"Connection failed: {e}")
            print_failed_check(f"Could not connect to {config.url}: {e}")
            findings.append(Finding(
                title="Live Server Connection Failed",
                severity=Severity.LOW,
                phase=6,
                phase_name="Server Configuration",
                description=f"Failed to connect to the live URL: {e}",
                evidence=config.url,
                remediation="Check if the website is active and the URL is correct.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            ))

    return PhaseResult(
        phase_number=6,
        phase_name="Server Configuration",
        phase_type=PhaseType.HYBRID,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Configuration review completed. Found {len(findings)} config gaps.",
        duration_seconds=time.time() - start_time
    )
