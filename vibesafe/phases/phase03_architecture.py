"""
Phase 3: Architecture Review
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.ui import console

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    
    # Retrieve tech stack from previous phase
    stack = None
    if scan_result and scan_result.tech_stack:
        stack = scan_result.tech_stack

    # Generate ASCII architecture diagram
    fe = stack.framework if stack and stack.framework else "Frontend"
    be = stack.runtime if stack and stack.runtime else "Backend API"
    db = stack.database if stack and stack.database else "Database"
    auth = f" ({stack.auth})" if stack and stack.auth else ""
    pm = f" ({stack.payments})" if stack and stack.payments else ""
    st = f" ({stack.storage})" if stack and stack.storage else ""

    diagram = f"""
  ┌───────────────────────────────────────────────────────────┐
  │                        [bold]Web Browser[/bold]                       │
  └─────────────────────────────┬─────────────────────────────┘
                                │ (HTTPS Traffic)
                                ▼
  ┌───────────────────────────────────────────────────────────┐
  │         [bold]Frontend Server / CDN[/bold]: {fe:<23} │
  └─────────────────────────────┬─────────────────────────────┘
                                │ (API Calls / Page Requests)
                                ▼
  ┌───────────────────────────────────────────────────────────┐
  │         [bold]Backend / API Layer[/bold]: {be:<24}  │
  └──────────────┬──────────────┬──────────────┬──────────────┘
                 │              │              │
                 │ (Queries)    │ (Auth)       │ (External SDKs)
                 ▼              ▼              ▼
  ┌──────────────┴───────┐┌─────┴───────┐┌─────┴──────────────┐
  │      [bold]Database[/bold]        ││ [bold]Auth Server[/bold] ││ [bold]Third-Party APIs[/bold]   │
  │ {db:<20} ││{auth:<13}││{pm:<20}│
  └──────────────────────┘└─────────────┘│{st:<20}│
                                         └────────────────────┘
"""

    console.print("\n[bold cyan]📐 System Architecture Diagram[/bold cyan]")
    console.print(diagram)

    # Architectural Checks
    findings.append(Finding(
        title="Verify Web Application Firewall (WAF) Deployment",
        severity=Severity.INFO,
        phase=3,
        phase_name="Architecture Review",
        description="Verify if a WAF (like Cloudflare, Vercel WAF, AWS WAF) is deployed in front of the application.",
        evidence="Architecture Review Phase",
        remediation="Deploy Cloudflare or Vercel WAF to block common web attacks (SQLi, XSS, bots) before they reach the server.",
        owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
    ))

    if stack and not stack.auth:
        findings.append(Finding(
            title="Missing Authentication Layer",
            severity=Severity.HIGH,
            phase=3,
            phase_name="Architecture Review",
            description="The architecture lacks a detected authentication provider, meaning all routes might be exposed.",
            evidence="No auth library found in package.json/requirements.txt",
            remediation="Implement NextAuth, Clerk, Supabase Auth, or passport-js to secure routes.",
            owasp_category=OWASPCategory.A07_AUTH_FAILURES
        ))

    return PhaseResult(
        phase_number=3,
        phase_name="Architecture Review",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        summary="Rendered system architecture flow diagram and checked security boundaries.",
        duration_seconds=time.time() - start_time
    )
