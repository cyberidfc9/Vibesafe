"""
Phase 17: Performance & Resilience
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory, ChecklistItem
from vibesafe.ui import ask_checklist

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    checklist = []

    items = [
        ("Rate limiting is active on all public endpoints, preventing denial of service (DoS) and API abuse.", "No rate limiting protection leaves application endpoints vulnerable to resource exhaustion / denial of service."),
        ("Request body payload size limits are configured (prevents uploading gigabyte-sized payloads).", "Unrestricted body payload sizes can cause server RAM starvation or server crashes."),
        ("Response payload compression (GZIP, Brotli) is enabled for static assets and API payloads.", "Lack of payload compression wastes bandwidth and slows page load speeds.")
    ]

    for desc, finding_desc in items:
        passed = None
        if not config.skip_guided:
            passed = ask_checklist(desc)
        
        checklist.append(ChecklistItem(description=desc, passed=passed))
        
        if passed is False:
            findings.append(Finding(
                title=f"Resilience Gap: {desc[:40]}...",
                severity=Severity.MEDIUM,
                phase=17,
                phase_name="Performance & Resilience",
                description=finding_desc,
                evidence="Guided Performance & Resilience Review",
                remediation="Enable rate limiting middleware (e.g. express-rate-limit, Cloudflare Rate Limiting), set body size limits, and configure payload compression.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            ))

    return PhaseResult(
        phase_number=17,
        phase_name="Performance & Resilience",
        phase_type=PhaseType.HYBRID,
        findings=findings,
        checklist=checklist,
        summary=f"Performance and resilience review completed. Found {len(findings)} recommendations.",
        duration_seconds=time.time() - start_time
    )
