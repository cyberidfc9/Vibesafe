"""
Phase 19: Logging & Monitoring
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory, ChecklistItem
from vibesafe.ui import ask_checklist

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    checklist = []

    items = [
        ("Application logs do not write sensitive parameters (passwords, auth tokens, credit cards, PII).", "Log statements print passwords or access tokens, exposing them in plaintext inside log management systems."),
        ("Security events (login failures, password updates, admin operations) are logged with audit trails.", "Lack of security logs makes post-incident analysis and detection of brute-force patterns impossible."),
        ("Real-time exception monitoring (e.g. Sentry, Bugsnag) is integrated to catch runtime crash issues.", "No monitoring system setup makes server errors or crashes invisible to administrators.")
    ]

    for desc, finding_desc in items:
        passed = None
        if not config.skip_guided:
            passed = ask_checklist(desc)
        
        checklist.append(ChecklistItem(description=desc, passed=passed))
        
        if passed is False:
            findings.append(Finding(
                title=f"Monitoring Deficiency: {desc[:40]}...",
                severity=Severity.MEDIUM,
                phase=19,
                phase_name="Logging & Monitoring",
                description=finding_desc,
                evidence="Guided Logging & Monitoring Review",
                remediation="Ensure sensitive request parameters are masked/scrubbed before logging, deploy logging middleware, and connect error tracking services like Sentry.",
                owasp_category=OWASPCategory.A09_LOGGING_FAILURES
            ))

    return PhaseResult(
        phase_number=19,
        phase_name="Logging & Monitoring",
        phase_type=PhaseType.HYBRID,
        findings=findings,
        checklist=checklist,
        summary=f"Logging and monitoring review completed. Discovered {len(findings)} recommendations.",
        duration_seconds=time.time() - start_time
    )
