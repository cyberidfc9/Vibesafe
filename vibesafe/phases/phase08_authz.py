"""
Phase 8: Authorization Testing
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory, ChecklistItem
from vibesafe.ui import ask_checklist

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    checklist = []

    items = [
        ("API routes check request ownership (e.g., verifying user A cannot access user B's resource ID).", "Potential IDOR / Broken Object Level Authorization (BOLA) exposing data."),
        ("Admin actions require server-side role check (verifying user roles, not just hidden buttons).", "Privilege escalation allows standard users to perform admin API actions."),
        ("Static files or uploads containing sensitive data are restricted behind authorization filters.", "Sensitive uploads are publicly accessible to anyone with the URL."),
        ("API keys, tokens, or JWTs have scoped permissions restricted to least privilege.", "Over-privileged tokens allow broad API access if leaked.")
    ]

    for desc, finding_desc in items:
        passed = None
        if not config.skip_guided:
            passed = ask_checklist(desc)
            if passed == "quit":
                break
        
        checklist.append(ChecklistItem(description=desc, passed=passed))
        
        if passed is False:
            findings.append(Finding(
                title=f"Authorization Gap: {desc[:40]}...",
                severity=Severity.HIGH,
                phase=8,
                phase_name="Authorization Testing",
                description=finding_desc,
                evidence="Guided Authorization Review",
                remediation="Implement middleware or server-side checks verifying both authentication (identity) and authorization (ownership/roles) for all requests.",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
            ))

    return PhaseResult(
        phase_number=8,
        phase_name="Authorization Testing",
        phase_type=PhaseType.GUIDED,
        findings=findings,
        checklist=checklist,
        summary=f"Authorization guided checks complete. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
