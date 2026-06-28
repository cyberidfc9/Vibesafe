"""
Phase 7: Authentication Testing
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory, ChecklistItem
from vibesafe.ui import ask_checklist, print_checklist_item

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    checklist = []

    # Initialize checklist items
    items = [
        ("Password policy enforces strength requirements (min length, complex characters).", "Weak password policy allows easy-to-guess user passwords."),
        ("Rate limiting is active on login endpoints (blocks brute-force/credential stuffing).", "Brute-force attacks can guess passwords without rate limit blocking."),
        ("MFA (Multi-Factor Authentication) is supported or required for admin/elevated accounts.", "Lack of MFA on admin/elevated accounts exposes them to single-factor compromise."),
        ("Password reset flow does not leak user exist status or allow account enumeration.", "Password reset flow allows attackers to check if an email exists on the site."),
        ("Sessions properly time out after inactivity and logout invalidates the session token.", "Expired sessions are not cleaned up, allowing session hijackers to reuse them.")
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
                title=f"Authentication Gap: {desc[:40]}...",
                severity=Severity.HIGH,
                phase=7,
                phase_name="Authentication Testing",
                description=finding_desc,
                evidence="Guided Authentication Review",
                remediation="Implement robust authentication protections (rate limiting, strong password requirements, MFA, secure session management).",
                owasp_category=OWASPCategory.A07_AUTH_FAILURES
            ))

    return PhaseResult(
        phase_number=7,
        phase_name="Authentication Testing",
        phase_type=PhaseType.GUIDED,
        findings=findings,
        checklist=checklist,
        summary=f"Authentication guided checks complete. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
