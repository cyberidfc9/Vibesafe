"""
Phase 18: Cloud Security
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory, ChecklistItem
from vibesafe.ui import ask_checklist

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    checklist = []

    items = [
        ("Cloud storage buckets (AWS S3, Supabase Storage) restrict public access (allowlist reads only, block public writes).", "Misconfigured storage bucket permissions allow public users to overwrite or read confidential files."),
        ("Cloud platform credentials/tokens are stored in dedicated secrets managers (Vercel Env, AWS Secrets Manager).", "Exposing cloud credentials in repository config files allows complete cloud account compromise."),
        ("Cloud security policies follow the principle of least privilege (IAM roles have limited access scopes).", "Broad IAM roles allow anyone who accesses the server to query, write or delete all cloud infrastructure.")
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
                title=f"Cloud Infrastructure Risk: {desc[:40]}...",
                severity=Severity.HIGH,
                phase=18,
                phase_name="Cloud Security",
                description=finding_desc,
                evidence="Guided Cloud Security Review",
                remediation="Ensure storage buckets are private, enable platform access logs, use env vars on Vercel/AWS instead of committing keys, and limit IAM roles.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            ))

    return PhaseResult(
        phase_number=18,
        phase_name="Cloud Security",
        phase_type=PhaseType.HYBRID,
        findings=findings,
        checklist=checklist,
        summary=f"Cloud security review completed. Found {len(findings)} recommendations.",
        duration_seconds=time.time() - start_time
    )
