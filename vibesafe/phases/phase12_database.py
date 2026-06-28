"""
Phase 12: Database Security
"""

import time
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory, ChecklistItem
from vibesafe.utils import find_files_by_name, read_file_safe
from vibesafe.ui import ask_checklist, print_finding

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    checklist = []

    # 1. Automated Prisma / Schema checks
    prisma_schemas = find_files_by_name(config, ["schema.prisma"])
    if prisma_schemas:
        content = read_file_safe(prisma_schemas[0]) or ""
        # Check if database has direct postgres url inside the schema instead of env var
        if 'url' in content and 'env("' not in content:
            finding = Finding(
                title="Hardcoded Database URL in Schema",
                severity=Severity.CRITICAL,
                phase=12,
                phase_name="Database Security",
                description="Database connection URL is hardcoded directly inside your schema file rather than using an env() reference.",
                file_path=str(prisma_schemas[0].name),
                evidence="datasource db { url = \"postgresql://...\" }",
                remediation="Replace the hardcoded connection string with `url = env(\"DATABASE_URL\")`.",
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
            )
            findings.append(finding)
            print_finding(finding)

    # 2. Checklist items
    items = [
        ("Passwords are cryptographically hashed on write using a strong algorithm (bcrypt, argon2, scrypt).", "Passwords stored in database are either unhashed (plain-text) or weakly hashed (md5, sha256)."),
        ("Database accounts use the principle of least privilege (app client doesn't connect as superuser/root).", "Over-privileged database account allows complete DB takeover if app has SQLi."),
        ("Supabase Row-Level Security (RLS) is enabled on all tables (if using Supabase).", "Disabled RLS allows any client with public keys to query all table rows directly."),
        ("Database backups are scheduled periodically, encrypted, and isolated offsite.", "No database backups exist, risking complete data loss under ransomware or server failure."),
        ("Audit logging is configured to track critical operations (e.g. data deletions, exports).", "No tracking for database administration tasks, making forensics impossible.")
    ]

    for desc, finding_desc in items:
        passed = None
        if not config.skip_guided:
            passed = ask_checklist(desc)
        
        checklist.append(ChecklistItem(description=desc, passed=passed))
        
        if passed is False:
            findings.append(Finding(
                title=f"Database Security Gap: {desc[:40]}...",
                severity=Severity.HIGH,
                phase=12,
                phase_name="Database Security",
                description=finding_desc,
                evidence="Guided Database Security Review",
                remediation="Enable RLS on tables, secure connection strings in env vars, run scheduled encrypted backups, and hash user passwords with bcrypt.",
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
            ))

    return PhaseResult(
        phase_number=12,
        phase_name="Database Security",
        phase_type=PhaseType.HYBRID,
        findings=findings,
        checklist=checklist,
        summary=f"Database security checks completed. Discovered {len(findings)} potential gaps.",
        duration_seconds=time.time() - start_time
    )
