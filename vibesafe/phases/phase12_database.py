"""
Phase 12: Database Security
"""

import time
import re
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import find_files_by_name, read_file_safe, walk_source_files
from vibesafe.ui import print_finding, print_passed_check, print_failed_check, print_info

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    passed_checks = []
    failed_checks = []

    # 1. Automated Prisma / Schema checks (Hardcoded URL check)
    prisma_schemas = find_files_by_name(config, ["schema.prisma"])
    if prisma_schemas:
        content = read_file_safe(prisma_schemas[0]) or ""
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

    # 2. Automated DB & SQL Scan
    has_db_code = False
    db_indicator_pat = re.compile(r"prisma|sequelize|mongoose|mongodb|postgresql|sqlite|mysql|sqlalchemy|django\.db|pymongo|pg-promise|knex", re.IGNORECASE)

    has_hashing = False
    hashing_pat = re.compile(r"bcrypt|argon2|scrypt|pbkdf2|make_password|generate_password_hash|django\.contrib\.auth\.hashers", re.IGNORECASE)

    raw_sql_injections = []
    raw_sql_pat = re.compile(
        r"\.query\(\s*[`'\"]SELECT.*?\$\{.*?\}\s*[`'\"]\)"
        r"|\.query\(\s*[`'\"]SELECT.*\+\s*\w+"
        r"|\.execute\(\s*f[`'\"]SELECT.*?\{.*?\}\s*[`'\"]\)"
        r"|\.execute\(\s*[`'\"]SELECT.*?%\s*\w+"
        r"|db\.raw\(\s*[`'\"]SELECT.*?\$\{.*?\}\s*[`'\"]\)"
        r"|db\.raw\(\s*[`'\"]SELECT.*\+\s*\w+",
        re.IGNORECASE
    )

    has_orm = False
    orm_pat = re.compile(r"PrismaClient|Sequelize|Mongoose|typeorm|SQLAlchemy|models\.Model|db\.define", re.IGNORECASE)

    hardcoded_conn_strings = []
    conn_string_pat = re.compile(r"\b(postgresql|mongodb|mongodb\+srv|mysql|redis)://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_-]+")

    has_supabase_rls = False
    supabase_rls_pat = re.compile(r"enable\s+row\s+level\s+security|enable\s+rls|alter\s+table.*enable\s+rls", re.IGNORECASE)
    has_supabase = False

    # Scan source files
    source_files = list(walk_source_files(config))
    for filepath in source_files:
        if "vibesafe" in filepath.parts:
            continue
        content = read_file_safe(filepath)
        if not content:
            continue

        # Check if project uses database at all
        if not has_db_code and db_indicator_pat.search(content):
            has_db_code = True

        if "supabase" in content.lower():
            has_supabase = True
            if supabase_rls_pat.search(content):
                has_supabase_rls = True

        if not has_hashing and hashing_pat.search(content):
            has_hashing = True
        if not has_orm and orm_pat.search(content):
            has_orm = True

        # Check for hardcoded connection strings in non-config/non-env source files
        if filepath.suffix in [".js", ".ts", ".py", ".go", ".php", ".rb"]:
            matches = conn_string_pat.findall(content)
            if matches:
                hardcoded_conn_strings.append((filepath.name, matches[0]))

            # Check for potential raw SQL injections
            sql_matches = raw_sql_pat.findall(content)
            if sql_matches:
                raw_sql_injections.append((filepath.name, sql_matches[0]))

    # Skip database findings if project does not seem to connect to a database
    if not has_db_code:
        print_info("No database connection or model libraries detected in source code. Skipping DB alerts.")
        return PhaseResult(
            phase_number=12,
            phase_name="Database Security",
            phase_type=PhaseType.AUTOMATED,
            findings=[],
            passed_checks=["No database integration detected"],
            summary="No database integration detected. Found 0 issues.",
            duration_seconds=time.time() - start_time
        )

    # 1. Hashing Check
    if has_hashing:
        passed_checks.append("Secure password hashing found")
        print_passed_check("Password Hashing: Password hashing algorithms detected in DB modules.")
    else:
        failed_checks.append("No password hashing detected in database models")
        print_failed_check("Password Hashing: No secure cryptographic password hashing imports found.")
        findings.append(Finding(
            title="Missing DB User Password Hashing",
            severity=Severity.CRITICAL,
            phase=12,
            phase_name="Database Security",
            description="The application uses database connections but password hashing (bcrypt, argon2, pbkdf2) is missing from the database logic, implying plaintext storage or weak MD5/SHA hashes.",
            evidence="No hashing libraries found in DB code.",
            remediation="Never store raw passwords. Enforce hashing (e.g. bcrypt/argon2) before running insert queries.",
            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
        ))

    # 2. Raw SQL Injection
    if raw_sql_injections:
        for filename, evidence in raw_sql_injections[:3]:
            failed_checks.append(f"SQL Injection risk in {filename}")
            print_failed_check(f"SQL Injection: Potential string interpolation in raw query inside {filename}.")
            findings.append(Finding(
                title="Potential SQL Injection Vulnerability",
                severity=Severity.CRITICAL,
                phase=12,
                phase_name="Database Security",
                description="Potential SQL Injection vulnerability detected. The code interpolates dynamic variables or concatenates strings directly into raw SQL queries.",
                file_path=filename,
                evidence=evidence,
                remediation="Replace raw string interpolation/concatenation with parameterized queries or ORM placeholders (e.g. using `?` or `$1` bindings).",
                owasp_category=OWASPCategory.A03_INJECTION
            ))
    else:
        passed_checks.append("No obvious raw SQL injection patterns found")
        print_passed_check("SQL Injection: Parameterized query style or ORM structures used.")

    # 3. Connection Strings
    if hardcoded_conn_strings:
        for filename, conn in hardcoded_conn_strings[:2]:
            failed_checks.append(f"Hardcoded DB credentials in {filename}")
            print_failed_check(f"DB Credentials: Connection credentials hardcoded inside {filename}.")
            findings.append(Finding(
                title="Exposed Database Credentials in Code",
                severity=Severity.CRITICAL,
                phase=12,
                phase_name="Database Security",
                description="Database connection strings with credentials were found hardcoded inside source files.",
                file_path=filename,
                evidence="db_url = 'postgresql://user:pass@host...'",
                remediation="Move connection strings out of the code and into server environment variables (`.env`).",
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
            ))
    else:
        passed_checks.append("No hardcoded connection strings found in source code files")
        print_passed_check("DB Credentials: No hardcoded credentials detected in source files.")

    # 4. ORM Usage Check
    if has_orm:
        passed_checks.append("Secure ORM framework is utilized")
        print_passed_check("ORM Usage: Code uses an ORM which provides default SQL injection safety.")
    else:
        passed_checks.append("No ORM utilized (Optional)")
        print_info("ORM Usage: Project executes raw database queries (No ORM imports detected).")

    # 5. Supabase RLS Check
    if has_supabase:
        if has_supabase_rls:
            passed_checks.append("Supabase RLS is configured")
            print_passed_check("Supabase RLS: Row-Level Security configuration found.")
        else:
            failed_checks.append("Supabase RLS not configured")
            print_failed_check("Supabase RLS: RLS configuration missing from database rules.")
            findings.append(Finding(
                title="Supabase Row-Level Security (RLS) Disabled",
                severity=Severity.HIGH,
                phase=12,
                phase_name="Database Security",
                description="Supabase is detected in the application, but no SQL statements or configs enabling RLS (`alter table enable rls`) were found.",
                evidence="Supabase references found, but RLS setup is absent.",
                remediation="Ensure Row-Level Security (RLS) is enabled on all tables in Supabase to restrict access to authenticated clients only.",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
            ))

    return PhaseResult(
        phase_number=12,
        phase_name="Database Security",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Database security checks completed. Discovered {len(findings)} potential gaps.",
        duration_seconds=time.time() - start_time
    )
