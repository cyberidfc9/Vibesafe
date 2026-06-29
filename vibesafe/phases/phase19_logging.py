"""
Phase 19: Logging & Monitoring (Automated Scanner)
"""

import time
import re
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import walk_source_files, read_file_safe
from vibesafe.ui import print_finding, print_passed_check, print_failed_check, print_info

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    passed_checks = []
    failed_checks = []

    # Flags for each control
    sensitive_log_findings = []
    has_error_monitoring = False
    has_structured_logging = False
    has_audit_trail = False

    # ── Pattern Definitions ───────────────────────────────────────────────
    # 1. Sensitive data in logs (critical check)
    sensitive_log_pat = re.compile(
        r"(console\.log|console\.info|console\.warn|console\.error|logger\.\w+|log\.\w+|print|logging\.\w+)"
        r"\s*\(.*?"
        r"(password|token|secret|api_key|apikey|credit.?card|ssn|private.?key|auth.?token|access.?token|refresh.?token|credentials)"
        r".*?\)",
        re.IGNORECASE
    )

    # 2. Error monitoring services
    error_monitoring_pat = re.compile(
        r"@sentry/node|@sentry/react|@sentry/browser|sentry-sdk|sentry_sdk|Sentry\.init|"
        r"bugsnag|Bugsnag|logrocket|LogRocket|datadog|newrelic|"
        r"@datadog/browser-rum|rollbar|Rollbar|airbrake|honeybadger",
        re.IGNORECASE
    )

    # 3. Structured logging libraries
    structured_logging_pat = re.compile(
        r"winston|pino|bunyan|morgan|log4js|"
        r"logging\.basicConfig|logging\.getLogger|loguru|structlog",
        re.IGNORECASE
    )

    # 4. Audit trail patterns
    audit_pat = re.compile(
        r"audit|auditlog|audit_log|activity_log|ActivityLog|"
        r"audit\.create|createAuditLog|logActivity",
        re.IGNORECASE
    )

    # ── Scan Source Files ─────────────────────────────────────────────────
    for filepath in walk_source_files(config):
        if "vibesafe" in filepath.parts:
            continue
        content = read_file_safe(filepath)
        if not content:
            continue

        # Check each line for sensitive data in logs
        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            match = sensitive_log_pat.search(line)
            if match:
                sensitive_log_findings.append((filepath.name, line_num, line.strip()[:120]))

        if not has_error_monitoring and error_monitoring_pat.search(content):
            has_error_monitoring = True
        if not has_structured_logging and structured_logging_pat.search(content):
            has_structured_logging = True
        if not has_audit_trail and audit_pat.search(content):
            has_audit_trail = True

    # ── Report Results ────────────────────────────────────────────────────

    # 1. Sensitive Data in Logs (most important check)
    if sensitive_log_findings:
        for filename, line_num, evidence in sensitive_log_findings[:5]:  # Limit to 5
            failed_checks.append(f"Sensitive data logged in {filename}:{line_num}")
            print_failed_check(f"Sensitive Logging: Potential sensitive data in log statement at {filename}:{line_num}.")
            findings.append(Finding(
                title="Sensitive Data Written to Logs",
                severity=Severity.HIGH,
                phase=19,
                phase_name="Logging & Monitoring",
                description="A log statement appears to include sensitive data (passwords, tokens, API keys, credit card info). This data will be exposed in plaintext in log files, monitoring dashboards, and log aggregation services.",
                file_path=filename,
                line_number=line_num,
                evidence=evidence,
                remediation="Remove sensitive data from log statements. If logging is necessary for debugging, mask or redact sensitive fields (e.g., `password: '****'`).",
                owasp_category=OWASPCategory.A09_LOGGING_FAILURES
            ))
    else:
        passed_checks.append("No sensitive data detected in log statements")
        print_passed_check("Sensitive Logging: No passwords, tokens, or secrets found in log calls.")

    # 2. Error Monitoring
    if has_error_monitoring:
        passed_checks.append("Error monitoring service integrated")
        print_passed_check("Error Monitoring: Crash/exception monitoring service (Sentry/Bugsnag/etc.) detected.")
    else:
        failed_checks.append("No error monitoring service detected")
        print_failed_check("Error Monitoring: No crash monitoring service (Sentry, Bugsnag, LogRocket, etc.) found.")
        findings.append(Finding(
            title="Missing Error Monitoring Service",
            severity=Severity.MEDIUM,
            phase=19,
            phase_name="Logging & Monitoring",
            description="No error monitoring or crash reporting service (like Sentry, Bugsnag, or LogRocket) was detected. Runtime errors and crashes will be invisible to developers.",
            evidence="No Sentry, Bugsnag, LogRocket, or Datadog imports found.",
            remediation="Integrate an error monitoring service (e.g., Sentry is free for small teams) to capture and alert on production exceptions.",
            owasp_category=OWASPCategory.A09_LOGGING_FAILURES
        ))

    # 3. Structured Logging
    if has_structured_logging:
        passed_checks.append("Structured logging library detected")
        print_passed_check("Structured Logging: Logging library (winston/pino/bunyan/etc.) found.")
    else:
        passed_checks.append("No structured logging library detected")
        print_info("Structured Logging: No dedicated logging library found (using console.log/print).")
        findings.append(Finding(
            title="No Structured Logging Framework",
            severity=Severity.LOW,
            phase=19,
            phase_name="Logging & Monitoring",
            description="The application uses basic console.log/print statements instead of a structured logging library. Structured logs are easier to search, filter, and aggregate in production.",
            evidence="No winston, pino, bunyan, or Python logging module config found.",
            remediation="Adopt a structured logging library (winston/pino for Node.js, loguru/structlog for Python) for better production observability.",
            owasp_category=OWASPCategory.A09_LOGGING_FAILURES
        ))

    # 4. Audit Trail
    if has_audit_trail:
        passed_checks.append("Audit logging patterns detected")
        print_passed_check("Audit Trail: Audit log creation patterns found for critical operations.")
    else:
        passed_checks.append("No audit trail patterns detected (Optional)")
        print_info("Audit Trail: No audit logging patterns found for tracking admin/critical actions.")
        findings.append(Finding(
            title="No Audit Trail for Critical Operations",
            severity=Severity.INFO,
            phase=19,
            phase_name="Logging & Monitoring",
            description="No audit logging patterns were found for tracking critical operations (admin actions, data exports, account changes). This makes post-incident forensics difficult.",
            evidence="No audit log creation calls found.",
            remediation="Implement audit logging for security-sensitive actions (login, password change, role change, data export, deletion).",
            owasp_category=OWASPCategory.A09_LOGGING_FAILURES
        ))

    return PhaseResult(
        phase_number=19,
        phase_name="Logging & Monitoring",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Logging & monitoring scan completed. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
