"""
Phase 7: Authentication Testing
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

    # Detect if auth features are present in the project to avoid false positives in non-auth apps
    has_auth_code = False
    auth_patterns = [
        re.compile(r"login|signup|register|password|session|jwt|auth\b", re.IGNORECASE)
    ]

    # Flags for each control
    has_hashing = False
    has_rate_limiting = False
    has_mfa = False
    has_session_timeout = False
    has_pw_rules = False

    # Regex definitions for controls
    hashing_pat = re.compile(r"bcrypt|argon2|scrypt|pbkdf2|hashlib|make_password|check_password|hashers|django\.contrib\.auth", re.IGNORECASE)
    rate_limit_pat = re.compile(r"express-rate-limit|ratelimit|slowdown|throttle|throttler|limiter|django-ratelimit", re.IGNORECASE)
    mfa_pat = re.compile(r"speakeasy|otplib|simplewebauthn|pyotp|totp|2fa\b|mfa\b|authenticator|google-authenticator", re.IGNORECASE)
    timeout_pat = re.compile(r"maxage|expires|session.*timeout|session.*age|jwt_expiration|expiresin", re.IGNORECASE)
    pw_rules_pat = re.compile(r"minlength|password.*length|zxcvbn|min_password_length|passwordvalidator|password.*regex", re.IGNORECASE)

    # Walk source files to detect controls
    for filepath in walk_source_files(config):
        content = read_file_safe(filepath)
        if not content:
            continue

        if not has_auth_code:
            for pat in auth_patterns:
                if pat.search(content):
                    has_auth_code = True
                    break

        if not has_hashing and hashing_pat.search(content):
            has_hashing = True
        if not has_rate_limiting and rate_limit_pat.search(content):
            has_rate_limiting = True
        if not has_mfa and mfa_pat.search(content):
            has_mfa = True
        if not has_session_timeout and timeout_pat.search(content):
            has_session_timeout = True
        if not has_pw_rules and pw_rules_pat.search(content):
            has_pw_rules = True

    # If the app doesn't seem to have authentication code, skip raising High findings but report what we scanned.
    if not has_auth_code:
        print_info("No authentication or registration patterns detected in source code. Skipping auth alerts.")
        return PhaseResult(
            phase_number=7,
            phase_name="Authentication Testing",
            phase_type=PhaseType.AUTOMATED,
            findings=[],
            passed_checks=["No authentication code detected (Skipped validations)"],
            summary="No authentication code detected. Found 0 issues.",
            duration_seconds=time.time() - start_time
        )

    # 1. Password Hashing
    if has_hashing:
        passed_checks.append("Secure password hashing library found")
        print_passed_check("Password Hashing: Cryptographic hashing imports/calls found.")
    else:
        failed_checks.append("No password hashing library found")
        print_failed_check("Password Hashing: No secure hashing (bcrypt/argon2/etc.) detected.")
        findings.append(Finding(
            title="Missing Secure Password Hashing",
            severity=Severity.HIGH,
            phase=7,
            phase_name="Authentication Testing",
            description="The application handles authentication but no secure password hashing algorithm (bcrypt, argon2, pbkdf2) was detected in the source code.",
            evidence="Auth code found, but no hashing library imports.",
            remediation="Ensure user passwords are encrypted at rest using strong, slow hashing algorithms (like Argon2id or bcrypt) before storing them.",
            owasp_category=OWASPCategory.A07_AUTH_FAILURES
        ))

    # 2. Rate Limiting on Auth
    if has_rate_limiting:
        passed_checks.append("Rate limiting library or logic found")
        print_passed_check("Rate Limiting: Rate limit or throttle implementation found.")
    else:
        failed_checks.append("No rate limiting detected on auth routes")
        print_failed_check("Rate Limiting: No throttling configuration detected.")
        findings.append(Finding(
            title="Missing Login Rate Limiting",
            severity=Severity.HIGH,
            phase=7,
            phase_name="Authentication Testing",
            description="No rate limiting or request throttling library was detected. This exposes auth endpoints to brute force and credential stuffing attacks.",
            evidence="Login/auth routes exist without rate limit controls.",
            remediation="Implement rate limiting (e.g. express-rate-limit for Node, django-ratelimit for Python) on endpoints handles login/verification.",
            owasp_category=OWASPCategory.A07_AUTH_FAILURES
        ))

    # 3. MFA/2FA
    if has_mfa:
        passed_checks.append("MFA integration found")
        print_passed_check("MFA: Multi-Factor Authentication code detected.")
    else:
        passed_checks.append("No MFA integration found (Optional)")
        print_info("MFA: Multi-Factor Authentication is not configured.")
        findings.append(Finding(
            title="MFA Recommendation",
            severity=Severity.INFO,
            phase=7,
            phase_name="Authentication Testing",
            description="Multi-factor authentication (MFA) libraries were not detected. Recommended to safeguard user/admin accounts.",
            evidence="No pyotp, otplib, or simplewebauthn code.",
            remediation="Consider integrating TOTP-based 2FA (using pyotp/otplib) or WebAuthn to secure accounts.",
            owasp_category=OWASPCategory.A07_AUTH_FAILURES
        ))

    # 4. Session Timeout Config
    if has_session_timeout:
        passed_checks.append("Session timeout configuration found")
        print_passed_check("Session Timeout: Explicit session/JWT age settings detected.")
    else:
        failed_checks.append("Missing session timeout configuration")
        print_failed_check("Session Timeout: No session duration or expiry restrictions detected.")
        findings.append(Finding(
            title="Missing Session Expiry Config",
            severity=Severity.MEDIUM,
            phase=7,
            phase_name="Authentication Testing",
            description="Session tokens or JWTs do not appear to have configuration enforcing timeout or maxAge restrictions.",
            evidence="Sessions generated without maxAge/expires constraints.",
            remediation="Configure a reasonable session timeout limits (e.g., 15-30 minutes for inactivity, max 24 hours maxAge).",
            owasp_category=OWASPCategory.A07_AUTH_FAILURES
        ))

    # 5. Password Validation
    if has_pw_rules:
        passed_checks.append("Password strength validation rules found")
        print_passed_check("Password Rules: Minimum length or strength checks detected.")
    else:
        failed_checks.append("No password strength validation found")
        print_failed_check("Password Rules: No password policy validation logic found.")
        findings.append(Finding(
            title="Missing Password Strength Policies",
            severity=Severity.MEDIUM,
            phase=7,
            phase_name="Authentication Testing",
            description="No password complexity or length checks (like zxcvbn or minLength validation) were detected on registration endpoints.",
            evidence="User passwords accepted without length or complexity checks.",
            remediation="Enforce a password policy requiring at least 10-12 characters, mixing uppercase, lowercase, numbers, and symbols.",
            owasp_category=OWASPCategory.A07_AUTH_FAILURES
        ))

    return PhaseResult(
        phase_number=7,
        phase_name="Authentication Testing",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Authentication scanning complete. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
