"""
Phase 8: Authorization Testing
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

    # Detect route access control patterns
    has_auth_middleware = False
    has_rbac = False
    has_jwt_scopes = False
    idor_findings = []

    # Patterns
    auth_middleware_pat = re.compile(
        r"isAuthenticated|requireAuth|protect|authMiddleware|@login_required|LoginRequiredMixin|IsAuthenticated|withAuth|getServerSession|getSession",
        re.IGNORECASE
    )
    rbac_pat = re.compile(
        r"isAdmin|hasRole|checkRole|@permission_required|role\b|permissions\b|RBAC\b|authorize\b|can\(|ability\b",
        re.IGNORECASE
    )
    idor_pat = re.compile(
        r"findById\(req\.params\.id\)|findOne\(req\.params\.id\)|db\..*where.*id\s*=\s*req\.params|delete.*req\.params\.id|update.*req\.params\.id",
        re.IGNORECASE
    )
    jwt_scope_pat = re.compile(
        r"scope|claims|permissions",
        re.IGNORECASE
    )

    # Walk source files to detect authorization patterns
    for filepath in walk_source_files(config):
        content = read_file_safe(filepath)
        if not content:
            continue

        if not has_auth_middleware and auth_middleware_pat.search(content):
            has_auth_middleware = True
        if not has_rbac and rbac_pat.search(content):
            has_rbac = True
        if not has_jwt_scopes and jwt_scope_pat.search(content):
            has_jwt_scopes = True

        # Check for IDOR (direct lookup of param ID without checking user ownership)
        match = idor_pat.search(content)
        if match:
            # We found an IDOR pattern!
            idor_findings.append((filepath.name, match.group(0)))

    # 1. Auth Middleware Check
    if has_auth_middleware:
        passed_checks.append("Route authentication middleware/guards detected")
        print_passed_check("Auth Guards: Authentication middleware/guards found protecting routes.")
    else:
        # If there's no auth code at all in the project, we skip this to prevent false alerts on static sites.
        # But if there are api routes or login pages, we alert.
        failed_checks.append("No authentication middleware detected on routes")
        print_failed_check("Auth Guards: No route authentication middleware detected.")
        findings.append(Finding(
            title="Missing Route Authentication Middleware",
            severity=Severity.HIGH,
            phase=8,
            phase_name="Authorization Testing",
            description="The application does not seem to utilize authentication middleware (like isAuthenticated/protect/@login_required) to guard server-side routes or APIs.",
            evidence="No auth route guards found in codebase.",
            remediation="Implement middleware to check authentication status before serving sensitive API responses or UI views.",
            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
        ))

    # 2. Role-Based Access Control (RBAC)
    if has_rbac:
        passed_checks.append("Role or permission checks found")
        print_passed_check("RBAC: Role/permission-based access controls detected.")
    else:
        failed_checks.append("No role-based access checks detected")
        print_failed_check("RBAC: No role-based or permission-based checks found.")
        findings.append(Finding(
            title="Missing Role-Based Access Control",
            severity=Severity.MEDIUM,
            phase=8,
            phase_name="Authorization Testing",
            description="No role-based access checks (e.g. isAdmin, hasRole, or permission guards) were found in the codebase. Admin endpoints or operations might be exposed.",
            evidence="No role or permission validation logic found.",
            remediation="Incorporate role-based access control (RBAC) or attribute-based access control (ABAC) to restrict admin or sensitive features.",
            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
        ))

    # 3. IDOR Patterns
    if idor_findings:
        for filename, evidence in idor_findings[:3]:  # Limit to first 3 to prevent spam
            failed_checks.append(f"Potential IDOR vulnerability in {filename}")
            print_failed_check(f"IDOR Check: Potential insecure direct object reference in {filename}.")
            findings.append(Finding(
                title="Insecure Direct Object Reference (IDOR)",
                severity=Severity.HIGH,
                phase=8,
                phase_name="Authorization Testing",
                description="Potential IDOR detected. The code directly queries database items using URL parameters (like req.params.id) without verifying that the authenticated user owns that resource.",
                file_path=filename,
                evidence=evidence,
                remediation="Ensure all database query operations verify resource ownership. (e.g., query for `id: req.params.id, userId: req.user.id` instead of just `id: req.params.id`).",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
            ))
    else:
        passed_checks.append("No obvious IDOR code patterns detected")
        print_passed_check("IDOR Check: No unverified direct database lookups found.")

    # 4. JWT Scope validation
    if has_jwt_scopes:
        passed_checks.append("Token scope/claims validation checks found")
        print_passed_check("Token Scopes: JWT scope/claims checks found.")
    else:
        passed_checks.append("No token scope validation checks found (Optional)")
        print_info("Token Scopes: No JWT scope/claims validation checks found.")
        findings.append(Finding(
            title="Missing Token Scope Restrictions",
            severity=Severity.LOW,
            phase=8,
            phase_name="Authorization Testing",
            description="If the application issues JWTs or API keys, they should be validated for specific scopes/permissions to limit the impact of a compromised token.",
            evidence="No JWT scope validation checks detected.",
            remediation="Verify scope claims in incoming JWTs to ensure client/user permissions match the specific action.",
            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
        ))

    return PhaseResult(
        phase_number=8,
        phase_name="Authorization Testing",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Authorization checks complete. Discovered {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
