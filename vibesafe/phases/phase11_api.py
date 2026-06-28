"""
Phase 11: API Security
"""

import time
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import walk_source_files, read_file_safe
from vibesafe.ui import print_finding

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    
    # 1. Identify API Routes
    source_files = list(walk_source_files(config))
    api_routes = []
    
    for filepath in source_files:
        if "vibesafe" in filepath.parts:
            continue

        # Look for typical path indicators for API endpoints
        rel_path = str(filepath)
        is_api_route = False
        if "/api/" in rel_path.replace("\\", "/"):
            is_api_route = True
        elif "route.ts" in filepath.name or "route.js" in filepath.name:
            is_api_route = True
        elif "views.py" in filepath.name or "endpoints" in filepath.name:
            is_api_route = True

        if is_api_route:
            api_routes.append(filepath)

    # 2. Audit routes
    for route_file in api_routes:
        content = read_file_safe(route_file)
        if not content:
            continue

        # Check for missing authentication checks in Next.js / Express routes
        # NextAuth session verification indicators: getServerSession, getSession, auth(), getToken
        # Clerk session indicators: auth()
        # Express session indicators: req.user, isAuthenticated
        auth_keywords = ["getServerSession", "getSession", "auth()", "getToken", "req.user", "isAuthenticated", "get_object_or_404", "require_auth", "login_required", "@router."]
        
        has_auth_check = any(kw in content for kw in auth_keywords)
        
        # If route handles POST/PUT/DELETE/PATCH but has no obvious auth check
        is_mutating = "POST" in content or "PUT" in content or "DELETE" in content or "PATCH" in content or "async function GET" in content
        
        if is_mutating and not has_auth_check:
            # We flag this as a potential unprotected route
            finding = Finding(
                title="Potential Unprotected API Route",
                severity=Severity.HIGH,
                phase=11,
                phase_name="API Security",
                description=f"API route file `{route_file.name}` contains mutating HTTP methods or query logic, but no authentication checks or session guards were detected.",
                file_path=str(route_file.name),
                evidence=content[:200].replace("\n", " "),
                remediation="Ensure session validation is executed at the entry point of the route handler. Reject requests with 401/403 status code if session is invalid.",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
            )
            findings.append(finding)
            print_finding(finding)

        # Check for error stack leakage
        if "err.stack" in content or "stackTrace" in content or "traceback" in content:
            finding = Finding(
                title="API Leaking Stack Trace",
                severity=Severity.MEDIUM,
                phase=11,
                phase_name="API Security",
                description=f"API handler in `{route_file.name}` reference `err.stack` or `traceback` inside error handling blocks.",
                file_path=str(route_file.name),
                evidence="Reference to err.stack/traceback",
                remediation="Log stack traces internally on your servers. Return generic client-facing messages instead of debugging details.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            )
            findings.append(finding)
            print_finding(finding)

    return PhaseResult(
        phase_number=11,
        phase_name="API Security",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        summary=f"Audited {len(api_routes)} API routes. Discovered {len(findings)} potential security issues.",
        duration_seconds=time.time() - start_time
    )
