"""
Phase 2: Threat Modeling
"""

import time
from rich.table import Table
from rich import box
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.ui import console

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    
    # Retrieve tech stack from previous phase
    stack = None
    if scan_result and scan_result.tech_stack:
        stack = scan_result.tech_stack

    # Define potential threats based on components
    threats = []

    # 1. Base Auth Threat
    if stack and stack.auth:
        threats.append({
            "component": f"Auth ({stack.auth})",
            "threat": "Session hijacking, brute-force attacks, credential stuffing, password reset bypass",
            "impact": "Account takeover, unauthorized data access",
            "risk": "High"
        })
    else:
        threats.append({
            "component": "Authentication (None Detected)",
            "threat": "No authentication detected. User verification missing.",
            "impact": "Total access to features without verification",
            "risk": "Critical"
        })

    # 2. Database Threat
    if stack and stack.database:
        threats.append({
            "component": f"Database ({stack.database})",
            "threat": "SQL Injection, insecure direct object reference (IDOR), unauthorized database access",
            "impact": "Full database exfiltration, modification, or destruction",
            "risk": "High"
        })
    else:
        threats.append({
            "component": "Database (None Detected)",
            "threat": "Check if database is built-in (e.g., local json) or missing",
            "impact": "Data loss or storage manipulation",
            "risk": "Medium"
        })

    # 3. Payments Threat
    if stack and stack.payments:
        threats.append({
            "component": f"Payments ({stack.payments})",
            "threat": "Price tampering, invoice/payment bypass, checkout parameter tampering",
            "impact": "Financial loss, unpaid orders or products obtained for free",
            "risk": "Critical"
        })

    # 4. Storage / Uploads Threat
    if stack and stack.storage:
        threats.append({
            "component": f"File Storage ({stack.storage})",
            "threat": "Malicious file uploads, executable script execution (RCE), bucket access control failures",
            "impact": "Complete server compromise, hosting malware, defacement",
            "risk": "High"
        })

    # 5. API Threat
    if stack and stack.api_routes_count > 0:
        threats.append({
            "component": f"API Security ({stack.api_routes_count} routes)",
            "threat": "Rate limit exhaustion (DoS), broken object level authorization (BOLA), mass assignment",
            "impact": "Service disruption, backend data leak",
            "risk": "High"
        })

    # Display Threat Table
    table = Table(
        title="🛡️ Threat Model Matrix",
        box=box.ROUNDED,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Attack Surface", style="cyan", min_width=18)
    table.add_column("Threat / Attack Vectors", style="white")
    table.add_column("Potential Impact", style="dim")
    table.add_column("Risk Level", justify="center", min_width=10)

    for t in threats:
        risk_color = "red" if t["risk"] == "Critical" else ("orange3" if t["risk"] == "High" else "yellow")
        table.add_row(
            t["component"],
            t["threat"],
            t["impact"],
            f"[{risk_color}]{t['risk']}[/{risk_color}]"
        )
        
        # Populate findings as recommendations
        findings.append(Finding(
            title=f"Threat Model Threat: {t['component']}",
            severity=Severity.INFO,
            phase=2,
            phase_name="Threat Modeling",
            description=f"Potential Attack Path identified: {t['threat']}",
            evidence=f"Component: {t['component']}",
            remediation=f"Secure {t['component']} by validating access controls, permissions, and input formats.",
            owasp_category=OWASPCategory.A04_INSECURE_DESIGN
        ))

    console.print(table)

    return PhaseResult(
        phase_number=2,
        phase_name="Threat Modeling",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        summary=f"Generated threat modeling mapping with {len(threats)} vectors.",
        duration_seconds=time.time() - start_time
    )
