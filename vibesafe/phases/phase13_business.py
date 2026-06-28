"""
Phase 13: Business Logic Testing
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory, ChecklistItem
from vibesafe.ui import ask_checklist

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    checklist = []

    # Detect stack or features if present
    stack = None
    if scan_result and scan_result.tech_stack:
        stack = scan_result.tech_stack

    is_ecommerce = False
    if stack and (stack.payments or "stripe" in str(stack.other_services).lower() or "razorpay" in str(stack.other_services).lower()):
        is_ecommerce = True

    # 1. Select checklist based on application context
    items = []
    if is_ecommerce:
        items = [
            ("Coupon codes can only be used once per user and cannot be applied in multiple tabs/parallel requests.", "Parallel coupon applications allow getting products for free or negative amounts."),
            ("Prices and quantities cannot be negative or manipulated in API requests (e.g. adding -5 items to subtract cost).", "Negative quantity parameters bypass Stripe/Razorpay pricing check, altering invoice totals."),
            ("Stock/Inventory checks are validated server-side on checkout (prevents overselling or double-booking).", "Client-side quantity validations let users check out unavailable or locked products.")
        ]
    else:
        items = [
            ("Multi-step workflows (registration, onboarding) cannot be bypassed by skipping pages or requests.", "Bypassing setup pages can lead to uninitialized user accounts with null values."),
            ("Resource deletions or modifications require verifying item state (e.g. user cannot delete a finalized post/order).", "State bypass allows users to delete or modify finalized system resources."),
            ("Rate limiting restricts repeating business logic processes (e.g., email notification trigger, account creation).", "Lack of process throttling allows spamming emails or server exhaustion.")
        ]

    for desc, finding_desc in items:
        passed = None
        if not config.skip_guided:
            passed = ask_checklist(desc)
        
        checklist.append(ChecklistItem(description=desc, passed=passed))
        
        if passed is False:
            findings.append(Finding(
                title=f"Business Logic Issue: {desc[:40]}...",
                severity=Severity.HIGH,
                phase=13,
                phase_name="Business Logic Testing",
                description=finding_desc,
                evidence="Guided Business Logic Review",
                remediation="Enforce state-transition logic, validate price/quantities on backend, prevent negative inputs, and lock resources under mutations.",
                owasp_category=OWASPCategory.A04_INSECURE_DESIGN
            ))

    return PhaseResult(
        phase_number=13,
        phase_name="Business Logic Testing",
        phase_type=PhaseType.GUIDED,
        findings=findings,
        checklist=checklist,
        summary=f"Business logic testing completed. Found {len(findings)} logical issues.",
        duration_seconds=time.time() - start_time
    )
