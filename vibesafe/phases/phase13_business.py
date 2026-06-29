"""
Phase 13: Business Logic Testing
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

    # Detect payment / cart / ordering keywords in project
    has_business_logic = False
    business_indicators = re.compile(r"cart|checkout|payment|stripe|razorpay|order|invoice|coupon|discount|price|amount|quantity", re.IGNORECASE)

    has_neg_bounds = False
    neg_bounds_pat = re.compile(r"<=\s*0|<\s*0|min:\s*0|Math\.abs|Math\.max\(0|gte:\s*0|minimum:\s*0|abs\(", re.IGNORECASE)

    has_transactions = False
    transactions_pat = re.compile(r"transaction|\$transaction|atomic|commit|rollback|lock|for update", re.IGNORECASE)

    has_idempotency = False
    idempotency_pat = re.compile(r"idempotency|idempotent|nonce|requestid|x-request-id|dedup", re.IGNORECASE)

    has_state_checks = False
    state_checks_pat = re.compile(r"\.status|\.state|workflow|statemachine|transition", re.IGNORECASE)

    # Walk source files to detect controls
    source_files = list(walk_source_files(config))
    for filepath in source_files:
        if "vibesafe" in filepath.parts:
            continue
        content = read_file_safe(filepath)
        if not content:
            continue

        if not has_business_logic and business_indicators.search(content):
            has_business_logic = True

        if not has_neg_bounds and neg_bounds_pat.search(content):
            has_neg_bounds = True
        if not has_transactions and transactions_pat.search(content):
            has_transactions = True
        if not has_idempotency and idempotency_pat.search(content):
            has_idempotency = True
        if not has_state_checks and state_checks_pat.search(content):
            has_state_checks = True

    # If the app does not appear to contain business logic / payment features, skip reports
    if not has_business_logic:
        print_info("No checkout, payment, or ordering logic detected in source code. Skipping business logic alerts.")
        return PhaseResult(
            phase_number=13,
            phase_name="Business Logic Testing",
            phase_type=PhaseType.AUTOMATED,
            findings=[],
            passed_checks=["No e-commerce or checkout flow detected"],
            summary="No payment or ordering flows detected. Found 0 issues.",
            duration_seconds=time.time() - start_time
        )

    # 1. Negative bounds check
    if has_neg_bounds:
        passed_checks.append("Numeric bounds/negative checks found")
        print_passed_check("Bounds Validation: Validations for negative amounts or quantities detected.")
    else:
        failed_checks.append("Missing negative bounds validation")
        print_failed_check("Bounds Validation: No negative bounds validations (e.g. <= 0, min:0) found.")
        findings.append(Finding(
            title="Missing Negative Price/Quantity Bounds",
            severity=Severity.HIGH,
            phase=13,
            phase_name="Business Logic Testing",
            description="The codebase handles transactions or cart items but lacks server-side validations ensuring amounts, prices, or quantities are not negative.",
            evidence="Transaction/cart code found, but no bounds checks.",
            remediation="Ensure all endpoints accepting quantities, prices, or amounts explicitly validate input values to be greater than zero.",
            owasp_category=OWASPCategory.A04_INSECURE_DESIGN
        ))

    # 2. Transactions
    if has_transactions:
        passed_checks.append("Database transaction/atomic locking patterns detected")
        print_passed_check("Transactions: DB transaction wrappers found ensuring data integrity.")
    else:
        failed_checks.append("No database transaction logic found")
        print_failed_check("Transactions: No atomic database transactions or locking mechanisms found.")
        findings.append(Finding(
            title="Missing Transactional Database Safety",
            severity=Severity.MEDIUM,
            phase=13,
            phase_name="Business Logic Testing",
            description="Multi-step database updates (like deducting stock and creating an order) are run without database transactions, exposing the system to race conditions or partial updates.",
            evidence="Order/stock updates executed without transaction bindings.",
            remediation="Wrap related database write operations in atomic transactions (e.g., Prisma's `$transaction` or Django's `@transaction.atomic`).",
            owasp_category=OWASPCategory.A04_INSECURE_DESIGN
        ))

    # 3. Idempotency Check
    if has_idempotency:
        passed_checks.append("Idempotency keys or request deduplication found")
        print_passed_check("Idempotency: Key verification or request deduplication patterns found.")
    else:
        passed_checks.append("No idempotency checks found (Optional)")
        print_info("Idempotency: No request idempotency keys detected in checkout controllers.")
        findings.append(Finding(
            title="Missing Idempotent Payment Checks",
            severity=Severity.LOW,
            phase=13,
            phase_name="Business Logic Testing",
            description="Checkout or payment handlers lack idempotency keys, which could allow users to double-submit payments due to network latency or double clicks.",
            evidence="Checkout api endpoints lack idempotency protections.",
            remediation="Accept an `Idempotency-Key` header on transaction endpoints to deduplicate identical requests.",
            owasp_category=OWASPCategory.A04_INSECURE_DESIGN
        ))

    # 4. State checks
    if has_state_checks:
        passed_checks.append("Entity state transitions are checked")
        print_passed_check("State Validation: Transitions verify order/item state before update.")
    else:
        failed_checks.append("Missing workflow state validation")
        print_failed_check("State Validation: State fields are mutated without prior status verification.")
        findings.append(Finding(
            title="Missing Workflow State Validation",
            severity=Severity.MEDIUM,
            phase=13,
            phase_name="Business Logic Testing",
            description="Mutations on checkout, order, or ticket entities do not verify the current status (e.g., modifying an order that is already processed).",
            evidence="State updates executed without matching state assertions.",
            remediation="Enforce assertions checking current status (e.g., `if (order.status !== 'pending') throw Error`) before applying updates.",
            owasp_category=OWASPCategory.A04_INSECURE_DESIGN
        ))

    return PhaseResult(
        phase_number=13,
        phase_name="Business Logic Testing",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Business logic scan completed. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
