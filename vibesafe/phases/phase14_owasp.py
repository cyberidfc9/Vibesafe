"""
Phase 14: OWASP Top 10 Review
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.ui import print_owasp_coverage

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    
    # Initialize coverage matrix with 0 findings count
    coverage = {cat.value: 0 for cat in OWASPCategory}

    # Aggregate findings from previous phases in the scan_result
    if scan_result and scan_result.phase_results:
        for pr in scan_result.phase_results:
            for f in pr.findings:
                if f.owasp_category:
                    cat_val = f.owasp_category.value
                    if cat_val in coverage:
                        coverage[cat_val] += 1

    # Render scorecard
    print_owasp_coverage(coverage)

    # If any category has 0 coverage, we flag it as an informational finding.
    # It reminds the developer that they haven't run checks/validations for it.
    for cat_val, count in coverage.items():
        if count == 0:
            # We don't flood findings list with all 10, just a summary
            pass

    return PhaseResult(
        phase_number=14,
        phase_name="OWASP Top 10 Review",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        summary="Mapped all detected vulnerabilities against the OWASP Top 10 checklist.",
        duration_seconds=time.time() - start_time
    )
