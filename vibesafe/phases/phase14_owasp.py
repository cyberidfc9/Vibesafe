"""
Phase 14: OWASP Top 10 Review & CWE Mapping
"""

import time
from collections import defaultdict
from rich.table import Table
from rich import box
from rich.console import Console
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.ui import print_owasp_coverage
from vibesafe.cwe_database import get_cwe_name

console = Console()

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    
    # Initialize coverage matrix with 0 findings count
    coverage = {cat.value: 0 for cat in OWASPCategory}
    
    # Aggregated CWE counts
    cwe_counts = defaultdict(int)

    # Aggregate findings from previous phases in the scan_result
    if scan_result:
        for f in scan_result.all_findings:
            if f.owasp_category:
                cat_val = f.owasp_category.value
                if cat_val in coverage:
                    coverage[cat_val] += 1
            if f.cwe_id:
                cwe_counts[f.cwe_id] += 1

    # Render OWASP scorecard
    print_owasp_coverage(coverage)

    # Render CWE breakdown table if there are CWE findings
    if cwe_counts:
        console.print()
        table = Table(
            title="🏷️ CWE (Common Weakness Enumeration) Breakdown",
            box=box.ROUNDED,
            title_style="bold cyan",
            show_header=True,
            header_style="bold white",
        )
        table.add_column("CWE ID & Name", min_width=50)
        table.add_column("Count", justify="center", min_width=10)
        
        for cwe_id, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True):
            table.add_row(get_cwe_name(cwe_id), str(count))
            
        console.print(table)

    return PhaseResult(
        phase_number=14,
        phase_name="OWASP Top 10 Review",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        summary="Mapped all detected vulnerabilities against the OWASP Top 10 checklist and CWE database.",
        duration_seconds=time.time() - start_time
    )
