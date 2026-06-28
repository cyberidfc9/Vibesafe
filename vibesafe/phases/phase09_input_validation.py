"""
Phase 9: Input Validation
"""

import time
import re
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import walk_source_files, read_file_safe
from vibesafe.ui import print_finding

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    
    # We scan source files for indicators of raw req.body / req.query usage
    # without typical validation libraries (zod, yup, joi, class-validator)
    source_files = list(walk_source_files(config))

    # Regexes for form/query parameters being assigned directly
    validation_libs = ["zod", "yup", "joi", "express-validator", "pydantic", "marshmallow", "validator"]
    
    for filepath in source_files:
        if "vibesafe" in filepath.parts:
            continue
            
        content = read_file_safe(filepath)
        if not content:
            continue

        # Let's check if this file contains an API route or page handler
        is_handler = "req.body" in content or "req.query" in content or "request.GET" in content or "request.POST" in content or "request.json()" in content or "searchParams" in content
        
        if is_handler:
            # Check if any validation libraries are imported
            has_validation = any(lib in content for lib in validation_libs)
            
            if not has_validation:
                finding = Finding(
                    title="Missing Schema Input Validation",
                    severity=Severity.MEDIUM,
                    phase=9,
                    phase_name="Input Validation",
                    description=f"File `{filepath.name}` handles client requests but does not import or use a schema validation library (Zod, Yup, Joi, or Pydantic).",
                    file_path=str(filepath.name),
                    evidence="No validation imports found in request handler file.",
                    remediation="Use a schema validator like Zod (for JS/TS) or Pydantic (for Python) to parse and sanitize all input (req.body, req.query, params) before executing database or file actions.",
                    owasp_category=OWASPCategory.A03_INJECTION
                )
                findings.append(finding)
                print_finding(finding)

        # Look for dangerous deserialization / regex matching that could cause ReDoS
        # e.g., complex regex matches on long strings
        redos_pattern = re.compile(r'/\([^)]+\)\+\//')
        if redos_pattern.search(content):
            finding = Finding(
                title="Potential ReDoS Regular Expression",
                severity=Severity.LOW,
                phase=9,
                phase_name="Input Validation",
                description="Regular expression with nested quantifiers found. This could be vulnerable to Regex Denial of Service (ReDoS).",
                file_path=str(filepath.name),
                evidence=redos_pattern.search(content).group(),
                remediation="Ensure regular expressions are simple, avoid nested quantifiers (e.g., (a+)+), or use safe regex engines.",
                owasp_category=OWASPCategory.A03_INJECTION
            )
            findings.append(finding)
            print_finding(finding)

    return PhaseResult(
        phase_number=9,
        phase_name="Input Validation",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        summary=f"Input validation scans completed on {len(source_files)} files. Discovered {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
