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
    
    # We check if tech stack context exists
    stack = None
    if scan_result and scan_result.tech_stack:
        stack = scan_result.tech_stack

    # Stack-aware validation libraries
    if stack and stack.runtime == "Python":
        validation_libs = ["pydantic", "marshmallow", "wtforms", "serializer", "Form"]
        expected_handler_patterns = ["request.GET", "request.POST", "request.data", "request.json", "request.args", "request.form"]
        remediation_text = "Use Pydantic models (for FastAPI/Flask) or Django Forms/Serializers to validate and sanitize client input data."
    else:
        # Default to Node.js/JS libs
        validation_libs = ["zod", "yup", "joi", "express-validator", "validator", "superstruct"]
        expected_handler_patterns = ["req.body", "req.query", "req.params", "request.json()", "searchParams.get"]
        remediation_text = "Use a schema validation library like Zod, Yup, or Joi to parse and sanitize all request parameters."

    for filepath in source_files:
        if "vibesafe" in filepath.parts:
            continue
            
        content = read_file_safe(filepath)
        if not content:
            continue

        # Let's check if this file contains an API route or page handler
        is_handler = any(pattern in content for pattern in expected_handler_patterns)
        
        if is_handler:
            # Check if any validation libraries are imported
            has_validation = any(lib in content for lib in validation_libs)
            
            if not has_validation:
                finding = Finding(
                    title="Missing Input Validation Schema",
                    severity=Severity.MEDIUM,
                    phase=9,
                    phase_name="Input Validation",
                    description=f"File `{filepath.name}` handles client requests but does not import or use any expected validation library ({', '.join(validation_libs)}).",
                    file_path=str(filepath.name),
                    evidence="No validation imports found in request handler file.",
                    remediation=remediation_text,
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
