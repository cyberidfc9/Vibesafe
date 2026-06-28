"""
Phase 10: File Upload Review
"""

import time
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory, ChecklistItem
from vibesafe.utils import walk_source_files, read_file_safe
from vibesafe.ui import ask_checklist, print_finding

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    checklist = []

    # 1. Automated Detection of File Upload code
    upload_packages = ["multer", "formidable", "busboy", "express-fileupload", "uploadThing", "cloudinary"]
    has_upload_code = False
    evidence_file = ""

    source_files = list(walk_source_files(config))
    for filepath in source_files:
        if "vibesafe" in filepath.parts:
            continue
            
        content = read_file_safe(filepath)
        if not content:
            continue

        if any(pkg in content for pkg in upload_packages) or "type=\"file\"" in content or "type=\'file\'" in content:
            has_upload_code = True
            evidence_file = filepath.name
            break

    # If uploads are detected or we are not skipping guided
    if has_upload_code:
        finding = Finding(
            title="File Upload Capability Detected",
            severity=Severity.INFO,
            phase=10,
            phase_name="File Upload Review",
            description="The application contains file upload capabilities or imports upload handlers.",
            file_path=evidence_file,
            evidence=f"Upload references found in: {evidence_file}",
            remediation="Ensure file uploads are restricted, validated, and scanned.",
            owasp_category=OWASPCategory.A04_INSECURE_DESIGN
        )
        findings.append(finding)
        print_finding(finding)

    # Guided checklist items
    items = [
        ("Uploaded files are validated against an ALLOWLIST of extensions (not just checks on MIME type).", "Attackers can bypass MIME checks and upload executable scripts (like PHP, JS, EXE)."),
        ("Upload size limits are enforced on both client-side and server-side.", "Large file uploads can cause disk exhaustion, leading to DoS."),
        ("Uploaded files are stored outside the web root or on a separate storage service (e.g. S3).", "Files stored in public web folders can be directly accessed and executed by attackers."),
        ("Original filenames are randomized or sanitized to prevent path traversal / directory injection.", "Malicious filenames with '../' patterns can overwrite system configuration files."),
        ("Files are scanned for malware / viruses upon upload (where applicable).", "Malicious files can be uploaded and distributed to other users.")
    ]

    # Only prompt if uploads are detected, or prompt anyway if user ran phase explicitly
    should_prompt = not config.skip_guided and (has_upload_code or config.only_phases)

    for desc, finding_desc in items:
        passed = None
        if should_prompt:
            passed = ask_checklist(desc)
        
        checklist.append(ChecklistItem(description=desc, passed=passed))
        
        if passed is False:
            findings.append(Finding(
                title=f"File Upload Risk: {desc[:40]}...",
                severity=Severity.HIGH,
                phase=10,
                phase_name="File Upload Review",
                description=finding_desc,
                evidence="Guided File Upload Review",
                remediation="Store uploads in external object storage (AWS S3, Cloudinary). Restrict file types to specific non-executable extensions, and rename files randomly.",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
            ))

    return PhaseResult(
        phase_number=10,
        phase_name="File Upload Review",
        phase_type=PhaseType.HYBRID,
        findings=findings,
        checklist=checklist,
        summary=f"File upload review completed. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
