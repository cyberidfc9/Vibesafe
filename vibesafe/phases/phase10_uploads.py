"""
Phase 10: File Upload Review
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

    # If no upload capability is detected, complete scan with info message
    if not has_upload_code:
        print_info("No file upload handlers or file inputs detected in source code. Skipping upload checks.")
        return PhaseResult(
            phase_number=10,
            phase_name="File Upload Review",
            phase_type=PhaseType.AUTOMATED,
            findings=[],
            passed_checks=["No upload code detected"],
            summary="No file upload code detected. Found 0 issues.",
            duration_seconds=time.time() - start_time
        )

    # File upload capability detected
    capability_finding = Finding(
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
    findings.append(capability_finding)
    print_finding(capability_finding)

    # 2. Automated Scan for Upload Protections
    has_type_validation = False
    has_size_limits = False
    has_name_sanitization = False
    has_external_storage = False

    type_pat = re.compile(r"mimetype|extension|allowedtypes|filefilter|accept|allowed_extensions|content_type|file_type", re.IGNORECASE)
    size_pat = re.compile(r"limits|maxfilesize|filesizelimit|max_file_size|limit.*size|filesize|maxsize|body.*limit", re.IGNORECASE)
    sanitize_pat = re.compile(r"sanitize|path\.basename|uuid|nanoid|randomuuid|crypto\.random|randomize", re.IGNORECASE)
    storage_pat = re.compile(r"s3|s3client|cloudinary|uploadthing|supabase\.storage|googleapis.*storage|azure.*blob|@aws-sdk", re.IGNORECASE)

    for filepath in source_files:
        if "vibesafe" in filepath.parts:
            continue
        content = read_file_safe(filepath)
        if not content:
            continue

        if not has_type_validation and type_pat.search(content):
            has_type_validation = True
        if not has_size_limits and size_pat.search(content):
            has_size_limits = True
        if not has_name_sanitization and sanitize_pat.search(content):
            has_name_sanitization = True
        if not has_external_storage and storage_pat.search(content):
            has_external_storage = True

    # Check 1: File Type Validation
    if has_type_validation:
        passed_checks.append("File type validation detected")
        print_passed_check("Upload Types: File type validation logic/patterns found.")
    else:
        failed_checks.append("No file type validation detected")
        print_failed_check("Upload Types: No file type allowlist validation detected.")
        findings.append(Finding(
            title="Missing File Type Validation",
            severity=Severity.HIGH,
            phase=10,
            phase_name="File Upload Review",
            description="The application handles file uploads but does not appear to validate the files against an allowlist of permitted extensions/mimetypes.",
            evidence="Upload code found, but no validation allowlist patterns.",
            remediation="Enforce strict file type validation using an allowlist of safe extensions (e.g. .jpg, .png, .pdf). Never rely on browser-provided MIME types alone.",
            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
        ))

    # Check 2: File Size Limits
    if has_size_limits:
        passed_checks.append("File size limits detected")
        print_passed_check("Upload Size: File size restrictions found.")
    else:
        failed_checks.append("No file size limits detected")
        print_failed_check("Upload Size: No upload payload size constraints detected.")
        findings.append(Finding(
            title="Missing Upload Size Limits",
            severity=Severity.MEDIUM,
            phase=10,
            phase_name="File Upload Review",
            description="No file size limits were found in the upload handling code. Attackers can upload extremely large files to trigger disk exhaustion.",
            evidence="No payload size restrictions defined.",
            remediation="Set maximum file size limits (e.g., 5MB for images) on both client-side forms and server-side request parsers.",
            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
        ))

    # Check 3: Filename Sanitization
    if has_name_sanitization:
        passed_checks.append("Filename sanitization/randomization detected")
        print_passed_check("Upload Names: Filename sanitization or randomization patterns found.")
    else:
        failed_checks.append("No filename sanitization detected")
        print_failed_check("Upload Names: Uploaded files might keep original user-supplied filenames.")
        findings.append(Finding(
            title="Missing Upload Filename Sanitization",
            severity=Severity.HIGH,
            phase=10,
            phase_name="File Upload Review",
            description="The original user-controlled filename is saved directly. This exposes the application to path traversal attacks if filenames contain '../' prefixes.",
            evidence="Original user filename used in local saving/storage.",
            remediation="Sanitize original filenames or, ideally, rename files to randomly generated UUIDs/nanoIDs before writing to disk.",
            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
        ))

    # Check 4: External Storage
    if has_external_storage:
        passed_checks.append("External cloud object storage detected")
        print_passed_check("Upload Storage: Files stored in external cloud storage (S3/Cloudinary/etc.).")
    else:
        passed_checks.append("Local disk storage used")
        print_info("Upload Storage: Files are stored locally in the web directory structure.")
        findings.append(Finding(
            title="Local Disk File Upload Storage",
            severity=Severity.MEDIUM,
            phase=10,
            phase_name="File Upload Review",
            description="Uploaded files are stored locally on the web server disk. If these folders are public, files can be directly executed by visiting their URL.",
            evidence="No cloud storage library (S3/Cloudinary/etc.) detected.",
            remediation="Store uploaded files outside the public web root directory, or migrate upload storage to dedicated services like AWS S3 or Cloudinary.",
            owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
        ))

    return PhaseResult(
        phase_number=10,
        phase_name="File Upload Review",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"File upload review completed. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
