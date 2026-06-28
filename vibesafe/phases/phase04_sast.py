"""
Phase 4: Static Code Review (SAST)
"""

import time
import re
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import walk_source_files, scan_file_for_patterns, get_project_root, relative_path, read_file_safe
from vibesafe.patterns.secrets import SECRET_PATTERNS
from vibesafe.patterns.injection import ALL_INJECTION_PATTERNS
from vibesafe.patterns.unsafe_code import ALL_UNSAFE_PATTERNS
from vibesafe.patterns.frameworks import ALL_FRAMEWORK_PATTERNS
from vibesafe.ui import print_finding

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    project_root = get_project_root(config)

    # Prepare patterns list for scan_file_for_patterns utility.
    # scan_file_for_patterns takes: list[tuple[str, re.Pattern]]
    
    # Let's map out patterns with their full metadata for lookup.
    # To avoid matching the pattern file itself (if project includes vibesafe source),
    # we should exclude the patterns folder or file. But config.exclude_dirs handles this.
    
    # Store custom metadata mapping to build findings
    pattern_metadata = {}

    sast_patterns = []

    # 1. Add Secrets patterns
    for name, desc, regex, severity, remediation in SECRET_PATTERNS:
        # Convert severity string to Severity Enum
        sev = Severity.INFO
        if severity == "critical":
            sev = Severity.CRITICAL
        elif severity == "high":
            sev = Severity.HIGH
        elif severity == "medium":
            sev = Severity.MEDIUM
        elif severity == "low":
            sev = Severity.LOW
        
        pattern_metadata[name] = {
            "description": desc,
            "severity": sev,
            "remediation": remediation,
            "owasp": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
        }
        sast_patterns.append((name, regex))

    # 2. Add Injection patterns
    for name, desc, regex, remediation in ALL_INJECTION_PATTERNS:
        pattern_metadata[name] = {
            "description": desc,
            "severity": Severity.HIGH,
            "remediation": remediation,
            "owasp": OWASPCategory.A03_INJECTION
        }
        sast_patterns.append((name, regex))

    # 3. Add Unsafe patterns
    for name, desc, regex, remediation in ALL_UNSAFE_PATTERNS:
        # Assign category depending on finding name
        owasp = OWASPCategory.A05_SECURITY_MISCONFIGURATION
        if "crypto" in name.lower() or "md5" in name.lower() or "sha1" in name.lower():
            owasp = OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
        elif "deserialization" in name.lower() or "pickle" in name.lower():
            owasp = OWASPCategory.A08_INTEGRITY_FAILURES
            
        pattern_metadata[name] = {
            "description": desc,
            "severity": Severity.MEDIUM,
            "remediation": remediation,
            "owasp": owasp
        }
        sast_patterns.append((name, regex))

    # 4. Add Framework patterns
    for name, desc, regex, remediation in ALL_FRAMEWORK_PATTERNS:
        pattern_metadata[name] = {
            "description": desc,
            "severity": Severity.MEDIUM,
            "remediation": remediation,
            "owasp": OWASPCategory.A05_SECURITY_MISCONFIGURATION
        }
        sast_patterns.append((name, regex))

    # Run scans on source files
    source_files = list(walk_source_files(config))

    # For safety, let's scan one by one and yield findings
    for filepath in source_files:
        # Skip vibesafe folder if it is in the project path
        if "vibesafe" in filepath.parts:
            continue

        matches = scan_file_for_patterns(filepath, sast_patterns, project_root)
        for m in matches:
            pat_name = m["pattern_name"]
            meta = pattern_metadata[pat_name]

            finding = Finding(
                title=pat_name,
                severity=meta["severity"],
                phase=4,
                phase_name="Static Code Review (SAST)",
                description=meta["description"],
                file_path=m["file_path"],
                line_number=m["line_number"],
                evidence=m["line_content"],
                remediation=meta["remediation"],
                owasp_category=meta["owasp"]
            )
            findings.append(finding)
            print_finding(finding)

    # 5. Check if any .env files are in the repository and not gitignored
    from vibesafe.patterns.secrets import ENV_FILES_SHOULD_BE_GITIGNORED
    gitignore_file = project_root / ".gitignore"
    gitignore_content = ""
    if gitignore_file.exists():
        gitignore_content = read_file_safe(gitignore_file) or ""

    for env_name in ENV_FILES_SHOULD_BE_GITIGNORED:
        env_files = list(project_root.glob(f"**/{env_name}"))
        for ef in env_files:
            # Check if this directory is excluded
            if any(part in ef.parts for part in config.exclude_dirs):
                continue
            
            # Check if mentioned in gitignore
            rel_ef = relative_path(ef, project_root)
            if env_name not in gitignore_content:
                finding = Finding(
                    title="Exposed Environment File",
                    severity=Severity.CRITICAL,
                    phase=4,
                    phase_name="Static Code Review (SAST)",
                    description=f"Environment file `{env_name}` found in project root but is not excluded in `.gitignore`.",
                    file_path=rel_ef,
                    evidence=f"File: {env_name} exists",
                    remediation="Add all `.env` and `.env.local` files to your `.gitignore` to prevent committing secrets to source control.",
                    owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
                )
                findings.append(finding)
                print_finding(finding)

    return PhaseResult(
        phase_number=4,
        phase_name="Static Code Review (SAST)",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        summary=f"Scanned {len(source_files)} source files. Discovered {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
