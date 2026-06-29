"""
Phase 18: Cloud Security (Automated Scanner)
"""

import time
import re
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import walk_source_files, walk_all_files, read_file_safe, find_files_by_name
from vibesafe.ui import print_finding, print_passed_check, print_failed_check, print_info

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    passed_checks = []
    failed_checks = []

    # ── Cloud Provider Detection ──────────────────────────────────────────
    detected_providers = []
    provider_files = {
        "vercel.json": "Vercel",
        "netlify.toml": "Netlify",
        "firebase.json": "Firebase/GCP",
        "fly.toml": "Fly.io",
        "render.yaml": "Render",
        "Dockerfile": "Docker",
        "docker-compose.yml": "Docker",
        "docker-compose.yaml": "Docker",
    }
    for fname, provider in provider_files.items():
        matches = find_files_by_name(config, [fname])
        if matches and provider not in detected_providers:
            detected_providers.append(provider)

    if detected_providers:
        print_info(f"Cloud providers detected: {', '.join(detected_providers)}")
    else:
        print_info("No cloud provider config files detected.")

    # ── 1. Firebase Rules Check ───────────────────────────────────────────
    firebase_rules_files = find_files_by_name(config, [
        "firestore.rules", "storage.rules", "database.rules.json",
    ])
    if firebase_rules_files:
        for rules_file in firebase_rules_files:
            content = read_file_safe(rules_file) or ""
            # Check for overly permissive rules
            if re.search(r"allow\s+read\s*,\s*write\s*:\s*if\s+true", content, re.IGNORECASE) or \
               re.search(r"allow\s+read\s*,\s*write\s*;", content, re.IGNORECASE) or \
               re.search(r'"\.read"\s*:\s*true.*"\.write"\s*:\s*true', content, re.IGNORECASE):
                failed_checks.append(f"Overly permissive Firebase rules in {rules_file.name}")
                print_failed_check(f"Firebase Rules: {rules_file.name} allows unrestricted read/write access!")
                findings.append(Finding(
                    title="Overly Permissive Firebase Security Rules",
                    severity=Severity.CRITICAL,
                    phase=18,
                    phase_name="Cloud Security",
                    description=f"Firebase security rules in `{rules_file.name}` allow unrestricted read and write access (`allow read, write: if true`). Anyone can read/modify your entire database.",
                    file_path=str(rules_file.name),
                    evidence="allow read, write: if true",
                    remediation="Restrict Firebase rules to authenticated users only: `allow read, write: if request.auth != null;` and add ownership checks.",
                    owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
                ))
            else:
                passed_checks.append(f"Firebase rules in {rules_file.name} have conditions")
                print_passed_check(f"Firebase Rules: {rules_file.name} has conditional access controls.")

    # ── 2. Docker Security ────────────────────────────────────────────────
    dockerfiles = find_files_by_name(config, ["Dockerfile"])
    for dockerfile in dockerfiles:
        content = read_file_safe(dockerfile) or ""

        # Check for running as root
        has_user_directive = bool(re.search(r"^USER\s+\S+", content, re.MULTILINE | re.IGNORECASE))
        runs_as_root = bool(re.search(r"^USER\s+root", content, re.MULTILINE | re.IGNORECASE))

        if runs_as_root or not has_user_directive:
            failed_checks.append("Docker container runs as root")
            print_failed_check("Docker: Container runs as root user (no non-root USER directive).")
            findings.append(Finding(
                title="Docker Container Running as Root",
                severity=Severity.MEDIUM,
                phase=18,
                phase_name="Cloud Security",
                description="The Dockerfile does not specify a non-root USER, meaning the container runs as root. A container escape vulnerability would give full host access.",
                file_path=str(dockerfile.name),
                evidence="No `USER <non-root>` directive found in Dockerfile.",
                remediation="Add `RUN adduser -D appuser && USER appuser` (or equivalent) to the Dockerfile to run as a non-root user.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            ))
        else:
            passed_checks.append("Docker container uses non-root user")
            print_passed_check("Docker: Container specifies a non-root USER directive.")

        # Check for --privileged or dangerous flags in compose
        if re.search(r"privileged:\s*true|--privileged", content, re.IGNORECASE):
            failed_checks.append("Docker container runs in privileged mode")
            print_failed_check("Docker: Container runs in privileged mode!")
            findings.append(Finding(
                title="Docker Privileged Mode Enabled",
                severity=Severity.CRITICAL,
                phase=18,
                phase_name="Cloud Security",
                description="The Docker configuration enables privileged mode, giving the container full access to host devices and kernel capabilities.",
                file_path=str(dockerfile.name),
                evidence="privileged: true",
                remediation="Remove `privileged: true` and use specific capabilities (`cap_add`) only when absolutely necessary.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            ))

    # Also check docker-compose files
    compose_files = find_files_by_name(config, ["docker-compose.yml", "docker-compose.yaml"])
    for compose_file in compose_files:
        content = read_file_safe(compose_file) or ""
        if re.search(r"privileged:\s*true", content, re.IGNORECASE):
            failed_checks.append("docker-compose uses privileged mode")
            print_failed_check(f"Docker: {compose_file.name} uses privileged mode!")
            findings.append(Finding(
                title="Docker Compose Privileged Mode",
                severity=Severity.CRITICAL,
                phase=18,
                phase_name="Cloud Security",
                description="docker-compose configuration enables privileged mode on a service container.",
                file_path=str(compose_file.name),
                evidence="privileged: true in docker-compose",
                remediation="Remove `privileged: true` from docker-compose services.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            ))

    # ── 3. Cloud Credential Exposure ──────────────────────────────────────
    cloud_cred_findings = []
    aws_key_pat = re.compile(r"AKIA[0-9A-Z]{16}")  # AWS Access Key ID prefix
    firebase_sa_pat = re.compile(r"\"type\":\s*\"service_account\"", re.IGNORECASE)
    gcloud_key_pat = re.compile(r"gcloud.*key|google_application_credentials", re.IGNORECASE)

    for filepath in walk_source_files(config):
        if "vibesafe" in filepath.parts:
            continue
        # Only check source code files, not .env
        if filepath.suffix in [".env", ".example"]:
            continue
        content = read_file_safe(filepath)
        if not content:
            continue

        if aws_key_pat.search(content):
            cloud_cred_findings.append((filepath.name, "AWS Access Key (AKIA...)"))
        if firebase_sa_pat.search(content) and filepath.suffix in [".js", ".ts", ".py", ".go"]:
            cloud_cred_findings.append((filepath.name, "Firebase Service Account JSON"))

    if cloud_cred_findings:
        for filename, cred_type in cloud_cred_findings[:3]:
            failed_checks.append(f"Exposed cloud credential in {filename}")
            print_failed_check(f"Cloud Credentials: {cred_type} found hardcoded in {filename}.")
            findings.append(Finding(
                title=f"Exposed Cloud Credential: {cred_type}",
                severity=Severity.CRITICAL,
                phase=18,
                phase_name="Cloud Security",
                description=f"A cloud provider credential ({cred_type}) was found hardcoded in source file `{filename}`. This allows full cloud account compromise if the code is pushed to a public repo.",
                file_path=filename,
                evidence=cred_type,
                remediation="Remove hardcoded credentials immediately. Use environment variables or a secrets manager (AWS Secrets Manager, Vercel Env, GCP Secret Manager).",
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
            ))
    else:
        passed_checks.append("No hardcoded cloud credentials detected")
        print_passed_check("Cloud Credentials: No hardcoded AWS keys or service account JSONs found.")

    # ── 4. S3 / Storage Bucket Permissions ────────────────────────────────
    has_public_bucket = False
    bucket_pat = re.compile(r"ACL.*public-read|publicreadaccess|blockpublicaccess.*false|public.*bucket", re.IGNORECASE)

    for filepath in walk_source_files(config):
        if "vibesafe" in filepath.parts:
            continue
        content = read_file_safe(filepath)
        if not content:
            continue
        if bucket_pat.search(content):
            has_public_bucket = True
            failed_checks.append(f"Public cloud storage bucket config in {filepath.name}")
            print_failed_check(f"Storage Buckets: Public bucket access configured in {filepath.name}.")
            findings.append(Finding(
                title="Public Cloud Storage Bucket Configuration",
                severity=Severity.CRITICAL,
                phase=18,
                phase_name="Cloud Security",
                description="Cloud storage bucket (S3/GCS) is configured with public read access, potentially exposing sensitive uploaded files to the internet.",
                file_path=str(filepath.name),
                evidence="ACL: public-read or BlockPublicAccess: false",
                remediation="Set bucket ACL to private. Use pre-signed URLs for temporary access and enable BlockPublicAccess on AWS S3.",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL
            ))
            break

    if not has_public_bucket:
        passed_checks.append("No publicly accessible storage bucket configurations found")
        print_passed_check("Storage Buckets: No public bucket ACL configurations detected.")

    # ── 5. Vercel/Netlify Config Checks ───────────────────────────────────
    vercel_configs = find_files_by_name(config, ["vercel.json"])
    for vc in vercel_configs:
        content = read_file_safe(vc) or ""
        # Check for env vars in vercel.json (should use Vercel dashboard instead)
        if re.search(r'"env"\s*:', content):
            failed_checks.append("Environment variables defined in vercel.json")
            print_failed_check("Vercel Config: Environment variables are defined in vercel.json (should use Vercel dashboard).")
            findings.append(Finding(
                title="Environment Variables in vercel.json",
                severity=Severity.MEDIUM,
                phase=18,
                phase_name="Cloud Security",
                description="Environment variables are defined directly in vercel.json which gets committed to git. Secrets should be managed via the Vercel dashboard.",
                file_path="vercel.json",
                evidence='"env": { ... } in vercel.json',
                remediation="Move environment variables to the Vercel dashboard (Settings > Environment Variables) instead of committing them in vercel.json.",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
            ))

    return PhaseResult(
        phase_number=18,
        phase_name="Cloud Security",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Cloud security scan completed. Found {len(findings)} issues.",
        duration_seconds=time.time() - start_time
    )
