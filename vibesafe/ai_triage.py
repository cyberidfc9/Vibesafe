"""
VibeSafe — AI-Powered Finding Triage & Prioritization

A local heuristic engine that intelligently scores, deduplicates, groups,
and prioritizes security findings based on exploitability context rather
than raw severity alone.

No external API calls — all logic runs locally.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

from vibesafe.models import Finding, Severity, ScanResult
from vibesafe.cwe_database import get_cwe_info, get_default_exploitability


# ─── Exploitability Context Signals ──────────────────────────────────────────────

# Patterns that indicate public-facing / high-risk code locations
PUBLIC_FACING_PATTERNS = [
    re.compile(r"(app|pages|routes)/(api|auth|login|signup|register|payment|checkout)", re.I),
    re.compile(r"(public|static|www|dist)/", re.I),
    re.compile(r"\.(html|htm|php|asp|jsp)$", re.I),
    re.compile(r"(controller|handler|view|endpoint|webhook)", re.I),
]

# Patterns that indicate internal/protected code (lower exploitability)
INTERNAL_PATTERNS = [
    re.compile(r"(test|spec|__test__|__spec__|fixture|mock|stub)", re.I),
    re.compile(r"(internal|private|admin|backoffice|migration|seed)", re.I),
    re.compile(r"\.(test|spec)\.(js|ts|py|rb)$", re.I),
]

# Patterns indicating the finding is in authentication-critical code
AUTH_CRITICAL_PATTERNS = [
    re.compile(r"(auth|login|session|token|jwt|oauth|password|credential|signup|register)", re.I),
]

# Patterns indicating payment/financial code
PAYMENT_PATTERNS = [
    re.compile(r"(payment|stripe|razorpay|paypal|billing|invoice|checkout|transaction|order)", re.I),
]


def compute_exploitability(finding: Finding) -> float:
    """
    Compute exploitability score (0.0-10.0) for a finding based on context.

    Factors:
    1. CWE default exploitability baseline
    2. File path context (public-facing vs internal)
    3. Whether the vulnerable code is in auth/payment critical paths
    4. Evidence complexity (simple match vs complex pattern)
    """
    # Start with CWE baseline or severity-based default
    if finding.cwe_id:
        base_score = get_default_exploitability(finding.cwe_id)
    else:
        base_score = {
            Severity.CRITICAL: 8.0,
            Severity.HIGH: 6.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }.get(finding.severity, 5.0)

    modifier = 0.0
    file_path = finding.file_path or ""

    # Boost: public-facing code is more exploitable
    if any(p.search(file_path) for p in PUBLIC_FACING_PATTERNS):
        modifier += 1.5

    # Reduce: test/internal code is less exploitable in production
    if any(p.search(file_path) for p in INTERNAL_PATTERNS):
        modifier -= 2.5

    # Boost: auth-critical code has higher impact
    if any(p.search(file_path) for p in AUTH_CRITICAL_PATTERNS):
        modifier += 1.0

    # Boost: payment code has very high impact
    if any(p.search(file_path) for p in PAYMENT_PATTERNS):
        modifier += 1.5

    # Boost: if evidence shows actual secret values (not just patterns)
    if finding.evidence:
        evidence_lower = finding.evidence.lower()
        if any(kw in evidence_lower for kw in ["password", "secret", "token", "key=", "apikey"]):
            modifier += 0.5

    # Clamp to 0.0 - 10.0
    return max(0.0, min(10.0, base_score + modifier))


def generate_explanation(finding: Finding) -> str:
    """
    Generate a human-readable 'why this matters' explanation for a finding.
    """
    explanations = []

    # Severity context
    sev_context = {
        Severity.CRITICAL: "This is a critical-severity issue that could lead to full system compromise.",
        Severity.HIGH: "This high-severity issue poses a significant security risk.",
        Severity.MEDIUM: "This medium-severity issue should be addressed in the near term.",
        Severity.LOW: "This low-severity issue represents a minor security concern.",
        Severity.INFO: "This is an informational finding for awareness.",
    }
    explanations.append(sev_context.get(finding.severity, ""))

    # CWE context
    if finding.cwe_id:
        cwe_info = get_cwe_info(finding.cwe_id)
        if cwe_info:
            explanations.append(f"Classified as {finding.cwe_id} ({cwe_info['name']}): {cwe_info['description']}")

    # Exploitability context
    if finding.exploitability_score >= 8.0:
        explanations.append("⚠️ HIGH EXPLOITABILITY — This vulnerability is trivially exploitable and should be prioritized immediately.")
    elif finding.exploitability_score >= 6.0:
        explanations.append("This vulnerability has a moderate-to-high exploitability rating.")
    elif finding.exploitability_score <= 3.0:
        explanations.append("This vulnerability has low real-world exploitability, but should still be tracked.")

    # File context
    file_path = finding.file_path or ""
    if any(p.search(file_path) for p in AUTH_CRITICAL_PATTERNS):
        explanations.append("📍 Located in authentication-critical code — compromise here affects all user accounts.")
    if any(p.search(file_path) for p in PAYMENT_PATTERNS):
        explanations.append("💳 Located in payment/financial code — exploitation could lead to financial losses.")
    if any(p.search(file_path) for p in INTERNAL_PATTERNS):
        explanations.append("🔒 Located in test/internal code — lower production risk, but should be reviewed.")

    return " ".join(explanations)


def _make_group_key(finding: Finding) -> str:
    """Create a grouping key for deduplication."""
    return f"{finding.title}|{finding.severity.value}|{finding.cwe_id or 'none'}|{finding.source_tool or 'vibesafe'}"


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Smart deduplication: group identical findings (same title, severity, CWE)
    across multiple files into a single representative finding with count.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        key = _make_group_key(finding)
        groups[key].append(finding)

    deduplicated = []
    group_counter = 0

    for key, group in groups.items():
        group_counter += 1
        group_id = f"GRP-{group_counter:04d}"

        if len(group) == 1:
            # Single finding — keep as-is but assign group ID
            finding = group[0]
            finding.group_id = group_id
            deduplicated.append(finding)
        else:
            # Multiple instances — create a representative finding
            representative = group[0]
            representative.group_id = group_id

            # List all affected files in description
            affected_files = sorted(set(f.file_path for f in group if f.file_path))
            file_list = ", ".join(affected_files[:10])
            if len(affected_files) > 10:
                file_list += f" ... and {len(affected_files) - 10} more"

            representative.description = (
                f"{representative.description}\n\n"
                f"📊 **{len(group)} instances found** across: {file_list}"
            )

            # Use the highest exploitability score from the group
            representative.exploitability_score = max(f.exploitability_score for f in group)

            deduplicated.append(representative)

    return deduplicated


def cross_tool_dedup(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicates where multiple tools found the same issue in the same file/line.
    Prefers: codeql > semgrep > trivy > gitleaks > vibesafe (tool specificity order).
    """
    tool_priority = {"codeql": 5, "semgrep": 4, "trivy": 3, "gitleaks": 2, "nuclei": 1, "vibesafe": 0, None: 0}

    # Group by file + line + similar title
    location_groups: dict[str, list[Finding]] = defaultdict(list)
    no_location = []

    for finding in findings:
        if finding.file_path and finding.line_number:
            loc_key = f"{finding.file_path}:{finding.line_number}"
            location_groups[loc_key].append(finding)
        else:
            no_location.append(finding)

    result = list(no_location)

    for loc_key, group in location_groups.items():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Keep the finding from the highest-priority tool
            group.sort(key=lambda f: tool_priority.get(f.source_tool, 0), reverse=True)
            best = group[0]
            other_tools = set(f.source_tool for f in group[1:] if f.source_tool)
            if other_tools:
                best.description += f"\n\n🔍 Also detected by: {', '.join(other_tools)}"
            result.append(best)

    return result


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """
    Sort findings by risk-to-effort ratio (most actionable first).

    Priority order:
    1. Critical + high exploitability (immediate action required)
    2. High + high exploitability
    3. Critical + low exploitability
    4. High + low exploitability
    5. Medium findings
    6. Low findings
    7. Info findings
    """
    return sorted(findings, key=lambda f: (-f.risk_score, -f.exploitability_score))


def run_ai_triage(scan_result: ScanResult) -> list[Finding]:
    """
    Main entry point: run the full AI triage pipeline on all scan findings.

    Steps:
    1. Score exploitability for each finding
    2. Generate human-readable explanations
    3. Cross-tool deduplication
    4. Smart grouping of repeated findings
    5. Prioritize by risk-to-effort ratio

    Returns the triaged, deduplicated, prioritized list of findings.
    """
    all_findings = list(scan_result.all_findings)

    if not all_findings:
        return []

    # Step 1: Score exploitability
    for finding in all_findings:
        finding.exploitability_score = compute_exploitability(finding)

    # Step 2: Generate explanations (append to description)
    for finding in all_findings:
        explanation = generate_explanation(finding)
        if explanation and "⚠️" in explanation:
            # Only add AI explanation for high-priority items to avoid noise
            finding.description = f"{finding.description}\n\n🤖 **AI Analysis:** {explanation}"

    # Step 3: Cross-tool deduplication
    all_findings = cross_tool_dedup(all_findings)

    # Step 4: Smart grouping
    all_findings = deduplicate_findings(all_findings)

    # Step 5: Prioritize
    all_findings = prioritize_findings(all_findings)

    return all_findings
