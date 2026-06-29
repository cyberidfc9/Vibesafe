"""
VibeSafe — Data Models

Core data structures used across all phases: findings, severity levels,
scan results, tech stack detection, and phase metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ─── Severity Levels ────────────────────────────────────────────────────────────

class Severity(Enum):
    """Finding severity levels, ordered from most to least critical."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "red",
            Severity.HIGH: "dark_orange",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }[self]

    @property
    def weight(self) -> int:
        """Numeric weight for scoring (higher = worse)."""
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }[self]


# ─── Phase Types ─────────────────────────────────────────────────────────────────

class PhaseType(Enum):
    """Whether a phase runs automatically, requires manual interaction, or both."""
    AUTOMATED = "automated"
    GUIDED = "guided"
    HYBRID = "hybrid"


# ─── OWASP Top 10 ───────────────────────────────────────────────────────────────

class OWASPCategory(Enum):
    """OWASP Top 10 (2021) categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 – Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 – Cryptographic Failures"
    A03_INJECTION = "A03:2021 – Injection"
    A04_INSECURE_DESIGN = "A04:2021 – Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 – Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 – Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 – Identification and Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2021 – Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 – Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 – Server-Side Request Forgery"


# ─── Finding ─────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding discovered during a scan."""
    title: str
    severity: Severity
    phase: int
    phase_name: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    evidence: str = ""
    remediation: str = ""
    owasp_category: Optional[OWASPCategory] = None
    cwe_id: Optional[str] = None
    exploitability_score: float = 5.0  # 0.0 (theoretical) to 10.0 (trivially exploitable)
    source_tool: Optional[str] = None  # e.g., "vibesafe", "semgrep", "codeql", "gitleaks"
    group_id: Optional[str] = None  # For AI triage deduplication grouping

    @property
    def risk_score(self) -> float:
        """Combined risk score (0-100) factoring severity weight + exploitability."""
        return self.severity.weight * (self.exploitability_score / 10.0)

    @property
    def risk_rating(self) -> str:
        """Human-readable risk rating based on combined risk score."""
        rs = self.risk_score
        if rs >= 30:
            return "CRITICAL"
        if rs >= 15:
            return "HIGH"
        if rs >= 8:
            return "MEDIUM"
        if rs >= 3:
            return "LOW"
        return "INFO"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "phase": self.phase,
            "phase_name": self.phase_name,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "owasp_category": self.owasp_category.value if self.owasp_category else None,
            "cwe_id": self.cwe_id,
            "exploitability_score": self.exploitability_score,
            "risk_score": self.risk_score,
            "risk_rating": self.risk_rating,
            "source_tool": self.source_tool,
        }


# ─── Phase Result ────────────────────────────────────────────────────────────────

@dataclass
class ChecklistItem:
    """An interactive checklist item for guided phases."""
    description: str
    passed: Optional[bool] = None  # None = not tested, True = passed, False = failed
    notes: str = ""


@dataclass
class PhaseResult:
    """Aggregated result from running a single phase."""
    phase_number: int
    phase_name: str
    phase_type: PhaseType
    findings: list[Finding] = field(default_factory=list)
    passed_checks: list[str] = field(default_factory=list)
    failed_checks: list[str] = field(default_factory=list)
    checklist: list[ChecklistItem] = field(default_factory=list)
    skipped: bool = False
    duration_seconds: float = 0.0
    summary: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def status_emoji(self) -> str:
        if self.skipped:
            return "⏭️"
        if self.critical_count > 0:
            return "🔴"
        if self.high_count > 0:
            return "🟠"
        if self.total_findings > 0:
            return "🟡"
        return "✅"


# ─── Tech Stack ──────────────────────────────────────────────────────────────────

@dataclass
class TechStack:
    """Detected technology stack of the scanned project."""
    framework: Optional[str] = None
    runtime: Optional[str] = None
    language: Optional[str] = None
    database: Optional[str] = None
    orm: Optional[str] = None
    auth: Optional[str] = None
    hosting: Optional[str] = None
    payments: Optional[str] = None
    storage: Optional[str] = None
    email: Optional[str] = None
    css_framework: Optional[str] = None
    package_manager: Optional[str] = None
    total_dependencies: int = 0
    api_routes_count: int = 0
    other_services: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = {}
        for fld in [
            "framework", "runtime", "language", "database", "orm", "auth",
            "hosting", "payments", "storage", "email", "css_framework",
            "package_manager",
        ]:
            val = getattr(self, fld)
            if val:
                result[fld.replace("_", " ").title()] = val
        if self.total_dependencies:
            result["Dependencies"] = str(self.total_dependencies)
        if self.api_routes_count:
            result["API Routes"] = str(self.api_routes_count)
        if self.other_services:
            result["Other Services"] = ", ".join(self.other_services)
        return result


# ─── Scan Result ─────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Complete result from a full VibeSafe security scan."""
    project_path: str
    url: Optional[str] = None
    tech_stack: Optional[TechStack] = None
    phase_results: list[PhaseResult] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    _triaged_findings: Optional[list[Finding]] = None

    @property
    def all_findings(self) -> list[Finding]:
        if self._triaged_findings is not None:
            return self._triaged_findings
        findings = []
        for pr in self.phase_results:
            findings.extend(pr.findings)
        return findings

    @property
    def severity_counts(self) -> dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity] += 1
        return counts

    @property
    def score(self) -> int:
        """Security score from 0–100. Uses exploitability-weighted risk scoring."""
        total_deduction = sum(f.risk_score for f in self.all_findings)
        return max(0, min(100, 100 - int(total_deduction)))

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 80:
            return "B"
        if s >= 70:
            return "C"
        if s >= 60:
            return "D"
        return "F"

    @property
    def grade_label(self) -> str:
        labels = {"A": "EXCELLENT", "B": "GOOD", "C": "FAIR", "D": "POOR", "F": "CRITICAL"}
        return labels[self.grade]

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


# ─── Phase Registry ──────────────────────────────────────────────────────────────

PHASE_REGISTRY: list[dict] = [
    {"number": 1, "name": "Information Gathering", "type": PhaseType.AUTOMATED},
    {"number": 2, "name": "Threat Modeling", "type": PhaseType.AUTOMATED},
    {"number": 3, "name": "Architecture Review", "type": PhaseType.AUTOMATED},
    {"number": 4, "name": "Static Code Review (SAST)", "type": PhaseType.AUTOMATED},
    {"number": 5, "name": "Dependency Security", "type": PhaseType.AUTOMATED},
    {"number": 6, "name": "Server Configuration", "type": PhaseType.HYBRID},
    {"number": 7, "name": "Authentication Testing", "type": PhaseType.AUTOMATED},
    {"number": 8, "name": "Authorization Testing", "type": PhaseType.AUTOMATED},
    {"number": 9, "name": "Input Validation", "type": PhaseType.AUTOMATED},
    {"number": 10, "name": "File Upload Review", "type": PhaseType.AUTOMATED},
    {"number": 11, "name": "API Security", "type": PhaseType.AUTOMATED},
    {"number": 12, "name": "Database Security", "type": PhaseType.AUTOMATED},
    {"number": 13, "name": "Business Logic Testing", "type": PhaseType.AUTOMATED},
    {"number": 14, "name": "OWASP Top 10 Review", "type": PhaseType.AUTOMATED},
    {"number": 15, "name": "Penetration Testing", "type": PhaseType.AUTOMATED},
    {"number": 16, "name": "Automated Vulnerability Scan", "type": PhaseType.HYBRID},
    {"number": 17, "name": "Performance & Resilience", "type": PhaseType.AUTOMATED},
    {"number": 18, "name": "Cloud Security", "type": PhaseType.AUTOMATED},
    {"number": 19, "name": "Logging & Monitoring", "type": PhaseType.AUTOMATED},
    {"number": 20, "name": "Final Security Report", "type": PhaseType.AUTOMATED},
]
