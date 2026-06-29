"""
VibeSafe — CWE Database

Maps CWE IDs to human-readable names, descriptions, OWASP Top 10 categories,
and default exploitability scores for risk-based prioritization.
"""

from __future__ import annotations

from typing import Optional
from vibesafe.models import OWASPCategory


# ─── CWE Entry Structure ────────────────────────────────────────────────────────
# Each entry: (CWE-ID, Name, Description, OWASP Category, Default Exploitability 0-10)

CWE_DATABASE: dict[str, dict] = {
    # ── Injection ────────────────────────────────────────────────────────────
    "CWE-79": {
        "name": "Cross-site Scripting (XSS)",
        "description": "Improper neutralization of input during web page generation allows attackers to inject malicious scripts.",
        "owasp": OWASPCategory.A03_INJECTION,
        "exploitability": 8.0,
    },
    "CWE-89": {
        "name": "SQL Injection",
        "description": "Improper neutralization of special elements used in SQL commands allows attackers to execute arbitrary queries.",
        "owasp": OWASPCategory.A03_INJECTION,
        "exploitability": 9.5,
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "Improper neutralization of special elements used in OS commands allows attackers to execute arbitrary system commands.",
        "owasp": OWASPCategory.A03_INJECTION,
        "exploitability": 9.0,
    },
    "CWE-94": {
        "name": "Code Injection",
        "description": "Improper control of code generation allows attackers to inject and execute arbitrary code.",
        "owasp": OWASPCategory.A03_INJECTION,
        "exploitability": 9.0,
    },
    "CWE-77": {
        "name": "Command Injection",
        "description": "Improper neutralization of special elements used in a command.",
        "owasp": OWASPCategory.A03_INJECTION,
        "exploitability": 9.0,
    },
    "CWE-90": {
        "name": "LDAP Injection",
        "description": "Improper neutralization of special elements used in LDAP queries.",
        "owasp": OWASPCategory.A03_INJECTION,
        "exploitability": 7.5,
    },
    "CWE-917": {
        "name": "Expression Language Injection",
        "description": "Improper neutralization of special elements in expression language statements.",
        "owasp": OWASPCategory.A03_INJECTION,
        "exploitability": 8.0,
    },

    # ── Broken Access Control ────────────────────────────────────────────────
    "CWE-284": {
        "name": "Improper Access Control",
        "description": "The software does not restrict or incorrectly restricts access to a resource.",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "exploitability": 7.0,
    },
    "CWE-639": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "description": "The system's authorization relies on user-supplied object identifiers without verifying ownership.",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "exploitability": 8.5,
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "description": "The software does not perform authorization checks for critical operations.",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "exploitability": 8.0,
    },
    "CWE-863": {
        "name": "Incorrect Authorization",
        "description": "The software performs authorization checks incorrectly, allowing unauthorized access.",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "exploitability": 7.5,
    },
    "CWE-22": {
        "name": "Path Traversal",
        "description": "Improper limitation of a pathname to a restricted directory allows attackers to access files outside intended boundaries.",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "exploitability": 8.0,
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The application can be made to send crafted requests to internal or external resources.",
        "owasp": OWASPCategory.A10_SSRF,
        "exploitability": 7.5,
    },

    # ── Cryptographic Failures ───────────────────────────────────────────────
    "CWE-327": {
        "name": "Use of Broken Crypto Algorithm",
        "description": "Use of a broken or risky cryptographic algorithm (e.g., MD5, SHA1, DES).",
        "owasp": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
        "exploitability": 5.0,
    },
    "CWE-328": {
        "name": "Reversible One-Way Hash",
        "description": "Use of a weak one-way hash that can be reversed or collided.",
        "owasp": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
        "exploitability": 5.0,
    },
    "CWE-330": {
        "name": "Insufficient Randomness",
        "description": "Use of insufficiently random values for security-critical operations.",
        "owasp": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
        "exploitability": 6.0,
    },
    "CWE-312": {
        "name": "Cleartext Storage of Sensitive Info",
        "description": "Sensitive information is stored in cleartext without encryption.",
        "owasp": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
        "exploitability": 6.5,
    },
    "CWE-319": {
        "name": "Cleartext Transmission of Sensitive Info",
        "description": "Sensitive data is transmitted over an unencrypted channel.",
        "owasp": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
        "exploitability": 7.0,
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "description": "The software contains hardcoded passwords, API keys, or cryptographic keys.",
        "owasp": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
        "exploitability": 9.0,
    },
    "CWE-321": {
        "name": "Hardcoded Cryptographic Key",
        "description": "A hardcoded cryptographic key increases the possibility that encrypted data may be recovered.",
        "owasp": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
        "exploitability": 8.0,
    },

    # ── Insecure Design ──────────────────────────────────────────────────────
    "CWE-209": {
        "name": "Error Message Information Leak",
        "description": "Error messages expose sensitive implementation details (stack traces, DB queries).",
        "owasp": OWASPCategory.A04_INSECURE_DESIGN,
        "exploitability": 4.0,
    },
    "CWE-250": {
        "name": "Execution with Unnecessary Privileges",
        "description": "The software executes with more privileges than necessary.",
        "owasp": OWASPCategory.A04_INSECURE_DESIGN,
        "exploitability": 5.0,
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "The application does not verify that requests originated from an authorized user.",
        "owasp": OWASPCategory.A04_INSECURE_DESIGN,
        "exploitability": 6.5,
    },
    "CWE-362": {
        "name": "Race Condition",
        "description": "Concurrent execution using shared resources with improper synchronization.",
        "owasp": OWASPCategory.A04_INSECURE_DESIGN,
        "exploitability": 5.0,
    },

    # ── Security Misconfiguration ────────────────────────────────────────────
    "CWE-16": {
        "name": "Configuration",
        "description": "Software configuration weakness that can lead to security issues.",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        "exploitability": 5.0,
    },
    "CWE-200": {
        "name": "Information Exposure",
        "description": "The software exposes sensitive information to an unauthorized actor.",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        "exploitability": 5.0,
    },
    "CWE-532": {
        "name": "Information Leak Through Log Files",
        "description": "Sensitive information is written to log files accessible to unauthorized users.",
        "owasp": OWASPCategory.A09_LOGGING_FAILURES,
        "exploitability": 4.5,
    },
    "CWE-614": {
        "name": "Sensitive Cookie Without Secure Flag",
        "description": "A session cookie is sent without the Secure attribute, making it vulnerable to interception.",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        "exploitability": 5.0,
    },
    "CWE-1004": {
        "name": "Sensitive Cookie Without HttpOnly Flag",
        "description": "A session cookie is accessible to JavaScript, enabling XSS-based session hijacking.",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        "exploitability": 6.0,
    },

    # ── Vulnerable Components ────────────────────────────────────────────────
    "CWE-1104": {
        "name": "Use of Unmaintained Third-Party Components",
        "description": "The product relies on third-party components that are no longer actively maintained.",
        "owasp": OWASPCategory.A06_VULNERABLE_COMPONENTS,
        "exploitability": 4.0,
    },

    # ── Auth Failures ────────────────────────────────────────────────────────
    "CWE-287": {
        "name": "Improper Authentication",
        "description": "The software does not properly verify the identity of the user.",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "exploitability": 8.0,
    },
    "CWE-307": {
        "name": "Improper Restriction of Excessive Authentication Attempts",
        "description": "No rate limiting on authentication attempts allows brute-force attacks.",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "exploitability": 7.0,
    },
    "CWE-384": {
        "name": "Session Fixation",
        "description": "The application does not regenerate session IDs after authentication.",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "exploitability": 6.0,
    },
    "CWE-521": {
        "name": "Weak Password Requirements",
        "description": "The software does not enforce sufficient password complexity requirements.",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "exploitability": 5.0,
    },
    "CWE-613": {
        "name": "Insufficient Session Expiration",
        "description": "Sessions do not expire or have excessively long expiration times.",
        "owasp": OWASPCategory.A07_AUTH_FAILURES,
        "exploitability": 5.0,
    },

    # ── Integrity Failures ───────────────────────────────────────────────────
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The application deserializes data from untrusted sources without validation.",
        "owasp": OWASPCategory.A08_INTEGRITY_FAILURES,
        "exploitability": 8.5,
    },
    "CWE-829": {
        "name": "Inclusion of Functionality from Untrusted Control Sphere",
        "description": "The software imports functionality from a source outside of its trust boundary.",
        "owasp": OWASPCategory.A08_INTEGRITY_FAILURES,
        "exploitability": 6.0,
    },

    # ── Logging Failures ─────────────────────────────────────────────────────
    "CWE-778": {
        "name": "Insufficient Logging",
        "description": "Security-critical events are not logged, hindering forensic investigation.",
        "owasp": OWASPCategory.A09_LOGGING_FAILURES,
        "exploitability": 2.0,
    },
    "CWE-117": {
        "name": "Log Injection",
        "description": "User-controlled data is written to logs without neutralization.",
        "owasp": OWASPCategory.A09_LOGGING_FAILURES,
        "exploitability": 4.0,
    },

    # ── SSRF ─────────────────────────────────────────────────────────────────
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The server can be tricked into making requests to unintended locations.",
        "owasp": OWASPCategory.A10_SSRF,
        "exploitability": 7.5,
    },

    # ── File Upload ──────────────────────────────────────────────────────────
    "CWE-434": {
        "name": "Unrestricted Upload of File with Dangerous Type",
        "description": "The software allows upload of dangerous file types that can be executed on the server.",
        "owasp": OWASPCategory.A04_INSECURE_DESIGN,
        "exploitability": 8.0,
    },

    # ── Miscellaneous ────────────────────────────────────────────────────────
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "description": "The software does not properly control the allocation of resources, leading to denial of service.",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        "exploitability": 5.0,
    },
    "CWE-601": {
        "name": "Open Redirect",
        "description": "The application redirects users to untrusted URLs based on user input.",
        "owasp": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        "exploitability": 5.5,
    },
    "CWE-611": {
        "name": "XML External Entity (XXE) Injection",
        "description": "The software processes XML input containing references to external entities.",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        "exploitability": 7.0,
    },
    "CWE-942": {
        "name": "Permissive CORS Policy",
        "description": "Overly permissive Cross-Origin Resource Sharing policy allows unauthorized domains to access resources.",
        "owasp": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        "exploitability": 5.0,
    },
}


def get_cwe_info(cwe_id: Optional[str]) -> Optional[dict]:
    """Look up CWE info by ID (e.g., 'CWE-79' or '79')."""
    if not cwe_id:
        return None
    # Normalize: accept '79' or 'CWE-79'
    normalized = cwe_id.strip()
    if not normalized.upper().startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return CWE_DATABASE.get(normalized.upper())


def get_cwe_name(cwe_id: Optional[str]) -> str:
    """Get human-readable CWE name, or the raw ID if not in database."""
    info = get_cwe_info(cwe_id)
    if info:
        return f"{cwe_id}: {info['name']}"
    return cwe_id or "Unknown"


def get_cwe_owasp(cwe_id: Optional[str]) -> Optional[OWASPCategory]:
    """Get the OWASP category for a CWE ID."""
    info = get_cwe_info(cwe_id)
    if info:
        return info.get("owasp")
    return None


def get_default_exploitability(cwe_id: Optional[str]) -> float:
    """Get default exploitability score (0-10) for a CWE ID."""
    info = get_cwe_info(cwe_id)
    if info:
        return info.get("exploitability", 5.0)
    return 5.0


def get_all_cwes() -> list[str]:
    """Return all CWE IDs in the database."""
    return sorted(CWE_DATABASE.keys())
