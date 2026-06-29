"""
VibeSafe — Unsafe Code Patterns

Regex patterns for detecting generally unsafe code practices:
weak crypto, debug code left in production, insecure configurations, etc.
"""

from __future__ import annotations

import re


# ─── Weak Cryptography ──────────────────────────────────────────────────────────

WEAK_CRYPTO_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "MD5 Usage",
        "MD5 is cryptographically broken — should not be used for security",
        re.compile(r'(?i)(?:createHash|hashlib\.)\s*\(\s*["\']md5["\']'),
        "Use SHA-256 or SHA-3 for checksums. Use bcrypt/argon2 for passwords."
    ),
    (
        "SHA1 Usage",
        "SHA-1 is deprecated for security purposes",
        re.compile(r'(?i)(?:createHash|hashlib\.)\s*\(\s*["\']sha1["\']'),
        "Use SHA-256 or SHA-3. Use bcrypt/argon2 for password hashing."
    ),
    (
        "Weak Random",
        "Math.random() is not cryptographically secure",
        re.compile(r'Math\.random\s*\(\s*\).*(?:token|secret|key|password|session|id|uuid)', re.IGNORECASE),
        "Use crypto.randomUUID() or crypto.getRandomValues() for security-sensitive random values."
    ),
    (
        "Insecure Hash for Password",
        "Using non-password-specific hash for passwords",
        re.compile(r'(?i)(?:sha256|sha512|sha1|md5)\s*\(\s*(?:password|passwd|pwd)'),
        "Use bcrypt, argon2, or scrypt for password hashing. Never use plain hashes."
    ),
]

# ─── Debug / Development Code ────────────────────────────────────────────────────

DEBUG_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Console.log with Sensitive Data",
        "console.log may leak sensitive data in production",
        re.compile(r'console\.log\s*\(.*(?:password|token|secret|key|credential|session|cookie)', re.IGNORECASE),
        "Remove console.log statements with sensitive data. Use a proper logger with levels."
    ),
    (
        "Debug Mode Enabled",
        "Debug mode or verbose logging enabled",
        re.compile(r'(?i)(?:DEBUG|debug)\s*[=:]\s*(?:true|True|1|["\']true["\'])'),
        "Ensure debug mode is disabled in production. Use environment-based configuration."
    ),
    (
        "TODO Security",
        "TODO/FIXME comment related to security",
        re.compile(r'(?i)(?:TODO|FIXME|HACK|XXX)\s*:?\s*.*(?:security|auth|password|token|secret|vuln|inject|xss|csrf|sanitiz)'),
        "Address security-related TODO comments before deployment."
    ),
    (
        "Commented-Out Security",
        "Security code appears to be commented out",
        re.compile(r'(?i)//\s*(?:authenticate|authorize|verify|validate|sanitize|escape|check(?:Auth|Permission|Token))'),
        "Review and re-enable commented-out security controls."
    ),
    (
        "Stack Trace in Response",
        "Error stack trace may be sent to client",
        re.compile(r'(?:\.stack|stackTrace|traceback)\s*(?:\)|,|\}|;|\])'),
        "Never send stack traces to clients. Log them server-side and return generic errors."
    ),
]

# ─── Insecure HTTP ───────────────────────────────────────────────────────────────

INSECURE_HTTP_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "HTTP URL (not HTTPS)",
        "HTTP URL used instead of HTTPS",
        re.compile(r'["\']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"\']+["\']'),
        "Use HTTPS for all external URLs to prevent man-in-the-middle attacks."
    ),
    (
        "TLS Verification Disabled",
        "TLS/SSL certificate verification is disabled",
        re.compile(r'(?i)(?:rejectUnauthorized|verify)\s*[=:]\s*(?:false|False|0)'),
        "Never disable TLS verification in production. Fix certificate issues properly."
    ),
    (
        "CORS Allow All",
        "CORS configured to allow all origins",
        re.compile(r'''(?i)(?:access-control-allow-origin|cors)\s*[=:]\s*['"]\*['"]'''),
        "Restrict CORS to specific allowed origins. Wildcard '*' allows any site to make requests."
    ),
]

# ─── Insecure Configuration ─────────────────────────────────────────────────────

INSECURE_CONFIG_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Insecure Cookie",
        "Cookie set without Secure, HttpOnly, or SameSite flags",
        re.compile(r'(?i)(?:set-cookie|cookie)\s*[=:]\s*["\'][^"\']*(?!.*(?:secure|httponly|samesite))'),
        "Set Secure, HttpOnly, and SameSite attributes on all sensitive cookies."
    ),
    (
        "Disabled CSRF",
        "CSRF protection appears to be disabled",
        re.compile(r'(?i)(?:csrf|xsrf)\s*[=:]\s*(?:false|False|disabled|off)'),
        "Enable CSRF protection. Use CSRF tokens for state-changing operations."
    ),
    (
        "Helmet Disabled",
        "Security middleware (Helmet.js) appears disabled",
        re.compile(r'(?i)(?:helmet|security)\s*[=:]\s*(?:false|disabled)'),
        "Enable security middleware for proper HTTP security headers."
    ),
    (
        "Open Redirect",
        "Potential open redirect using user-controlled redirect URL",
        re.compile(r'(?:redirect|location\.href|window\.location)\s*[=(]\s*(?:req\.|request\.|params\.|query\.|body\.)'),
        "Validate redirect URLs against a whitelist. Never redirect to user-controlled URLs."
    ),
]

# ─── Unsafe Deserialization ──────────────────────────────────────────────────────

DESERIALIZATION_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Unsafe YAML Load (Python)",
        "yaml.load() without SafeLoader — arbitrary code execution risk",
        re.compile(r'yaml\.load\s*\([^)]*\)(?!.*(?:SafeLoader|safe_load))'),
        "Use yaml.safe_load() instead of yaml.load()."
    ),
    (
        "Pickle Load (Python)",
        "pickle.load() — unsafe deserialization allows arbitrary code execution",
        re.compile(r'pickle\.(?:load|loads)\s*\('),
        "Avoid pickle for untrusted data. Use JSON or a safe serialization format."
    ),
    (
        "JSON Parse without Try/Catch",
        "JSON.parse() usage — ensure it is wrapped in try/catch to handle malformed input",
        re.compile(r'JSON\.parse\s*\('),
        "Wrap JSON.parse() in try/catch to handle malformed input gracefully."
    ),
]

# ─── File Operations ─────────────────────────────────────────────────────────────

UNSAFE_FILE_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Executable Upload Path",
        "Uploaded files stored in a publicly accessible / executable directory",
        re.compile(r'(?i)(?:upload|save|store).*(?:public|static|www|htdocs|webroot)'),
        "Store uploads outside the web root. Serve them through a controlled endpoint."
    ),
    (
        "No File Type Validation",
        "File accepted without type/extension validation",
        re.compile(r'(?i)(?:multer|formidable|busboy|upload)\s*\(\s*\{[^}]*\}'),
        "Validate file types, extensions, and MIME types. Use an allowlist approach."
    ),
]

# ─── Combined Export ─────────────────────────────────────────────────────────────

ALL_UNSAFE_PATTERNS = (
    WEAK_CRYPTO_PATTERNS +
    DEBUG_PATTERNS +
    INSECURE_HTTP_PATTERNS +
    INSECURE_CONFIG_PATTERNS +
    DESERIALIZATION_PATTERNS +
    UNSAFE_FILE_PATTERNS
)
