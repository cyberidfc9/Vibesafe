"""
VibeSafe — Framework-Specific Security Patterns

Patterns for detecting security anti-patterns specific to popular web frameworks:
Next.js, React, Vue, Express, Django, Flask, etc.
"""

from __future__ import annotations

import re


# ─── Next.js Specific ────────────────────────────────────────────────────────────

NEXTJS_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Next.js API Route No Auth",
        "Next.js API route handler without authentication check",
        re.compile(r'export\s+(?:default\s+)?(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH|handler)\s*\('),
        "Add authentication middleware. Verify session/token at the start of every API route."
    ),
    (
        "Server Action without Validation",
        "Next.js Server Action without input validation",
        re.compile(r'["\']use server["\']'),
        "Validate all inputs in Server Actions. Use zod or similar schema validation."
    ),
    (
        "Client-Side Secret Access",
        "Accessing non-NEXT_PUBLIC env var might leak to client",
        re.compile(r'(?:process\.env\.)(?!NEXT_PUBLIC_)[A-Z_]+.*(?:["\']use client["\']|client)', re.DOTALL),
        "Only NEXT_PUBLIC_ prefixed env vars are safe for client components."
    ),
    (
        "Next.js Redirect Without Validation",
        "redirect() with user input — open redirect risk",
        re.compile(r'redirect\s*\(\s*(?:req|request|params|searchParams|query)'),
        "Validate redirect destinations against a whitelist of allowed paths."
    ),
    (
        "Missing Next.js Security Headers",
        "next.config with no security headers defined",
        re.compile(r'(?:module\.exports|export\s+default)\s*=?\s*\{(?![\s\S]*headers)[\s\S]*\}'),
        "Add security headers in next.config.js using the headers() function."
    ),
]

# ─── Express.js Specific ─────────────────────────────────────────────────────────

EXPRESS_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Express No Helmet",
        "Express app without helmet() security middleware",
        re.compile(r'express\s*\(\s*\)(?![\s\S]{0,500}helmet)'),
        "Install and use helmet: app.use(helmet()) for security headers."
    ),
    (
        "Express No Rate Limit",
        "Express app without rate limiting middleware",
        re.compile(r'express\s*\(\s*\)(?![\s\S]{0,1000}(?:rateLimit|rate-limit|limiter))'),
        "Add rate limiting: npm install express-rate-limit and apply to routes."
    ),
    (
        "Express Trust Proxy",
        "Express trust proxy setting — ensure it's correctly configured",
        re.compile(r'(?:trust\s+proxy|trust proxy)\s*[=,]\s*(?:true|1|["\']true["\'])'),
        "Set trust proxy to a specific number of proxies, not just 'true'."
    ),
    (
        "Express Error Handler Leaks Info",
        "Express error handler may leak stack traces",
        re.compile(r'(?:err|error)\.(?:stack|message)\s*(?:\)|,|\})', re.IGNORECASE),
        "Return generic error messages in production. Log detailed errors server-side."
    ),
]

# ─── React Specific ──────────────────────────────────────────────────────────────

REACT_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "React Ref to DOM for HTML",
        "Using ref.current.innerHTML — bypasses React's XSS protection",
        re.compile(r'(?:ref|Ref)\.current\.innerHTML'),
        "Use React's state and rendering. If raw HTML is needed, sanitize with DOMPurify."
    ),
    (
        "Storing Secrets in State",
        "Sensitive data stored in React state (visible in DevTools)",
        re.compile(r'useState\s*\(\s*.*(?:token|secret|password|apiKey|api_key)', re.IGNORECASE),
        "Don't store secrets in React state. Use HTTP-only cookies or server-side sessions."
    ),
    (
        "LocalStorage for Tokens",
        "Storing auth tokens in localStorage — vulnerable to XSS",
        re.compile(r'localStorage\.setItem\s*\(\s*["\'](?:token|auth|jwt|session|access_token)', re.IGNORECASE),
        "Use HTTP-only cookies instead of localStorage for auth tokens."
    ),
]

# ─── Django Specific ─────────────────────────────────────────────────────────────

DJANGO_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Django DEBUG True",
        "Django DEBUG=True in production exposes sensitive information",
        re.compile(r'DEBUG\s*=\s*True'),
        "Set DEBUG=False in production. Use environment variables for configuration."
    ),
    (
        "Django ALLOWED_HOSTS Wildcard",
        "Django ALLOWED_HOSTS contains wildcard",
        re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\\*['\"]"),
        "Set specific hostnames in ALLOWED_HOSTS. Never use '*' in production."
    ),
    (
        "Django mark_safe",
        "Django mark_safe() — potential XSS if content is user-controlled",
        re.compile(r'mark_safe\s*\('),
        "Avoid mark_safe with user input. Use Django's auto-escaping template system."
    ),
    (
        "Django CSRF Exempt",
        "CSRF protection disabled on view",
        re.compile(r'@csrf_exempt'),
        "Avoid disabling CSRF. If necessary for an API, use token-based auth instead."
    ),
    (
        "Django Raw SQL",
        "Django raw SQL query — SQL injection risk",
        re.compile(r'\.raw\s*\(\s*f["\']|\.raw\s*\(\s*["\'].*%s.*["\']'),
        "Use Django ORM queries. If raw SQL is needed, use parameterized queries."
    ),
]

# ─── Flask Specific ──────────────────────────────────────────────────────────────

FLASK_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Flask Debug Mode",
        "Flask running in debug mode",
        re.compile(r'(?:app\.run|\.debug)\s*\(.*debug\s*=\s*True'),
        "Disable debug mode in production. Use environment variables."
    ),
    (
        "Flask Secret Key Hardcoded",
        "Flask secret key appears hardcoded",
        re.compile(r'(?:SECRET_KEY|secret_key)\s*=\s*["\'][^"\']+["\']'),
        "Generate a strong random secret key and store in environment variables."
    ),
    (
        "Flask No CSRF",
        "Flask form without CSRF protection",
        re.compile(r'(?:Flask\s*\()(?![\s\S]{0,500}CSRFProtect)'),
        "Use Flask-WTF with CSRFProtect for CSRF protection."
    ),
]

# ─── Vue.js Specific ─────────────────────────────────────────────────────────────

VUE_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Vue v-html with Variable",
        "Vue v-html with dynamic data — XSS risk if data is user-controlled",
        re.compile(r'v-html\s*=\s*["\'](?!.*sanitize)'),
        "Sanitize content before using v-html. Use v-text for plain text."
    ),
    (
        "Vue API Key in Component",
        "API key or secret in Vue component (visible in client bundle)",
        re.compile(r'(?:VUE_APP_|VITE_).*(?:SECRET|PRIVATE|KEY).*='),
        "Only VITE_ prefixed vars are exposed. Never prefix secrets with VITE_."
    ),
]


# ─── Framework Detection Hints ───────────────────────────────────────────────────

FRAMEWORK_INDICATORS: dict[str, list[re.Pattern]] = {
    "Next.js": [
        re.compile(r'"next"\s*:'),
        re.compile(r'next\.config'),
        re.compile(r'from\s+["\']next'),
    ],
    "React": [
        re.compile(r'"react"\s*:'),
        re.compile(r'from\s+["\']react["\']'),
        re.compile(r'import\s+React'),
    ],
    "Vue.js": [
        re.compile(r'"vue"\s*:'),
        re.compile(r'from\s+["\']vue["\']'),
        re.compile(r'createApp'),
    ],
    "Svelte": [
        re.compile(r'"svelte"\s*:'),
        re.compile(r'<script.*>'),  # combined with .svelte extension
    ],
    "Angular": [
        re.compile(r'"@angular/core"\s*:'),
        re.compile(r'@Component'),
    ],
    "Express": [
        re.compile(r'"express"\s*:'),
        re.compile(r'require\s*\(\s*["\']express["\']'),
    ],
    "Django": [
        re.compile(r'django'),
        re.compile(r'INSTALLED_APPS'),
    ],
    "Flask": [
        re.compile(r'from\s+flask\s+import'),
        re.compile(r'Flask\s*\('),
    ],
    "FastAPI": [
        re.compile(r'from\s+fastapi\s+import'),
        re.compile(r'FastAPI\s*\('),
    ],
    "Astro": [
        re.compile(r'"astro"\s*:'),
    ],
}

# ─── Combined Export ─────────────────────────────────────────────────────────────

ALL_FRAMEWORK_PATTERNS = (
    NEXTJS_PATTERNS +
    EXPRESS_PATTERNS +
    REACT_PATTERNS +
    DJANGO_PATTERNS +
    FLASK_PATTERNS +
    VUE_PATTERNS
)
