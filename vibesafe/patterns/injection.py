"""
VibeSafe — Injection Vulnerability Patterns

Regex patterns for detecting potential injection vulnerabilities:
SQL injection, XSS, command injection, path traversal, etc.
"""

from __future__ import annotations

import re


# ─── SQL Injection Patterns ──────────────────────────────────────────────────────

SQL_INJECTION_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "SQL String Concatenation",
        "SQL query built with string concatenation — vulnerable to SQL injection",
        re.compile(r'(?i)(?:query|execute|raw)\s*\(\s*[`"\']?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s.*\$\{'),
        "Use parameterized queries or an ORM. Never concatenate user input into SQL."
    ),
    (
        "SQL Template Literal",
        "SQL query using template literals with variables",
        re.compile(r'(?i)(?:query|execute|sql)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`'),
        "Use parameterized queries. Template literals are NOT safe for SQL."
    ),
    (
        "Raw SQL with f-string (Python)",
        "Python f-string used in SQL query",
        re.compile(r'(?i)(?:execute|cursor\.execute|\.raw)\s*\(\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE)'),
        "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    ),
    (
        "String Format in SQL (Python)",
        "Python .format() used in SQL query",
        re.compile(r'(?i)(?:execute|cursor\.execute|\.raw)\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']\.format\('),
        "Use parameterized queries instead of .format() for SQL."
    ),
    (
        "SQL Concatenation (+)",
        "SQL query built with + operator",
        re.compile(r'(?i)["\'](?:SELECT|INSERT|UPDATE|DELETE)\s.*["\']\s*\+\s*(?:req\.|request\.|params\.|query\.|body\.|user)'),
        "Use parameterized queries. Never concatenate request data into SQL."
    ),
    (
        "Prisma Raw Query",
        "Prisma $queryRaw or $executeRaw with template literal",
        re.compile(r'(?i)\.\$(?:queryRaw|executeRaw)\s*\(\s*`'),
        "Use Prisma.$queryRaw with Prisma.sql tagged template for safe parameterization."
    ),
]

# ─── XSS Patterns ────────────────────────────────────────────────────────────────

XSS_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "dangerouslySetInnerHTML",
        "React dangerouslySetInnerHTML — potential XSS if content is user-controlled",
        re.compile(r'dangerouslySetInnerHTML'),
        "Sanitize HTML with DOMPurify before rendering. Prefer safe rendering alternatives."
    ),
    (
        "innerHTML Assignment",
        "Direct innerHTML assignment — potential XSS vector",
        re.compile(r'\.innerHTML\s*='),
        "Use textContent for text, or sanitize HTML with DOMPurify before innerHTML."
    ),
    (
        "outerHTML Assignment",
        "Direct outerHTML assignment — potential XSS vector",
        re.compile(r'\.outerHTML\s*='),
        "Avoid outerHTML. Use safe DOM manipulation methods."
    ),
    (
        "document.write",
        "document.write() usage — can enable XSS",
        re.compile(r'document\.write\s*\('),
        "Avoid document.write(). Use DOM manipulation methods instead."
    ),
    (
        "v-html Directive (Vue)",
        "Vue v-html directive — potential XSS if data is user-controlled",
        re.compile(r'v-html\s*='),
        "Sanitize content before using v-html. Consider using v-text for plain text."
    ),
    (
        "[innerHTML] Binding (Angular)",
        "Angular innerHTML binding — potential XSS",
        re.compile(r'\[innerHTML\]\s*='),
        "Use Angular's DomSanitizer or pipe through a sanitization function."
    ),
    (
        "{@html} Tag (Svelte)",
        "Svelte {@html} tag — renders raw HTML",
        re.compile(r'\{@html\s'),
        "Sanitize content before using {@html}. Use text interpolation when possible."
    ),
]

# ─── Command Injection Patterns ──────────────────────────────────────────────────

COMMAND_INJECTION_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "child_process.exec",
        "Node.js exec() with potential user input — command injection risk",
        re.compile(r'(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\']\s*\+)'),
        "Use child_process.execFile() or spawn() with argument arrays instead of exec()."
    ),
    (
        "subprocess with shell=True (Python)",
        "Python subprocess with shell=True — command injection risk",
        re.compile(r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True'),
        "Avoid shell=True. Use subprocess.run() with a list of arguments."
    ),
    (
        "os.system (Python)",
        "Python os.system() — command injection risk",
        re.compile(r'os\.system\s*\('),
        "Use subprocess.run() with a list of arguments instead of os.system()."
    ),
    (
        "eval() Usage",
        "eval() executes arbitrary code — critical security risk",
        re.compile(r'(?<!\w)eval\s*\('),
        "Never use eval() with user input. Use JSON.parse() for JSON, or safer alternatives."
    ),
    (
        "Function() Constructor",
        "new Function() — can execute arbitrary code",
        re.compile(r'new\s+Function\s*\('),
        "Avoid new Function(). Use safer alternatives."
    ),
    (
        "exec() Python",
        "Python exec() — executes arbitrary code",
        re.compile(r'(?<!\w)exec\s*\(\s*(?:request|req|input|data|body)'),
        "Never use exec() with user input."
    ),
]

# ─── Path Traversal Patterns ─────────────────────────────────────────────────────

PATH_TRAVERSAL_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Unsanitized File Path",
        "File operation using user input without path sanitization",
        re.compile(r'(?:readFile|writeFile|createReadStream|readFileSync|writeFileSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)'),
        "Validate and sanitize file paths. Use path.resolve() and check against a whitelist."
    ),
    (
        "Path Join with User Input",
        "path.join with user-controlled input — potential traversal",
        re.compile(r'path\.join\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)'),
        "Validate the resolved path stays within the intended directory."
    ),
    (
        "Python open() with User Input",
        "Python open() using user-controlled variable",
        re.compile(r'open\s*\(\s*(?:request\.|filename|filepath|file_path|user_file)'),
        "Validate file paths against a whitelist. Use os.path.realpath() to resolve symlinks."
    ),
]

# ─── SSRF Patterns ───────────────────────────────────────────────────────────────

SSRF_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    (
        "Fetch with User URL",
        "fetch() or axios with user-controlled URL — SSRF risk",
        re.compile(r'(?:fetch|axios\.(?:get|post|put|delete)|got|request)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|url|userUrl)'),
        "Validate and whitelist allowed URLs/domains. Block internal IPs and metadata endpoints."
    ),
    (
        "HTTP Request with Variable URL",
        "HTTP request using a variable URL",
        re.compile(r'(?:fetch|axios|got|request|urllib|requests\.get)\s*\(\s*`\$\{'),
        "Validate URLs against a whitelist. Never pass user input directly as a URL."
    ),
]

# ─── Combined Export ─────────────────────────────────────────────────────────────

ALL_INJECTION_PATTERNS = (
    SQL_INJECTION_PATTERNS +
    XSS_PATTERNS +
    COMMAND_INJECTION_PATTERNS +
    PATH_TRAVERSAL_PATTERNS +
    SSRF_PATTERNS
)
