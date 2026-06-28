"""
VibeSafe — Secret Detection Patterns

Regex patterns for detecting hardcoded secrets, API keys, tokens,
and credentials in source code.
"""

from __future__ import annotations

import re

# Each pattern is: (name, description, regex, severity_hint, remediation)
SECRET_PATTERNS: list[tuple[str, str, re.Pattern, str, str]] = [
    # ── API Keys ────────────────────────────────────────────────────────
    (
        "AWS Access Key",
        "AWS access key ID found in source code",
        re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'),
        "critical",
        "Move AWS credentials to environment variables. Use IAM roles instead of access keys."
    ),
    (
        "AWS Secret Key",
        "Possible AWS secret access key",
        re.compile(r'(?i)aws[_\-]?secret[_\-]?(?:access)?[_\-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}'),
        "critical",
        "Remove from code. Use AWS Secrets Manager or environment variables."
    ),
    (
        "Google API Key",
        "Google API key found in source code",
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "high",
        "Move to environment variables. Restrict the API key in Google Cloud Console."
    ),
    (
        "Stripe Secret Key",
        "Stripe secret key found in source code",
        re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        "critical",
        "IMMEDIATELY rotate this key in Stripe Dashboard. Use environment variables."
    ),
    (
        "Stripe Publishable Key (Live)",
        "Stripe live publishable key — ensure it's only used client-side",
        re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
        "medium",
        "Publishable keys are okay client-side, but ensure secret keys aren't nearby."
    ),
    (
        "Razorpay Key",
        "Razorpay API key found in source code",
        re.compile(r'rzp_(?:live|test)_[0-9a-zA-Z]{14,}'),
        "high",
        "Move Razorpay keys to environment variables. Rotate if live key is exposed."
    ),
    (
        "GitHub Token",
        "GitHub personal access token or OAuth token",
        re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
        "critical",
        "Revoke this token immediately on GitHub. Use environment variables."
    ),
    (
        "Slack Token",
        "Slack bot or user token",
        re.compile(r'xox[bpors]-[0-9a-zA-Z\-]{10,}'),
        "high",
        "Revoke in Slack admin. Use environment variables."
    ),
    (
        "Discord Token",
        "Discord bot token",
        re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'),
        "critical",
        "Regenerate this bot token immediately in Discord Developer Portal."
    ),
    (
        "Twilio API Key",
        "Twilio Account SID or Auth Token pattern",
        re.compile(r'(?i)(?:twilio|TWILIO)[_\-]?(?:auth|AUTH)[_\-]?(?:token|TOKEN)\s*[=:]\s*["\']?[a-f0-9]{32}'),
        "high",
        "Move to environment variables. Rotate in Twilio console."
    ),
    (
        "SendGrid API Key",
        "SendGrid API key",
        re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
        "critical",
        "Revoke and regenerate in SendGrid. Use environment variables."
    ),
    (
        "Mailgun API Key",
        "Mailgun API key",
        re.compile(r'key-[0-9a-zA-Z]{32}'),
        "high",
        "Move to environment variables. Rotate in Mailgun dashboard."
    ),
    (
        "Firebase API Key",
        "Firebase/Google Cloud API key in code",
        re.compile(r'(?i)firebase[_\-]?(?:api)?[_\-]?key\s*[=:]\s*["\']?AIza[0-9A-Za-z\-_]{35}'),
        "medium",
        "Firebase API keys are semi-public but should still use environment variables for server-side."
    ),
    (
        "Supabase Service Role Key",
        "Supabase service role key (has full DB access)",
        re.compile(r'(?i)(?:supabase|SUPABASE)[_\-]?(?:service|SERVICE)[_\-]?(?:role|ROLE)[_\-]?(?:key|KEY)\s*[=:]\s*["\']?eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+'),
        "critical",
        "NEVER expose service role keys client-side. Use environment variables server-side only."
    ),
    (
        "Cloudinary URL",
        "Cloudinary API secret in URL",
        re.compile(r'cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[A-Za-z0-9]+'),
        "high",
        "Move Cloudinary credentials to environment variables."
    ),

    # ── Generic Secrets ─────────────────────────────────────────────────
    (
        "Private Key",
        "Private key block found in source code",
        re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        "critical",
        "Remove private keys from source code immediately. Use a secrets manager."
    ),
    (
        "Hardcoded Password",
        "Possible hardcoded password in assignment",
        re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']'),
        "high",
        "Never hardcode passwords. Use environment variables or a secrets vault."
    ),
    (
        "Hardcoded Secret",
        "Possible hardcoded secret in assignment",
        re.compile(r'(?i)(?:secret|token|api_key|apikey|access_key|auth_token)\s*[=:]\s*["\'][^"\']{8,}["\']'),
        "high",
        "Move secrets to environment variables. Never commit them to source control."
    ),
    (
        "Bearer Token",
        "Hardcoded Bearer token",
        re.compile(r'["\']Bearer\s+[A-Za-z0-9\-_\.]{20,}["\']'),
        "high",
        "Remove hardcoded tokens. Load from environment variables at runtime."
    ),
    (
        "JWT Token",
        "Possible hardcoded JWT token",
        re.compile(r'eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}'),
        "high",
        "JWT tokens should not be hardcoded. Check if this is a test fixture."
    ),
    (
        "Database Connection String",
        "Database connection string with credentials",
        re.compile(r'(?i)(?:mongodb|postgres|mysql|redis|amqp)(?:\+\w+)?://[^\s:]+:[^\s@]+@[^\s]+'),
        "critical",
        "Move database connection strings to environment variables."
    ),

    # ── .env in Code ────────────────────────────────────────────────────
    (
        "Env Variable in Code",
        "Environment variable value appears hardcoded instead of using process.env",
        re.compile(r'(?i)(?:process\.env\.|import\.meta\.env\.)\w+\s*\|\|\s*["\'][^"\']{8,}["\']'),
        "medium",
        "Fallback values for env vars should not contain real secrets."
    ),
]

# Files that commonly contain secrets (higher priority for scanning)
HIGH_PRIORITY_FILES = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    "config.js",
    "config.ts",
    "constants.js",
    "constants.ts",
    "settings.py",
    "config.py",
    "secrets.yml",
    "credentials.json",
    "service-account.json",
    "firebase-config.js",
    "firebase-config.ts",
    "supabase.js",
    "supabase.ts",
]

# .env files that should NOT be committed to git
ENV_FILES_SHOULD_BE_GITIGNORED = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.test",
]
