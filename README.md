# VibeSafe 🛡️ — 20-Phase Security Testing CLI for Vibe-Coded Websites

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Scan](https://img.shields.io/badge/security-OWASP%20Top%2010-red.svg)](#)

VibeSafe is a professional Command Line Interface (CLI) security scanner engineered specifically for vibe-coded, AI-built, or quickly prototyped web applications. It automates code-level vulnerability analysis, audits server configurations, verifies cloud security rules, and walks developers through interactive checklists corresponding to a rigorous 20-phase penetration testing lifecycle.

---

## Table of Contents
1. [Overview & Design philosophy](#overview--design-philosophy)
2. [Key Features](#key-features)
3. [Architecture Diagram](#architecture-diagram)
4. [Installation & Setup](#installation--setup)
5. [Quick Start & Command Reference](#quick-start--command-reference)
6. [Detailed 20-Phase Testing Lifecycle](#detailed-20-phase-testing-lifecycle)
7. [Configuring VibeSafe (`.vibesafe.yml`)](#configuring-vibesafe-vibesafeyml)
8. [Report Outputs (Markdown & HTML Dashboard)](#report-outputs-markdown--html-dashboard)
9. [License](#license)

---

## Overview & Design Philosophy

AI generation (vibe coding) lets developers construct robust, highly interactive web applications in minutes. However, security boundaries are frequently omitted or misconfigured (e.g. unvalidated database queries, exposed credentials, or missing authentication middleware). 

VibeSafe bridges this gap by acting as an automated security engineer on your machine. It follows the **Professional Website Security Testing Lifecycle** to systematically review every vector of your website.

---

## Key Features

- **⚡ 20 Security Phases**: Structured after professional penetration testing playbooks.
- **🔍 Auto-Tech Stack Detection**: Identifies Node.js, Python, Next.js, Express, Django, Flask, SQLite, Postgres, Supabase, Stripe, Razorpay, Cloudinary, and more.
- **🔑 Custom SAST Engine**: Automated regular expression scanning targeting secrets, SQL injection, XSS, insecure file handling, and weak cryptographical setups.
- **🤖 100% Automated Security Audits**: All authentication, authorization, uploads, database settings, and cloud configs are scanned automatically from the source code.
- **📊 Professional Report Outputs**: Generates standard Markdown reports and responsive, dark-themed HTML dashboard reports with severity filters.

---

## Architecture Diagram

```
                              [ VibeSafe CLI ]
                                      │
                                      ▼
                        [ Configuration Loader ] ( .vibesafe.yml )
                                      │
                                      ▼
                           [ Phase Runner Engine ]
                                      │
         ┌────────────────────────────┴────────────────────────────┐
         ▼                                                         ▼
  [ Automated Code Scanners ]                            [ Live HTTP Scanner ]
  ├── Phase 1: Recon                                     ├── Phase 6: Config Review
  ├── Phase 2: Threat Modeling                           ├── Phase 16: Vuln Scan
  ├── Phase 3: Architecture Mapping                      └── Phase 17: Latency Check
  ├── Phase 4: SAST Scan
  ├── Phase 5: Dependency Security
  ├── Phase 7: Auth Controls (Auto)
  ├── Phase 8: Authz Controls (Auto)
  ├── Phase 9: Input Validation
  ├── Phase 10: File Upload Review (Auto)
  ├── Phase 11: API Security
  ├── Phase 12: Database Security (Auto)
  ├── Phase 13: Business Logic Testing (Auto)
  ├── Phase 14: OWASP scorecard
  ├── Phase 15: Penetration Testing (Auto)
  ├── Phase 17: Performance & Resilience (Auto)
  ├── Phase 18: Cloud Security (Auto)
  └── Phase 19: Logging & Monitoring (Auto)
                                      │
                                      ▼
                        [ Phase 20: Report Generator ]
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
         [ Markdown Report File ]           [ Styled HTML Dashboard ]
```

---

## Installation & Setup

### Prerequisites
- Python **3.10** or newer installed.
- Pip (Python Package Installer).

### Step-by-Step Installation (Linux / Kali Linux / macOS)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/cyberidfc9/Vibesafe.git
   cd Vibesafe
   ```

2. **Run the Hollywood-style interactive installer**:
   This automatically bypasses the PEP 668 `externally-managed-environment` error by sandboxing the tool in a Python virtual environment and mapping the global command interface:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Verify installation**:
   Run the phases command to ensure the global execution wrapper is active:
   ```bash
   vibesafe phases
   ```

### Alternate Manual Installation (Windows)

If you are on Windows, run:
```bash
pip install -e .
```

---

## Quick Start & Command Reference

VibeSafe uses a structured CLI command system. Here is a summary of all commands:

| Command | Description | Example |
| :--- | :--- | :--- |
| `vibesafe init` | Creates a default config file (`.vibesafe.yml`) in the current directory. | `vibesafe init` |
| `vibesafe scan <path>` | Scans the target folder across all 20 phases. | `vibesafe scan ./my-next-project` |
| `vibesafe phases` | Lists description and type of all 20 security phases. | `vibesafe phases` |
| `vibesafe version` | Displays the current version of the tool. | `vibesafe version` |

### Advanced Scan Parameters

- **Test a live deployment alongside source files**:
  ```bash
  vibesafe scan ./my-project --url https://my-deployed-site.com
  ```
- **Skip interactive/guided prompts (Ideal for CI/CD runs)**:
  ```bash
  vibesafe scan ./my-project --skip-guided
  ```
- **Run only a specific phase (e.g. SAST scan only)**:
  ```bash
  vibesafe scan ./my-project --phase 4
  ```
- **Skip specific phases**:
  ```bash
  vibesafe scan ./my-project --skip 17 --skip 18
  ```
- **Specify a custom output directory**:
  ```bash
  vibesafe scan ./my-project --output ./security-audit-reports
  ```

---

## Detailed 20-Phase Testing Lifecycle

### 1. Information Gathering (Recon)
- **Type:** Automated
- **Actions:** Scans `package.json`, configuration files, and folders to detect the runtime, front-end framework, database/ORM, storage buckets, payment processors, and hosting environments.

### 2. Threat Modeling
- **Type:** Automated
- **Actions:** Analyzes the detected tech stack to map the potential attack surface (e.g. identifies high-risk areas like payments, user uploads, or API integrations).

### 3. Architecture Review
- **Type:** Automated
- **Actions:** Generates an ASCII data flow and architecture mapping of your application, highlighting security gaps.

### 4. Static Code Review (SAST)
- **Type:** Automated
- **Actions:** Scans files against regex patterns for hardcoded credentials/tokens (AWS, Stripe, Razorpay), SQLi, XSS, unsafe serialization, path traversals, and exposed `.env` configs.

### 5. Dependency Security
- **Type:** Automated
- **Actions:** Checks for package vulnerabilities using `npm audit` or `pip audit`. Falls back to scanning manifests for unmaintained or obsolete libraries.

### 6. Server Configuration
- **Type:** Hybrid
- **Actions:** Checks source code configs. If `--url` is specified, it makes live requests to inspect HTTP security headers (CSP, HSTS, CORS) and cookie attributes (Secure, HttpOnly, SameSite).

### 7. Authentication Testing
- **Type:** Automated
- **Actions:** Scans source code for secure password hashing (bcrypt, argon2), auth route rate limiting, MFA libraries, session timeout configurations, and password strength policies.

### 8. Authorization Testing
- **Type:** Automated
- **Actions:** Verifies presence of route authentication guards/middleware, role-based checks (RBAC), token scopes, and checks for potential IDOR (Insecure Direct Object Reference) vulnerabilities in queries.

### 9. Input Validation
- **Type:** Automated
- **Actions:** Scans request handlers for unvalidated schema parameters, missing body validation libraries (like Zod or Joi), and Regular Expression Denial of Service (ReDoS) issues.

### 10. File Upload Review
- **Type:** Automated
- **Actions:** Identifies upload endpoints and checks for allowlisted file type validation, maximum file size restrictions, filename sanitization, and external cloud storage (like S3/Cloudinary).

### 11. API Security
- **Type:** Automated
- **Actions:** Scans API route directories for unauthenticated paths, input sanitization checks, and traceback exposures.

### 12. Database Security
- **Type:** Automated
- **Actions:** Inspects schema configurations, checks for hardcoded connection credentials, verifies password hashing on DB write operations, and scans for raw SQL injection risks.

### 13. Business Logic Testing
- **Type:** Automated
- **Actions:** Scans e-commerce and transaction handlers for negative pricing/quantity validation, database locking/transactions, idempotency keys, and workflow state validation checks.

### 14. OWASP Top 10 Review
- **Type:** Automated
- **Actions:** Maps all findings discovered across the run to their respective categories on the OWASP Top 10 scorecard.

### 15. Penetration Testing
- **Type:** Automated
- **Actions:** Scans for exposed production source maps (JS maps), verbose exception leaks in API responses, and hardcoded development/debug modes.

### 16. Automated Vulnerability Scan
- **Type:** Hybrid
- **Actions:** If a live URL is provided, scans for public files (`/.env`, `/.git/config`, `wp-config.php.bak`) and directory listing vulnerabilities.

### 17. Performance & Resilience
- **Type:** Automated
- **Actions:** Checks rate limiting libraries, Gzip/Brotli payload compression, timeout settings for external calls, and measures live host response latency.

### 18. Cloud Security
- **Type:** Automated
- **Actions:** Scans for permissive Firebase security rules, root Docker container configurations, public S3 bucket ACL configurations, and committed cloud credentials.

### 19. Logging & Monitoring
- **Type:** Automated
- **Actions:** Scans for sensitive data leaking into logs (passwords, keys), winston/pino structured logging configurations, and error monitoring services (Sentry/Bugsnag).

### 20. Final Security Audit
- **Type:** Automated
- **Actions:** Aggregates findings, calculates the final score, and saves the reports.

---

## Configuring VibeSafe (`.vibesafe.yml`)

You can place a configuration file in your project root to personalize scans. Create a template using:
```bash
vibesafe init
```

### Config Options Example:
```yaml
# .vibesafe.yml

# Target Live URL (optional)
url: https://my-deployed-app.com

# Phases to skip by default (by number)
skip_phases:
  - 17 # Skip Performance
  - 18 # Skip Cloud

# Skip interactive checklists by default
skip_guided: false

# Folders to ignore during static analysis
exclude_dirs:
  - node_modules
  - .next
  - dist
  - build

# Custom secret key patterns (regex)
custom_secret_patterns:
  - "MY_APP_TOKEN_[A-Za-z0-9]{32}"

# Formats to output
report_formats:
  - markdown
  - html
```

---

## Report Outputs

Every run produces two clean reports inside the output directory:

### 1. Markdown Report
A comprehensive report optimized for code repositories and text viewers. Includes code block evidence and markdown tables mapping severity levels.

### 2. HTML Dashboard
A modern, dark-themed responsive web dashboard styled after GitHub's developer design syntax (dark background `#0d1117`, cards `#161b22`, highlights `#58a6ff`). Features:
- Visual score speedometer gauge (e.g. `GOOD`, `FAIR`, `CRITICAL`).
- Severity distribution cards.
- Interactive filter buttons to filter findings by severity level (All, Critical, High, Medium, Low).
- Expandable code snippet blocks showing finding evidence.

---

## License

VibeSafe is licensed under the [MIT License](LICENSE).
