# VibeSafe 🛡️

A professional web application security testing CLI tool designed for vibe-coded/AI-built websites. VibeSafe walks you through a comprehensive 20-phase security testing lifecycle, combining automated static code analysis, live URL scanning, and interactive guided checklists.

## Features

- **20 Testing Phases**: Reconstructs the complete professional penetration testing lifecycle.
- **Beautiful Rich terminal UI**: Color-coded findings, visual score gauges, and ASCII threat/architecture mapping.
- **Dual Mode**: Scans local source code (Next.js, Python, Express, etc.) AND live web endpoints.
- **Dual Formats**: Generates beautiful, styled dark-themed HTML dashboards and Markdown reports.

---

## Installation

Install the package locally:

```bash
cd c:\Users\Bipin\Desktop\AiLoganalyser\vibesafe
pip install -e .
```

---

## Usage

### 1. Initialize configuration in your project
```bash
vibesafe init
```
This generates a `.vibesafe.yml` in your current directory.

### 2. Run a full security scan
```bash
vibesafe scan <path_to_project_root>
```

### 3. Scan a live website alongside your codebase
```bash
vibesafe scan <path_to_project_root> --url https://your-website.com
```

### 4. Run only automated phases (skip interactive prompts)
```bash
vibesafe scan <path_to_project_root> --skip-guided
```

### 5. Run a specific phase (e.g., SAST Static Code Review)
```bash
vibesafe scan <path_to_project_root> --phase 4
```

### 6. View all 20 phases
```bash
vibesafe phases
```

---

## The 20-Phase Security Testing Lifecycle

1. **Information Gathering (Recon)**: Detects technology stack, services, and APIs.
2. **Threat Modeling**: Maps potential attack vectors.
3. **Architecture Review**: Visualizes database, API, and cloud connections.
4. **Static Code Review (SAST)**: Scans source code for credentials, hardcoded keys, SQLi, XSS, and dangerous functions.
5. **Dependency Scan**: Checks libraries for known CVEs using automated audits.
6. **Server Configuration**: Audits TLS/SSL cookies and security headers (CSP, HSTS).
7. **Authentication Testing**: Guided verification of passwords, rate limits, and MFA.
8. **Authorization Testing**: Checks for IDOR, access control gaps, and privilege levels.
9. **Input Validation**: Evaluates form and query validations (Zod/Pydantic).
10. **File Upload Review**: Checks upload extensions, storage location, and size limits.
11. **API Security**: Inspects endpoints for validation, method protection, and errors.
12. **Database Security**: Audits credential exposure, password hashing, and RLS.
13. **Business Logic Testing**: Guides you to test coupon abuse, price overrides, etc.
14. **OWASP Top 10 Review**: Renders an OWASP compliance scorecard mapping findings.
15. **Manual Penetration Testing**: General manual verification guide.
16. **Automated Vulnerability Scan**: Checks URL for exposed folders (`/.git/`, `/.env`).
17. **Performance & DoS Testing**: Checks rate-limit bounds, response speed, and compression.
18. **Cloud Security Review**: Audits IAM permission scopes, platform settings, and logs.
19. **Logging & Monitoring**: Verifies log safety and error trackers (Sentry).
20. **Final Security Audit**: Generates clean Markdown reports and dark-themed HTML summary.
