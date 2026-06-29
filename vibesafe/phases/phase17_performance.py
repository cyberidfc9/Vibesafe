"""
Phase 17: Performance & Resilience (Automated Scanner)
"""

import time
import re
import httpx
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.utils import walk_source_files, read_file_safe
from vibesafe.ui import print_finding, print_passed_check, print_failed_check, print_info

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    passed_checks = []
    failed_checks = []

    # 1. Automated Scan of Source Files
    has_rate_limiting = False
    has_body_limit = False
    has_compression = False
    has_timeouts = False

    rate_limit_pat = re.compile(r"express-rate-limit|ratelimit|slowdown|throttle|throttler|limiter|slowapi|django-ratelimit", re.IGNORECASE)
    body_limit_pat = re.compile(r"limit:\s*['\"]\d+|client_max_body_size|max_content_length|maxcontentlength|bodyparser.*limit", re.IGNORECASE)
    compression_pat = re.compile(r"compression|shrink-ray|zlib|gzip|deflate|brotli", re.IGNORECASE)
    timeout_pat = re.compile(r"timeout|abortcontroller|signal|requesttimeout|connecttimeout", re.IGNORECASE)

    source_files = list(walk_source_files(config))
    for filepath in source_files:
        if "vibesafe" in filepath.parts:
            continue
        content = read_file_safe(filepath)
        if not content:
            continue

        if not has_rate_limiting and rate_limit_pat.search(content):
            has_rate_limiting = True
        if not has_body_limit and body_limit_pat.search(content):
            has_body_limit = True
        if not has_compression and compression_pat.search(content):
            has_compression = True
        if not has_timeouts and timeout_pat.search(content):
            has_timeouts = True

    # 2. Live HTTP Scan (if URL is provided)
    live_compressed = False
    if config.url:
        print_info(f"Probing {config.url} for performance headers and response speeds...")
        try:
            start_req = time.time()
            with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
                headers = {"Accept-Encoding": "gzip, deflate, br"}
                res = client.get(config.url, headers=headers)
                latency = time.time() - start_req

                content_encoding = res.headers.get("content-encoding", "").lower()
                if any(enc in content_encoding for enc in ["gzip", "br", "deflate"]):
                    live_compressed = True

                if latency > 2.5:
                    failed_checks.append(f"High server response latency: {latency:.2f}s")
                    print_failed_check(f"Latency: Response latency was high ({latency:.2f}s).")
                    findings.append(Finding(
                        title="High Server Response Latency",
                        severity=Severity.MEDIUM,
                        phase=17,
                        phase_name="Performance & Resilience",
                        description=f"The server took {latency:.2f} seconds to respond to a basic homepage request, indicating potential resource bottlenecks or lack of caching.",
                        evidence=f"Response latency: {latency:.2f}s",
                        remediation="Implement server-side page caching, optimize database queries, or use a CDN (like Cloudflare) to serve static content quickly.",
                        owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
                    ))
                else:
                    passed_checks.append(f"Server response latency is low ({latency:.2f}s)")
                    print_passed_check(f"Latency: Server responded quickly in {latency:.2f}s.")
        except Exception as e:
            print_info(f"Performance request failed: {e}")

    # Check 1: Rate Limiting
    if has_rate_limiting:
        passed_checks.append("Rate limiting middleware detected")
        print_passed_check("Rate Limiting: Rate limit wrappers or imports found.")
    else:
        failed_checks.append("No rate limiting detected")
        print_failed_check("Rate Limiting: No throttling configuration detected.")
        findings.append(Finding(
            title="Missing Rate Limiting Protection",
            severity=Severity.HIGH,
            phase=17,
            phase_name="Performance & Resilience",
            description="No rate limiting or throttle controls were detected in the codebase. This leaves the API/endpoints vulnerable to Denial of Service (DoS) and automated scanning abuse.",
            evidence="No rate limiter imports or middlewares configured.",
            remediation="Implement rate limiting (e.g., using `express-rate-limit` for Node or `django-ratelimit` for Python) to throttle abusive client requests.",
            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
        ))

    # Check 2: Body Size Limits
    if has_body_limit:
        passed_checks.append("Request body size limits configured")
        print_passed_check("Body Size Limits: Maximum request size configurations found.")
    else:
        failed_checks.append("No request body size limits found")
        print_failed_check("Body Size Limits: No request body size limits detected.")
        findings.append(Finding(
            title="Missing Request Body Size Limits",
            severity=Severity.MEDIUM,
            phase=17,
            phase_name="Performance & Resilience",
            description="The server doesn't configure maximum limits for incoming request bodies, making it vulnerable to RAM/CPU exhaustion if massive payloads are posted.",
            evidence="Request parser setup lacks size limit options.",
            remediation="Limit payload sizes in middleware (e.g. `express.json({ limit: '1mb' })` or setting `client_max_body_size` in Nginx).",
            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
        ))

    # Check 3: Compression
    if has_compression or live_compressed:
        passed_checks.append("Response compression detected")
        print_passed_check("Compression: GZIP/Brotli response compression configured.")
    else:
        passed_checks.append("No response compression detected")
        print_info("Compression: No payload compression middleware detected.")
        findings.append(Finding(
            title="Missing Response Compression",
            severity=Severity.LOW,
            phase=17,
            phase_name="Performance & Resilience",
            description="Payload compression (like GZIP or Brotli) is not configured, resulting in slower loads and unnecessary bandwidth usage.",
            evidence="No compression middleware or live content-encoding header found.",
            remediation="Enable compression middleware (e.g. `compression` for Express) or enable Brotli/Gzip in your reverse proxy config.",
            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION
        ))

    # Check 4: Timeouts
    if has_timeouts:
        passed_checks.append("Request timeout configurations found")
        print_passed_check("Timeouts: Request timeouts or AbortController bindings found.")
    else:
        passed_checks.append("No timeout configurations detected (Optional)")
        print_info("Timeouts: No timeout settings detected for external/database operations.")

    return PhaseResult(
        phase_number=17,
        phase_name="Performance & Resilience",
        phase_type=PhaseType.AUTOMATED,
        findings=findings,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        summary=f"Performance scan completed. Found {len(findings)} recommendations.",
        duration_seconds=time.time() - start_time
    )
