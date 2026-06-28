"""
Phase 20: Final Security Report
"""

import time
from datetime import datetime
from pathlib import Path
from vibesafe.models import PhaseResult, PhaseType, Finding, Severity, OWASPCategory
from vibesafe.ui import print_report_saved

def run(config, scan_result=None) -> PhaseResult:
    start_time = time.time()
    findings = []
    
    if not scan_result:
        return PhaseResult(
            phase_number=20,
            phase_name="Final Security Report",
            phase_type=PhaseType.AUTOMATED,
            summary="No scan result found to generate report.",
            duration_seconds=time.time() - start_time
        )

    # 1. Output directory preparation
    out_dir = Path(config.project_path) / config.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    saved_paths = []
    
    # Aggregate all findings across phases
    all_findings = scan_result.all_findings

    # Count severities
    counts = scan_result.severity_counts

    # 2. Generate Markdown Report
    if "markdown" in config.report_formats:
        md_file = out_dir / f"vibesafe-report-{date_str}.md"
        
        md_content = f"""# VibeSafe Web Application Security Testing Report

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Project Path:** `{scan_result.project_path}`  
**Live URL:** `{scan_result.url or 'None provided'}`

---

## Executive Summary

| Security Score | Grade | Severity Details |
| :--- | :---: | :--- |
| **{scan_result.score}/100** | **{scan_result.grade} ({scan_result.grade_label})** | 🔴 Critical: {counts[Severity.CRITICAL]}<br>🟠 High: {counts[Severity.HIGH]}<br>🟡 Medium: {counts[Severity.MEDIUM]}<br>🔵 Low: {counts[Severity.LOW]}<br>⚪ Info: {counts[Severity.INFO]} |

---

## Detailed Findings

"""
        if all_findings:
            # Sort findings by severity (Critical first)
            sev_order = list(Severity)
            sorted_findings = sorted(all_findings, key=lambda f: sev_order.index(f.severity))
            
            for i, f in enumerate(sorted_findings, 1):
                loc = f"{f.file_path or 'Global'}"
                if f.line_number:
                    loc += f":L{f.line_number}"
                
                md_content += f"""### {i}. {f.severity.emoji} {f.severity.value.upper()} │ {f.title}
* **Phase:** Phase {f.phase} ({f.phase_name})
* **Location:** `{loc}`
* **OWASP Mapping:** {f.owasp_category.value if f.owasp_category else 'N/A'}

#### Description
{f.description}

"""
                if f.evidence:
                    md_content += f"""#### Evidence
```text
{f.evidence}
```

"""
                if f.remediation:
                    md_content += f"""#### Remediation / Mitigation
{f.remediation}

---

"""
        else:
            md_content += "🎉 **No security issues found!** The application complies with all automated and checked security phases.\n"

        md_file.write_text(md_content, encoding="utf-8")
        saved_paths.append(str(md_file.resolve()))

    # 3. Generate HTML Report
    if "html" in config.report_formats:
        html_file = out_dir / f"vibesafe-report-{date_str}.html"
        
        # Build finding cards HTML
        findings_html = ""
        if all_findings:
            sev_order = list(Severity)
            sorted_findings = sorted(all_findings, key=lambda f: sev_order.index(f.severity))
            
            for i, f in enumerate(sorted_findings, 1):
                loc = f"{f.file_path or 'Global'}"
                if f.line_number:
                    loc += f":L{f.line_number}"
                
                evidence_block = ""
                if f.evidence:
                    evidence_block = f"""
                    <div class="evidence-block">
                        <strong>Evidence:</strong>
                        <pre><code>{f.evidence}</code></pre>
                    </div>"""
                
                remediation_block = ""
                if f.remediation:
                    remediation_block = f"""
                    <div class="remediation-block">
                        <strong>💡 Remediation:</strong>
                        <p>{f.remediation}</p>
                    </div>"""

                findings_html += f"""
                <div class="finding-card" data-severity="{f.severity.value}">
                    <div class="card-header border-{f.severity.color}">
                        <span class="badge badge-{f.severity.color}">{f.severity.emoji} {f.severity.value.upper()}</span>
                        <h3>{f.title}</h3>
                    </div>
                    <div class="card-body">
                        <div class="finding-meta">
                            <span><strong>Phase:</strong> Phase {f.phase} ({f.phase_name})</span>
                            <span><strong>Location:</strong> <code>{loc}</code></span>
                            <span><strong>OWASP:</strong> {f.owasp_category.value if f.owasp_category else 'N/A'}</span>
                        </div>
                        <p class="description">{f.description}</p>
                        {evidence_block}
                        {remediation_block}
                    </div>
                </div>"""
        else:
            findings_html = """
            <div class="no-findings">
                🎉 No security issues found! Keep up the good work.
            </div>"""

        # HTML template with dark mode aesthetics
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VibeSafe Security Audit Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --text-color: #c9d1d9;
            --text-muted: #8b949e;
            --border-color: #30363d;
            --accent-cyan: #58a6ff;
            
            --critical-color: #f85149;
            --high-color: #db6d28;
            --medium-color: #d29922;
            --low-color: #58a6ff;
            --info-color: #8b949e;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}

        header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 40px;
        }}

        h1, h2, h3 {{
            color: #ffffff;
            margin-top: 0;
        }}

        h1 {{
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 10px;
        }}

        .meta-info {{
            color: var(--text-muted);
            font-size: 0.95rem;
        }}

        .meta-info span {{
            margin-right: 20px;
        }}

        /* Executive Summary Dashboard */
        .summary-dashboard {{
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            margin-bottom: 40px;
        }}

        .score-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 30px;
            text-align: center;
        }}

        .score-value {{
            font-size: 4rem;
            font-weight: 800;
            color: var(--accent-cyan);
            line-height: 1;
            margin-bottom: 10px;
        }}

        .score-grade {{
            font-size: 1.5rem;
            font-weight: 600;
            color: #ffffff;
        }}

        .counts-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 30px;
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            align-items: center;
        }}

        .count-item {{
            text-align: center;
        }}

        .count-number {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 5px;
        }}

        .count-label {{
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
        }}

        /* Findings Filters */
        .filter-bar {{
            margin-bottom: 30px;
            display: flex;
            gap: 10px;
        }}

        .filter-btn {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s ease;
        }}

        .filter-btn:hover, .filter-btn.active {{
            background-color: var(--border-color);
            border-color: var(--text-color);
        }}

        /* Finding Card */
        .finding-card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 25px;
            overflow: hidden;
        }}

        .card-header {{
            padding: 15px 20px;
            background-color: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .card-header h3 {{
            margin: 0;
            font-size: 1.25rem;
        }}

        .card-body {{
            padding: 20px;
        }}

        .finding-meta {{
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 15px;
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }}

        .finding-meta code {{
            background-color: rgba(255,255,255,0.05);
            padding: 2px 6px;
            border-radius: 4px;
        }}

        .description {{
            font-size: 1rem;
            margin-bottom: 20px;
        }}

        .evidence-block, .remediation-block {{
            background-color: rgba(0, 0, 0, 0.2);
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
            border-left: 3px solid var(--border-color);
        }}

        .remediation-block {{
            border-left-color: var(--accent-cyan);
        }}

        .evidence-block pre {{
            margin: 0;
            overflow-x: auto;
        }}

        .evidence-block code {{
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            font-size: 0.9rem;
        }}

        /* Severity Badges & Borders */
        .border-red {{ border-left: 4px solid var(--critical-color); }}
        .border-dark_orange {{ border-left: 4px solid var(--high-color); }}
        .border-yellow {{ border-left: 4px solid var(--medium-color); }}
        .border-blue {{ border-left: 4px solid var(--low-color); }}
        .border-dim {{ border-left: 4px solid var(--info-color); }}

        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .badge-red {{ background-color: var(--critical-color); color: white; }}
        .badge-dark_orange {{ background-color: var(--high-color); color: white; }}
        .badge-yellow {{ background-color: var(--medium-color); color: #0d1117; }}
        .badge-blue {{ background-color: var(--low-color); color: white; }}
        .badge-dim {{ background-color: var(--info-color); color: white; }}

        .no-findings {{
            text-align: center;
            padding: 50px;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            font-size: 1.25rem;
        }}
    </style>
    <script>
        function filterSeverity(severity) {{
            const cards = document.querySelectorAll('.finding-card');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            cards.forEach(card => {{
                if (severity === 'all' || card.getAttribute('data-severity') === severity) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</head>
<body>
    <div class="container">
        <header>
            <h1>VibeSafe Security Audit</h1>
            <div class="meta-info">
                <span><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span><strong>Path:</strong> <code>{scan_result.project_path}</code></span>
                <span><strong>Target:</strong> {scan_result.url or 'Local Filesystem Scan'}</span>
            </div>
        </header>

        <section class="summary-dashboard">
            <div class="score-card">
                <div class="score-value">{scan_result.score}</div>
                <div class="score-grade">GRADE: {scan_result.grade} ({scan_result.grade_label})</div>
            </div>
            <div class="counts-card">
                <div class="count-item">
                    <div class="count-number" style="color: var(--critical-color);">{counts[Severity.CRITICAL]}</div>
                    <div class="count-label">Critical</div>
                </div>
                <div class="count-item">
                    <div class="count-number" style="color: var(--high-color);">{counts[Severity.HIGH]}</div>
                    <div class="count-label">High</div>
                </div>
                <div class="count-item">
                    <div class="count-number" style="color: var(--medium-color);">{counts[Severity.MEDIUM]}</div>
                    <div class="count-label">Medium</div>
                </div>
                <div class="count-item">
                    <div class="count-number" style="color: var(--low-color);">{counts[Severity.LOW]}</div>
                    <div class="count-label">Low</div>
                </div>
                <div class="count-item">
                    <div class="count-number" style="color: var(--info-color);">{counts[Severity.INFO]}</div>
                    <div class="count-label">Info</div>
                </div>
            </div>
        </section>

        <h2>Vulnerabilities Discovered</h2>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterSeverity('all')">All</button>
            <button class="filter-btn" onclick="filterSeverity('critical')">🔴 Critical</button>
            <button class="filter-btn" onclick="filterSeverity('high')">🟠 High</button>
            <button class="filter-btn" onclick="filterSeverity('medium')">🟡 Medium</button>
            <button class="filter-btn" onclick="filterSeverity('low')">🔵 Low</button>
        </div>

        <div class="findings-list">
            {findings_html}
        </div>
    </div>
</body>
</html>"""

        html_file.write_text(html_content, encoding="utf-8")
        saved_paths.append(str(html_file.resolve()))

    # Print success output
    print_report_saved(saved_paths)

    return PhaseResult(
        phase_number=20,
        phase_name="Final Security Report",
        phase_type=PhaseType.AUTOMATED,
        summary=f"Generated {len(saved_paths)} report files successfully.",
        duration_seconds=time.time() - start_time
    )
