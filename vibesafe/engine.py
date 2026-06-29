"""
VibeSafe — Phase Runner Engine

Orchestrates all 20 security phases, manages state between phases,
collects findings, and coordinates the overall scan lifecycle.
"""

from __future__ import annotations

import importlib
import time
from datetime import datetime
from typing import Optional

from vibesafe.config import VibesafeConfig
from vibesafe.models import (
    PHASE_REGISTRY,
    PhaseResult,
    PhaseType,
    ScanResult,
)
from vibesafe.ui import (
    console,
    print_banner,
    print_scan_target,
    print_phase_header,
    print_phase_complete,
    print_score_gauge,
    print_severity_table,
    print_phase_summary_table,
    print_error,
    print_warning,
)
from vibesafe.integrations import run_all_integrations
from vibesafe.ai_triage import run_ai_triage


# Phase module name mapping
PHASE_MODULES = {
    1: "vibesafe.phases.phase01_recon",
    2: "vibesafe.phases.phase02_threat_model",
    3: "vibesafe.phases.phase03_architecture",
    4: "vibesafe.phases.phase04_sast",
    5: "vibesafe.phases.phase05_dependencies",
    6: "vibesafe.phases.phase06_config",
    7: "vibesafe.phases.phase07_auth",
    8: "vibesafe.phases.phase08_authz",
    9: "vibesafe.phases.phase09_input_validation",
    10: "vibesafe.phases.phase10_uploads",
    11: "vibesafe.phases.phase11_api",
    12: "vibesafe.phases.phase12_database",
    13: "vibesafe.phases.phase13_business",
    14: "vibesafe.phases.phase14_owasp",
    15: "vibesafe.phases.phase15_pentest",
    16: "vibesafe.phases.phase16_scanner",
    17: "vibesafe.phases.phase17_performance",
    18: "vibesafe.phases.phase18_cloud",
    19: "vibesafe.phases.phase19_logging",
    20: "vibesafe.phases.phase20_report",
}


def should_run_phase(phase_number: int, config: VibesafeConfig) -> bool:
    """Determine if a phase should run based on config."""
    # If only_phases is set, only run those
    if config.only_phases:
        return phase_number in config.only_phases

    # Otherwise, skip phases in skip_phases
    if phase_number in config.skip_phases:
        return False

    return True


def get_phase_info(phase_number: int) -> dict:
    """Get phase metadata from the registry."""
    for phase in PHASE_REGISTRY:
        if phase["number"] == phase_number:
            return phase
    return {"number": phase_number, "name": f"Phase {phase_number}", "type": PhaseType.AUTOMATED}


def run_phase(
    phase_number: int,
    config: VibesafeConfig,
    scan_result: ScanResult,
) -> PhaseResult:
    """Run a single phase and return its result."""
    phase_info = get_phase_info(phase_number)
    phase_name = phase_info["name"]
    phase_type = phase_info["type"]

    # Check if phase should be skipped
    if not should_run_phase(phase_number, config):
        return PhaseResult(
            phase_number=phase_number,
            phase_name=phase_name,
            phase_type=phase_type,
            skipped=True,
            summary="Skipped by configuration",
        )

    # Skip guided phases if requested
    if config.skip_guided and phase_type == PhaseType.GUIDED:
        return PhaseResult(
            phase_number=phase_number,
            phase_name=phase_name,
            phase_type=phase_type,
            skipped=True,
            summary="Guided phase skipped (--skip-guided)",
        )

    # Print phase header
    print_phase_header(phase_number, phase_name, phase_type)

    # Import and run the phase module
    module_name = PHASE_MODULES.get(phase_number)
    if not module_name:
        print_error(f"No module found for phase {phase_number}")
        return PhaseResult(
            phase_number=phase_number,
            phase_name=phase_name,
            phase_type=phase_type,
            skipped=True,
            summary="Module not found",
        )

    try:
        module = importlib.import_module(module_name)
        start_time = time.time()
        result = module.run(config, scan_result)
        result.duration_seconds = time.time() - start_time
    except ImportError as e:
        print_error(f"Could not import phase module: {e}")
        return PhaseResult(
            phase_number=phase_number,
            phase_name=phase_name,
            phase_type=phase_type,
            skipped=True,
            summary=f"Import error: {e}",
        )
    except Exception as e:
        print_error(f"Phase {phase_number} failed: {e}")
        return PhaseResult(
            phase_number=phase_number,
            phase_name=phase_name,
            phase_type=phase_type,
            summary=f"Error: {e}",
        )

    # Print phase completion
    print_phase_complete(result)

    return result


def run_scan(config: VibesafeConfig) -> ScanResult:
    """Run the full VibeSafe security scan across all phases."""
    # Initialize scan result
    scan_result = ScanResult(
        project_path=config.project_path,
        url=config.url,
        start_time=datetime.now(),
    )

    # Print banner and target
    print_banner()
    print_scan_target(config.project_path, config.url)

    # Run phases 1 to 19 in order
    for phase_number in range(1, 20):
        result = run_phase(phase_number, config, scan_result)
        scan_result.phase_results.append(result)

        # After Phase 1, store tech stack for later phases
        if phase_number == 1 and hasattr(result, '_tech_stack'):
            scan_result.tech_stack = result._tech_stack

    # Run external tool integrations (Phase 0)
    integration_findings = run_all_integrations(config, scan_result)
    integration_result = PhaseResult(
        phase_number=0,
        phase_name="External Tool Integration",
        phase_type=PhaseType.AUTOMATED,
        findings=integration_findings,
        summary=f"Ran external security scanners (found {len(integration_findings)} findings)."
    )
    scan_result.phase_results.append(integration_result)

    # Run AI triage to score, deduplicate, and prioritize findings
    console.print("  [blue]🤖 Running local AI Triage engine...[/blue]")
    triaged_findings = run_ai_triage(scan_result)
    scan_result._triaged_findings = triaged_findings
    console.print(f"  [green]✅ AI Triage complete (triaged into {len(triaged_findings)} prioritized findings)[/green]")

    # Run Phase 20 (report generation)
    report_result = run_phase(20, config, scan_result)
    scan_result.phase_results.append(report_result)

    # Record end time
    scan_result.end_time = datetime.now()

    # Print final summary
    console.print()
    console.print("━" * 60, style="cyan")
    print_score_gauge(scan_result.score, scan_result.grade, scan_result.grade_label)
    print_severity_table(scan_result)
    print_phase_summary_table(scan_result)

    # Print scan duration
    duration = scan_result.duration_seconds
    minutes = int(duration // 60)
    seconds = int(duration % 60)
    if minutes > 0:
        console.print(f"\n  ⏱️  Total scan time: [bold]{minutes}m {seconds}s[/bold]")
    else:
        console.print(f"\n  ⏱️  Total scan time: [bold]{seconds}s[/bold]")
    console.print()

    return scan_result


def run_single_phase(
    phase_number: int,
    config: VibesafeConfig,
) -> ScanResult:
    """Run a single phase only."""
    scan_result = ScanResult(
        project_path=config.project_path,
        url=config.url,
        start_time=datetime.now(),
    )

    print_banner()
    print_scan_target(config.project_path, config.url)

    # If running phase > 1, we might need phase 1 for tech stack context
    if phase_number > 1:
        console.print("  [dim]Running Phase 1 first for context...[/dim]")
        recon_result = run_phase(1, config, scan_result)
        scan_result.phase_results.append(recon_result)
        if hasattr(recon_result, '_tech_stack'):
            scan_result.tech_stack = recon_result._tech_stack

    # Run the requested phase
    result = run_phase(phase_number, config, scan_result)
    scan_result.phase_results.append(result)

    scan_result.end_time = datetime.now()

    # Print summary
    console.print()
    print_severity_table(scan_result)

    return scan_result
