"""
VibeSafe — Configuration Loader

Reads project-specific settings from .vibesafe.yml or uses sensible defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class VibesafeConfig:
    """Configuration for a VibeSafe scan."""
    # Paths
    project_path: str = "."
    url: Optional[str] = None

    # Phase control
    skip_phases: list[int] = field(default_factory=list)
    only_phases: list[int] = field(default_factory=list)
    skip_guided: bool = False

    # Scanning
    exclude_dirs: list[str] = field(default_factory=lambda: [
        "node_modules", ".next", ".git", "__pycache__", "dist", "build",
        ".vercel", ".netlify", "coverage", ".nyc_output", "venv", ".venv",
        "env", ".tox", ".pytest_cache", ".mypy_cache",
    ])
    exclude_files: list[str] = field(default_factory=lambda: [
        "*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json",
        "yarn.lock", "pnpm-lock.yaml",
    ])
    max_file_size_kb: int = 500

    # Source file extensions to scan
    source_extensions: list[str] = field(default_factory=lambda: [
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".py", ".rb", ".php", ".go", ".rs", ".java",
        ".vue", ".svelte", ".astro",
        ".html", ".htm", ".ejs", ".hbs", ".pug",
        ".css", ".scss", ".less",
        ".json", ".yml", ".yaml", ".toml", ".env",
        ".sql", ".graphql", ".gql",
        ".sh", ".bash", ".ps1",
        ".md", ".mdx",
    ])

    # Config file extensions (always scanned regardless of source_extensions)
    config_extensions: list[str] = field(default_factory=lambda: [
        ".json", ".yml", ".yaml", ".toml", ".env", ".config.js",
        ".config.ts", ".config.mjs",
    ])

    # Output
    output_dir: str = "."
    report_formats: list[str] = field(default_factory=lambda: ["markdown", "html"])

    # Secrets scanning
    custom_secret_patterns: list[str] = field(default_factory=list)
    ignore_secret_paths: list[str] = field(default_factory=list)

    # Tech stack overrides
    tech_stack_overrides: dict = field(default_factory=dict)


def load_config(project_path: str, url: Optional[str] = None) -> VibesafeConfig:
    """Load configuration from .vibesafe.yml if it exists, otherwise use defaults."""
    config = VibesafeConfig(project_path=project_path, url=url)

    config_file = Path(project_path) / ".vibesafe.yml"
    if not config_file.exists():
        config_file = Path(project_path) / ".vibesafe.yaml"

    if config_file.exists():
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            # Merge loaded config into defaults
            if "skip_phases" in data:
                config.skip_phases = data["skip_phases"]
            if "only_phases" in data:
                config.only_phases = data["only_phases"]
            if "skip_guided" in data:
                config.skip_guided = data["skip_guided"]
            if "exclude_dirs" in data:
                config.exclude_dirs.extend(data["exclude_dirs"])
            if "exclude_files" in data:
                config.exclude_files.extend(data["exclude_files"])
            if "max_file_size_kb" in data:
                config.max_file_size_kb = data["max_file_size_kb"]
            if "output_dir" in data:
                config.output_dir = data["output_dir"]
            if "report_formats" in data:
                config.report_formats = data["report_formats"]
            if "custom_secret_patterns" in data:
                config.custom_secret_patterns = data["custom_secret_patterns"]
            if "ignore_secret_paths" in data:
                config.ignore_secret_paths = data["ignore_secret_paths"]
            if "tech_stack" in data:
                config.tech_stack_overrides = data["tech_stack"]
            if "url" in data and not url:
                config.url = data["url"]
        except Exception:
            pass  # Silently fall back to defaults if config is malformed

    return config


def generate_default_config() -> str:
    """Generate a default .vibesafe.yml template."""
    return """\
# VibeSafe Configuration
# Place this file in your project root as .vibesafe.yml

# Live URL to test (optional)
# url: https://your-site.com

# Skip specific phases (by number)
# skip_phases: [17]

# Run only specific phases
# only_phases: [4, 5, 6]

# Skip all interactive/guided phases
# skip_guided: false

# Additional directories to exclude from scanning
# exclude_dirs:
#   - vendor
#   - tmp

# Additional files to exclude
# exclude_files:
#   - "*.generated.js"

# Maximum file size to scan (KB)
# max_file_size_kb: 500

# Report output directory
# output_dir: ./reports

# Report formats: markdown, html, or both
# report_formats:
#   - markdown
#   - html

# Custom secret patterns (regex)
# custom_secret_patterns:
#   - "MY_CUSTOM_KEY_[A-Za-z0-9]{32}"

# Paths to ignore for secret scanning
# ignore_secret_paths:
#   - "tests/fixtures"
#   - "docs/examples"

# Tech stack overrides (if auto-detection gets it wrong)
# tech_stack:
#   framework: Next.js
#   database: PostgreSQL
#   hosting: Vercel
"""
