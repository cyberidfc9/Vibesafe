"""
VibeSafe — Shared Utilities

File scanning, pattern matching, and helper functions used across phases.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Generator, Optional

from vibesafe.config import VibesafeConfig


def walk_source_files(
    config: VibesafeConfig,
    extensions: Optional[list[str]] = None,
) -> Generator[Path, None, None]:
    """
    Walk the project directory and yield source files matching the config.

    Respects exclude_dirs, exclude_files, max_file_size, and extension filters.
    """
    root = Path(config.project_path).resolve()
    exts = set(extensions or config.source_extensions)
    exclude_dirs = set(config.exclude_dirs)
    max_size = config.max_file_size_kb * 1024

    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out excluded directories (modifying dirnames in-place)
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs and not d.startswith(".")
        ]

        for filename in filenames:
            filepath = Path(dirpath) / filename

            # Check extension
            if not any(filename.endswith(ext) for ext in exts):
                continue

            # Check excluded file patterns
            if any(fnmatch.fnmatch(filename, pat) for pat in config.exclude_files):
                continue

            # Check file size
            try:
                if filepath.stat().st_size > max_size:
                    continue
            except OSError:
                continue

            yield filepath


def walk_all_files(config: VibesafeConfig) -> Generator[Path, None, None]:
    """Walk ALL files in project (no extension filter). Still respects excludes."""
    root = Path(config.project_path).resolve()
    exclude_dirs = set(config.exclude_dirs)
    max_size = config.max_file_size_kb * 1024

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs and not d.startswith(".")
        ]
        for filename in filenames:
            filepath = Path(dirpath) / filename
            try:
                if filepath.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield filepath


def read_file_safe(filepath: Path, encoding: str = "utf-8") -> Optional[str]:
    """Read a file safely, returning None on any error."""
    try:
        return filepath.read_text(encoding=encoding, errors="replace")
    except Exception:
        return None


def read_json_file(filepath: Path) -> Optional[dict]:
    """Read and parse a JSON file, returning None on error."""
    import json
    content = read_file_safe(filepath)
    if content is None:
        return None
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return None


def read_yaml_file(filepath: Path) -> Optional[dict]:
    """Read and parse a YAML file, returning None on error."""
    import yaml
    content = read_file_safe(filepath)
    if content is None:
        return None
    try:
        return yaml.safe_load(content) or {}
    except Exception:
        return None


def find_files_by_name(
    config: VibesafeConfig,
    filenames: list[str],
) -> list[Path]:
    """Find files matching specific names in the project."""
    results = []
    root = Path(config.project_path).resolve()
    exclude_dirs = set(config.exclude_dirs)

    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs and not d.startswith(".")
        ]
        for filename in files:
            if filename in filenames:
                results.append(Path(dirpath) / filename)
    return results


def find_files_by_pattern(
    config: VibesafeConfig,
    pattern: str,
) -> list[Path]:
    """Find files matching a glob pattern in the project."""
    results = []
    root = Path(config.project_path).resolve()
    exclude_dirs = set(config.exclude_dirs)

    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs and not d.startswith(".")
        ]
        for filename in files:
            if fnmatch.fnmatch(filename, pattern):
                results.append(Path(dirpath) / filename)
    return results


def scan_file_for_patterns(
    filepath: Path,
    patterns: list[tuple[str, re.Pattern]],
    project_root: Path,
) -> list[dict]:
    """
    Scan a single file against a list of (name, regex_pattern) tuples.
    Returns list of matches with file path, line number, and matched content.
    """
    content = read_file_safe(filepath)
    if content is None:
        return []

    matches = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, start=1):
        for pattern_name, pattern in patterns:
            if pattern.search(line):
                # Get relative path for cleaner display
                try:
                    rel_path = filepath.relative_to(project_root)
                except ValueError:
                    rel_path = filepath

                matches.append({
                    "pattern_name": pattern_name,
                    "file_path": str(rel_path),
                    "absolute_path": str(filepath),
                    "line_number": line_num,
                    "line_content": line.strip(),
                })
    return matches


def relative_path(filepath: Path, project_root: Path) -> str:
    """Get relative path string, falling back to absolute if not relative."""
    try:
        return str(filepath.relative_to(project_root))
    except ValueError:
        return str(filepath)


def count_lines(filepath: Path) -> int:
    """Count lines in a file."""
    content = read_file_safe(filepath)
    if content is None:
        return 0
    return len(content.split("\n"))


def truncate_string(s: str, max_len: int = 120) -> str:
    """Truncate a string with ellipsis if too long."""
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


def is_binary_file(filepath: Path) -> bool:
    """Check if a file appears to be binary."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except Exception:
        return True


def file_exists_in_project(config: VibesafeConfig, filename: str) -> bool:
    """Check if a file exists anywhere in the project."""
    return len(find_files_by_name(config, [filename])) > 0


def get_project_root(config: VibesafeConfig) -> Path:
    """Get the resolved project root path."""
    return Path(config.project_path).resolve()
