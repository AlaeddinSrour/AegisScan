"""Deterministic repository-scope classification for security findings."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

from .models import CodeRole


DEPENDENCY_SEGMENTS = {
    "node_modules",
    "vendor",
    "vendors",
    "third_party",
    "third-party",
}
GENERATED_SEGMENTS = {
    "build",
    "dist",
    "coverage",
    ".next",
    ".nuxt",
    "generated",
    "target",
}
TEST_SEGMENTS = {"test", "tests", "spec", "specs", "__tests__"}
FIXTURE_SEGMENTS = {
    "fixture",
    "fixtures",
    "codefixes",
    "examples",
    "example",
    "samples",
    "sample",
    "training",
}
DOCUMENTATION_SEGMENTS = {"doc", "docs", "documentation"}
KNOWN_VENDORED_ASSETS = {
    "angular.js",
    "bootstrap.js",
    "d3.js",
    "jquery.js",
    "moment.js",
    "react.js",
    "three.js",
    "vue.js",
}


def load_ignore_patterns(repo_root: Path) -> list[str]:
    """Load optional repository-relative patterns from ``.aegisscanignore``."""
    ignore_file = repo_root / ".aegisscanignore"
    if not ignore_file.is_file():
        return []
    patterns: list[str] = []
    for raw_line in ignore_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            patterns.append(
                "!" + line[2:] if line.startswith("!/") else line.lstrip("/")
            )
    return patterns


def is_ignored(path: str, patterns: list[str]) -> bool:
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix().lstrip("./")
    ignored = False
    for raw_pattern in patterns:
        forced_runtime = raw_pattern.startswith("!")
        pattern = raw_pattern[1:] if forced_runtime else raw_pattern
        if fnmatch(normalized, pattern) or fnmatch(
            normalized, pattern.rstrip("/") + "/**"
        ):
            ignored = not forced_runtime
    return ignored


def is_forced_runtime(path: str, patterns: list[str]) -> bool:
    """Return whether the last matching negated scope pattern forces runtime."""
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix().lstrip("./")
    forced = False
    for raw_pattern in patterns:
        pattern = raw_pattern[1:] if raw_pattern.startswith("!") else raw_pattern
        if fnmatch(normalized, pattern) or fnmatch(
            normalized, pattern.rstrip("/") + "/**"
        ):
            forced = raw_pattern.startswith("!")
    return forced


def classify_code_role(path: str, ignore_patterns: list[str] | None = None) -> CodeRole:
    """Classify a path without relying on model judgment or repository content."""
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix().lstrip("./")
    if ignore_patterns and is_forced_runtime(normalized, ignore_patterns):
        return "RUNTIME"
    if ignore_patterns and is_ignored(normalized, ignore_patterns):
        return "IGNORED"

    lowered_parts = tuple(part.casefold() for part in PurePosixPath(normalized).parts)
    part_set = set(lowered_parts)
    filename = lowered_parts[-1] if lowered_parts else ""

    if part_set & DEPENDENCY_SEGMENTS or (
        "assets" in part_set and filename in KNOWN_VENDORED_ASSETS
    ):
        return "DEPENDENCY"
    if part_set & GENERATED_SEGMENTS or filename.endswith(
        (".min.js", ".min.css", ".generated.ts", ".bundle.js", ".chunk.js", ".map")
    ):
        return "GENERATED"
    if part_set & FIXTURE_SEGMENTS:
        return "FIXTURE"
    if part_set & TEST_SEGMENTS or any(token in filename for token in (".test.", ".spec.")):
        return "TEST"
    if part_set & DOCUMENTATION_SEGMENTS or filename.endswith((".md", ".rst", ".adoc")):
        return "DOCUMENTATION"
    if normalized:
        return "RUNTIME"
    return "UNKNOWN"


def is_runtime_role(role: CodeRole) -> bool:
    return role in {"RUNTIME", "UNKNOWN"}
