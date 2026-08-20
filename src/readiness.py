"""Local scanner discovery and concise readiness diagnostics."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScannerStatus:
    key: str
    name: str
    available: bool
    required: bool
    executable: str = ""
    version: str = ""
    detail: str = ""
    install_command: str = ""


def _resolve(command: str, environment_name: str) -> str | None:
    configured = os.environ.get(environment_name, "").strip()
    if configured:
        configured_path = Path(configured).expanduser()
        if configured_path.is_file():
            return str(configured_path)
        return shutil.which(configured)
    discovered = shutil.which(command)
    if discovered:
        return discovered
    for prefix in ("/opt/homebrew/bin", "/usr/local/bin"):
        candidate = Path(prefix) / command
        if candidate.is_file():
            return str(candidate)
    return None


def _version_text(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "Version unavailable"
    output = "\n".join((completed.stdout, completed.stderr)).strip()
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    return first_line[:120] or "Version unavailable"


def inspect_scanner_readiness(
    *,
    dependency_enabled: bool = True,
    secret_enabled: bool = True,
    include_versions: bool = True,
) -> list[ScannerStatus]:
    semgrep = _resolve("semgrep", "SEMGREP_COMMAND")
    osv = _resolve("osv-scanner", "OSV_SCANNER_COMMAND")
    betterleaks = _resolve("betterleaks", "BETTERLEAKS_COMMAND")
    gitleaks = _resolve("gitleaks", "GITLEAKS_COMMAND")
    secret_executable = betterleaks or gitleaks
    secret_name = (
        "Betterleaks"
        if betterleaks
        else "Gitleaks fallback"
        if gitleaks
        else "Betterleaks"
    )
    secret_version_command = (
        [secret_executable, "version"] if secret_executable else []
    )

    return [
        ScannerStatus(
            key="semgrep",
            name="Semgrep",
            available=semgrep is not None,
            required=True,
            executable=semgrep or "",
            version=_version_text([semgrep, "--version"])
            if semgrep and include_versions
            else "",
            detail=(
                "Required for repository static analysis."
                if semgrep
                else "Required scanner is not available on the app search path."
            ),
            install_command="python3 -m pip install semgrep",
        ),
        ScannerStatus(
            key="osv",
            name="OSV-Scanner",
            available=osv is not None,
            required=dependency_enabled,
            executable=osv or "",
            version=_version_text([osv, "--version"])
            if osv and include_versions
            else "",
            detail=(
                "Enabled dependency advisory scanner."
                if dependency_enabled
                else "Optional because dependency scanning is disabled."
            ),
            install_command="brew install osv-scanner",
        ),
        ScannerStatus(
            key="secrets",
            name=secret_name,
            available=secret_executable is not None,
            required=secret_enabled,
            executable=secret_executable or "",
            version=_version_text(secret_version_command)
            if secret_executable and include_versions
            else "",
            detail=(
                "Betterleaks is preferred; Gitleaks remains a supported fallback."
                if secret_executable
                else "No supported current/history secret scanner was found."
            ),
            install_command="brew install betterleaks",
        ),
    ]


def missing_required_scanners(statuses: list[ScannerStatus]) -> list[ScannerStatus]:
    return [status for status in statuses if status.required and not status.available]
