"""Semgrep runner with explicit failure handling and optional diff filtering."""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .scope import classify_code_role, is_runtime_role, load_ignore_patterns

logger = logging.getLogger(__name__)

SEMGREP_TIMEOUT_SECONDS = int(os.environ.get("AEGISSCAN_SEMGREP_TIMEOUT", "300"))


def _error_detail(error: object) -> str:
    if isinstance(error, dict):
        value = error.get("message") or error.get("type") or str(error)
    else:
        value = str(error)
    return " ".join(str(value).split())[:300]


def _error_path(repo_root: Path, error: object) -> str:
    """Return a contained repository-relative target path from a Semgrep error."""
    if not isinstance(error, dict) or not error.get("path"):
        return ""
    raw_path = Path(str(error["path"]))
    candidate = raw_path.resolve() if raw_path.is_absolute() else (repo_root / raw_path).resolve()
    try:
        return candidate.relative_to(repo_root).as_posix()
    except ValueError:
        return ""


def _error_line(error: object) -> int:
    if isinstance(error, dict):
        spans = error.get("spans") or []
        if spans and isinstance(spans[0], dict):
            start = spans[0].get("start") or {}
            if isinstance(start, dict) and isinstance(start.get("line"), int):
                return max(1, start["line"])
        message = str(error.get("message") or "")
        match = re.search(r":(\d+)(?::|\b)", message)
        if match:
            return max(1, int(match.group(1)))
    return 1


def _is_target_parse_error(error: object) -> bool:
    if not isinstance(error, dict):
        return False
    error_type = re.sub(r"[^a-z]", "", str(error.get("type") or "").casefold())
    return any(marker in error_type for marker in ("syntaxerror", "partialparsing", "lexicalerror"))


def _is_resource_limit_error(error: object) -> bool:
    if not isinstance(error, dict):
        return False
    error_type = re.sub(r"[^a-z]", "", str(error.get("type") or "").casefold())
    return any(
        marker in error_type
        for marker in (
            "timeout",
            "outofmemory",
            "stackoverflow",
            "fixpointtimeout",
        )
    )


def _partition_scan_errors(
    repo_path: str,
    scan_errors: list[object],
) -> tuple[
    list[tuple[object, str, int, str]],
    list[tuple[object, str, int, str]],
    list[object],
]:
    """Separate auditable non-runtime parser errors from completeness failures."""
    root = Path(repo_path).resolve()
    patterns = load_ignore_patterns(root)
    non_runtime_errors: list[tuple[object, str, int, str]] = []
    runtime_incomplete_errors: list[tuple[object, str, int, str]] = []
    fatal_errors: list[object] = []
    for error in scan_errors:
        path = _error_path(root, error)
        role = classify_code_role(path, patterns) if path else "UNKNOWN"
        location = (error, path, _error_line(error), role)
        if path and not is_runtime_role(role) and (
            _is_target_parse_error(error) or _is_resource_limit_error(error)
        ):
            non_runtime_errors.append(location)
        elif path and is_runtime_role(role) and _is_resource_limit_error(error):
            runtime_incomplete_errors.append(location)
        else:
            fatal_errors.append(error)
    return non_runtime_errors, runtime_incomplete_errors, fatal_errors


def _semgrep_executable() -> str:
    """Find Semgrep even when a macOS app has a restricted GUI PATH."""
    configured = os.environ.get("SEMGREP_COMMAND")
    if configured:
        return configured
    discovered = shutil.which("semgrep")
    if discovered:
        return discovered
    for candidate in ("/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep"):
        if Path(candidate).is_file():
            return candidate
    return "semgrep"


def _aegisscan_rules_path() -> Path:
    """Return the packaged, versioned ruleset used as the coverage floor."""
    return Path(__file__).resolve().with_name("aegisscan_rules.yml")


def run_semgrep_scan(
    repo_path: str,
    changed_files_lines: Optional[dict[str, set[int]]] = None,
) -> str:
    """
    Run Semgrep on the repository and return formatted findings for LLM triage.

    Findings are filtered to only include lines modified in the PR when
    `changed_files_lines` is provided.

    Args:
        repo_path: Absolute path to the repository root.
        changed_files_lines: Mapping of {filepath: set(modified_line_numbers)}.

    Returns:
        Formatted string of Semgrep findings, or "" if none found.
    """
    logger.info("Running Semgrep scan for sequential triage...")
    try:
        semgrep_cmd = [
            _semgrep_executable(), "scan",
            "--config", str(_aegisscan_rules_path()),
            "--config", "p/security-audit",
            "--config", "p/python",
            "--exclude", ".github",
            "--exclude", ".git",
            "--exclude", ".venv",
            "--exclude", "node_modules",
            "--max-target-bytes", "1000000",
            "--json",
            "--quiet",
        ]
        scan_environment = os.environ.copy()
        system_certificate_store = Path("/etc/ssl/cert.pem")
        if system_certificate_store.is_file():
            scan_environment.setdefault("SSL_CERT_FILE", str(system_certificate_store))
        scan_environment.setdefault("SEMGREP_SEND_METRICS", "off")
        scan_environment.setdefault(
            "SEMGREP_LOG_FILE",
            str(Path(tempfile.gettempdir()) / "aegisscan-semgrep.log"),
        )
        result = subprocess.run(
            semgrep_cmd + [repo_path],
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT_SECONDS,
            env=scan_environment,
        )
        if not result.stdout:
            returncode = result.returncode if isinstance(result.returncode, int) else 0
            error = " ".join((result.stderr or "").split())[:400]
            if returncode != 0:
                raise RuntimeError(
                    f"Semgrep exited with status {returncode}: {error or 'no diagnostic output'}"
                )
            raise RuntimeError("Semgrep produced no JSON output; scan completeness is unknown.")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Semgrep returned invalid JSON output.") from exc

        scan_errors = data.get("errors") or []
        (
            non_runtime_errors,
            runtime_incomplete_errors,
            fatal_errors,
        ) = _partition_scan_errors(repo_path, scan_errors)
        returncode = result.returncode if isinstance(result.returncode, int) else 0
        if returncode != 0:
            diagnostics = " ".join((result.stderr or "").split())
            benign_signal_warning = (
                "Failed to register segfault signal handler" in diagnostics
                and "Failed to register unwind handler" in diagnostics
                and not fatal_errors
            )
            if benign_signal_warning:
                logger.warning(
                    "Semgrep emitted the known macOS signal-handler warning but returned "
                    "valid JSON without scan errors; continuing with its complete results."
                )
            else:
                raise RuntimeError(
                    f"Semgrep exited with status {returncode}: "
                    f"{diagnostics[:400] or 'no diagnostic output'}"
                )
        if fatal_errors:
            detail = _error_detail(fatal_errors[0])
            raise RuntimeError(
                f"Semgrep reported {len(fatal_errors)} runtime or global scan error(s); "
                f"completeness is unknown: {detail}"
            )
        if non_runtime_errors:
            logger.warning(
                "Semgrep could not completely scan %s deterministically non-runtime file(s); "
                "retaining them as NON_RUNTIME evidence.",
                len(non_runtime_errors),
            )
        if runtime_incomplete_errors:
            logger.warning(
                "Semgrep hit resource limits in %s runtime file/rule pair(s); "
                "retaining them as NEEDS_REVIEW evidence.",
                len(runtime_incomplete_errors),
            )
        results = data.get("results", [])
        if not results and not non_runtime_errors and not runtime_incomplete_errors:
            return ""

        formatted_findings = []
        for i, finding in enumerate(results):
            path = finding.get("path", "")
            if os.path.isabs(path):
                try:
                    path = os.path.relpath(path, repo_path)
                except ValueError:
                    continue
            start_line = finding.get("start", {}).get("line", "")

            # Diff-aware filtering
            if changed_files_lines is not None:
                if path not in changed_files_lines:
                    continue  # Skip files not modified in the PR
                if start_line not in changed_files_lines[path]:
                    continue  # Skip vulnerabilities on lines not modified in the PR

            rule_id = finding.get("check_id", "")
            message = finding.get("extra", {}).get("message", "")
            snippet = finding.get("extra", {}).get("lines", "").strip()

            file_context = ""
            try:
                root_path = Path(repo_path).resolve()
                full_path = (root_path / path).resolve()
                try:
                    full_path.relative_to(root_path)
                except ValueError as exc:
                    raise RuntimeError(
                        f"Semgrep returned a finding outside the repository boundary: {path}"
                    ) from exc
                if os.path.exists(full_path):
                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                        all_lines = f.readlines()
                    if start_line:
                        ctx_start = max(0, int(start_line) - 31)
                        ctx_end = min(len(all_lines), int(start_line) + 30)
                        file_context = "".join(all_lines[ctx_start:ctx_end])
                    else:
                        file_context = "".join(all_lines[:60])
            except RuntimeError:
                raise
            except Exception as e:
                logger.warning(f"Could not read file {path} for context: {e}")

            block = (
                f"Finding #{i + 1}:\n"
                f"Rule ID: {rule_id}\n"
                f"File: {path}:{start_line}\n"
                f"Message: {message}\n"
                f"Code Snippet: {snippet}\n"
            )
            if file_context:
                block += (
                    f"\n--- FILE CONTEXT ({path}:{max(1, int(start_line) - 30)}-{int(start_line) + 30}) ---\n"
                    f"{file_context}\n"
                    f"--- END FILE CONTEXT ---\n"
                )

            formatted_findings.append(block)

        for offset, (error, path, line, role) in enumerate(
            non_runtime_errors, start=len(results) + 1
        ):
            error_type = (
                str(error.get("type") or "Syntax error")
                if isinstance(error, dict)
                else "Syntax error"
            )
            formatted_findings.append(
                f"Finding #{offset}:\n"
                "Rule ID: aegisscan.semgrep.non-runtime-parse-error\n"
                f"File: {path}:{line}\n"
                f"Message: Semgrep {error_type} in deterministically {role.lower()} code; "
                "the file was not fully parsed and is retained for auditability.\n"
                "Code Snippet: [Scan error; source context intentionally omitted.]\n"
            )

        runtime_start = len(results) + len(non_runtime_errors) + 1
        for offset, (error, path, line, _role) in enumerate(
            runtime_incomplete_errors, start=runtime_start
        ):
            error_type = (
                str(error.get("type") or "resource limit")
                if isinstance(error, dict)
                else "resource limit"
            )
            formatted_findings.append(
                f"Finding #{offset}:\n"
                "Rule ID: aegisscan.semgrep.runtime-scan-incomplete\n"
                f"File: {path}:{line}\n"
                f"Message: Semgrep hit {error_type} while scanning this runtime file; "
                "coverage is incomplete and manual review is required.\n"
                "Code Snippet: [Resource-limit error; source context intentionally omitted.]\n"
            )

        return "\n".join(formatted_findings)

    except FileNotFoundError as exc:
        raise RuntimeError(
            "Semgrep is not installed. Install it with `brew install semgrep` "
            "or `python3 -m pip install semgrep`."
        ) from exc
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Semgrep scan timed out after {SEMGREP_TIMEOUT_SECONDS}s; "
            "the repository cannot be reported as clean."
        )
    except RuntimeError:
        raise
    except Exception as e:
        logger.error(f"Semgrep scan failed: {e}")
        raise RuntimeError(f"Semgrep scan failed: {e}") from e
