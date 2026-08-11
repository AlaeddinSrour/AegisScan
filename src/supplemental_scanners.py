"""Deterministic dependency and secret scanners used alongside Semgrep."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .models import FindingDisposition, ReviewIssue
from .scope import classify_code_role, load_ignore_patterns


OSV_TIMEOUT_SECONDS = int(os.environ.get("AEGISSCAN_OSV_TIMEOUT", "300"))
SECRET_SCANNER_TIMEOUT_SECONDS = int(
    os.environ.get(
        "AEGISSCAN_BETTERLEAKS_TIMEOUT",
        os.environ.get("AEGISSCAN_GITLEAKS_TIMEOUT", "300"),
    )
)


@dataclass
class DetectorResult:
    """Normalized output from one deterministic supplemental detector."""

    detector: str
    finding_count: int = 0
    issues: list[ReviewIssue] = field(default_factory=list)
    dispositions: list[FindingDisposition] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _executable(command: str, environment_name: str) -> str | None:
    configured = os.environ.get(environment_name)
    if configured:
        return configured
    discovered = shutil.which(command)
    if discovered:
        return discovered
    for prefix in ("/opt/homebrew/bin", "/usr/local/bin"):
        candidate = Path(prefix) / command
        if candidate.is_file():
            return str(candidate)
    return None


def _compact_error(value: str) -> str:
    return " ".join(value.split())[:500]


def _finding_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha256(
        "\0".join(str(part) for part in parts).encode("utf-8", errors="replace")
    ).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _relative_file(repo_root: Path, raw_path: object) -> tuple[str, Path | None]:
    if not raw_path:
        return "dependency-inventory", None
    path = Path(str(raw_path))
    candidate = path.resolve() if path.is_absolute() else (repo_root / path).resolve()
    try:
        relative = candidate.relative_to(repo_root).as_posix()
    except ValueError:
        return Path(str(raw_path)).name or "dependency-inventory", None
    return relative, candidate if candidate.is_file() else None


def _severity(vulnerability: dict[str, object]) -> str:
    labels: list[str] = []
    for key in ("database_specific", "ecosystem_specific"):
        value = vulnerability.get(key)
        if isinstance(value, dict) and value.get("severity"):
            labels.append(str(value["severity"]).upper())
    joined = " ".join(labels)
    if "CRITICAL" in joined:
        return "CRITICAL"
    if "HIGH" in joined:
        return "HIGH"
    if any(value in joined for value in ("MODERATE", "MEDIUM")):
        return "WARNING"
    if isinstance(vulnerability.get("severity"), list):
        # OSV often carries a CVSS vector rather than a textual band. Without
        # adding a second CVSS implementation, retain it as actionable warning
        # evidence instead of incorrectly labeling a known advisory as INFO.
        return "WARNING"
    return "INFO"


def _fixed_versions(vulnerability: dict[str, object]) -> list[str]:
    versions: list[str] = []
    affected = vulnerability.get("affected")
    if not isinstance(affected, list):
        return versions
    for item in affected:
        if not isinstance(item, dict):
            continue
        ranges = item.get("ranges")
        if not isinstance(ranges, list):
            continue
        for version_range in ranges:
            if not isinstance(version_range, dict):
                continue
            events = version_range.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and event.get("fixed"):
                    version = str(event["fixed"])
                    if version not in versions:
                        versions.append(version)
    return versions


def scan_dependencies(repo_path: str) -> DetectorResult:
    """Run OSV-Scanner V2 and normalize known vulnerable dependencies."""
    result = DetectorResult(detector="osv")
    executable = _executable("osv-scanner", "OSV_SCANNER_COMMAND")
    if executable is None:
        result.errors.append(
            "OSV-Scanner is unavailable. Install it with `brew install osv-scanner`."
        )
        return result

    root = Path(repo_path).resolve()
    command = [
        executable,
        "scan",
        "source",
        "--format=json",
        "--recursive",
        str(root),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=OSV_TIMEOUT_SECONDS,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result.errors.append(f"OSV-Scanner could not complete: {_compact_error(str(exc))}")
        return result

    if completed.returncode == 128:
        # OSV-Scanner documents 128 as "no packages found". This is a valid,
        # non-applicable result for repositories without supported manifests.
        return result
    if completed.returncode not in {0, 1} or not completed.stdout.strip():
        detail = _compact_error(completed.stderr or "no JSON output")
        result.errors.append(
            f"OSV-Scanner exited with status {completed.returncode}: {detail}"
        )
        return result
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        result.errors.append(f"OSV-Scanner returned invalid JSON: {exc}")
        return result

    ignore_patterns = load_ignore_patterns(root)
    seen: set[tuple[str, str, str, str]] = set()
    scan_results = payload.get("results") if isinstance(payload, dict) else None
    for scan_result in scan_results if isinstance(scan_results, list) else []:
        if not isinstance(scan_result, dict):
            continue
        source = scan_result.get("source")
        source_path = source.get("path") if isinstance(source, dict) else ""
        relative_file, current_file = _relative_file(root, source_path)
        role = classify_code_role(relative_file, ignore_patterns)
        packages = scan_result.get("packages")
        for package_entry in packages if isinstance(packages, list) else []:
            if not isinstance(package_entry, dict):
                continue
            package = package_entry.get("package")
            package = package if isinstance(package, dict) else {}
            package_name = str(package.get("name") or "unknown package")
            package_version = str(package.get("version") or "unknown version")
            grouped_ids: dict[str, str] = {}
            groups = package_entry.get("groups")
            for group in groups if isinstance(groups, list) else []:
                if not isinstance(group, dict) or not isinstance(group.get("ids"), list):
                    continue
                ids = sorted(str(value) for value in group["ids"] if value)
                if ids:
                    grouped_ids.update({value: ids[0] for value in ids})
            vulnerabilities = package_entry.get("vulnerabilities")
            for vulnerability in vulnerabilities if isinstance(vulnerabilities, list) else []:
                if not isinstance(vulnerability, dict):
                    continue
                raw_vulnerability_id = str(vulnerability.get("id") or "OSV-UNKNOWN")
                vulnerability_id = grouped_ids.get(
                    raw_vulnerability_id, raw_vulnerability_id
                )
                key = (relative_file, package_name, package_version, vulnerability_id)
                if key in seen:
                    continue
                seen.add(key)
                finding_id = _finding_id("OSV", *key)
                fixed = _fixed_versions(vulnerability)
                fixed_text = ", ".join(fixed[:5]) if fixed else "a reviewed non-vulnerable release"
                advisory_summary = _compact_error(
                    str(vulnerability.get("summary") or "A known vulnerability affects this dependency version.")
                )
                line = 1
                if current_file is not None:
                    try:
                        for index, text in enumerate(
                            current_file.read_text(encoding="utf-8", errors="replace").splitlines(),
                            start=1,
                        ):
                            if package_name.casefold() in text.casefold():
                                line = index
                                break
                    except OSError:
                        pass
                issue = ReviewIssue(
                    file=relative_file,
                    line=line,
                    severity=_severity(vulnerability),
                    issue_name=f"Vulnerable dependency: {package_name} ({vulnerability_id})",
                    description=(
                        f"{package_name} {package_version} matches {vulnerability_id}. "
                        f"{advisory_summary}"
                    ),
                    original_code=f"{package_name} {package_version}",
                    suggested_fix=f"Upgrade {package_name} to {fixed_text} after compatibility testing.",
                    finding_id=finding_id,
                    rule_id=f"osv.{vulnerability_id}",
                    confidence="MEDIUM",
                    code_role=role,
                    source_evidence=(
                        f"OSV-Scanner resolved {package_name} {package_version} from "
                        f"{relative_file}."
                    ),
                    sink_evidence=f"The resolved version is listed as affected by {vulnerability_id}.",
                    sink_file=relative_file,
                    sink_line=line,
                    reachability_evidence=(
                        "The vulnerable version is present in dependency metadata; runtime call "
                        "reachability was not established."
                    ),
                    remediation_type="MANUAL_REQUIRED",
                )
                result.issues.append(issue)
                result.dispositions.append(
                    FindingDisposition(
                        finding_id=finding_id,
                        status="CONFIRMED",
                        reason=(
                            "OSV matched the resolved package version to a published advisory; "
                            "runtime reachability may still require review."
                        ),
                        file=relative_file,
                        line=line,
                        rule_id=f"osv.{vulnerability_id}",
                        message=advisory_summary,
                        code_role=role,
                        confidence="MEDIUM",
                    )
                )
    result.finding_count = len(seen)
    return result


def _secret_scanner() -> tuple[str, str] | None:
    """Prefer Betterleaks while retaining Gitleaks as a transition fallback."""
    betterleaks = _executable("betterleaks", "BETTERLEAKS_COMMAND")
    if betterleaks:
        return "betterleaks", betterleaks
    gitleaks = _executable("gitleaks", "GITLEAKS_COMMAND")
    if gitleaks:
        return "gitleaks", gitleaks
    return None


def _run_secret_scanner_mode(
    scanner: str,
    executable: str,
    root: Path,
    mode: str,
    report_path: Path,
    max_target_bytes: int,
) -> tuple[list[dict[str, object]], str | None]:
    command = [
        executable,
        mode,
        "--no-banner",
        "--redact=100",
        "--max-target-megabytes",
        str(max(1, (int(max_target_bytes) + 999_999) // 1_000_000)),
        "--report-format=json",
        "--report-path",
        str(report_path),
        str(root),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=SECRET_SCANNER_TIMEOUT_SECONDS,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], (
            f"{scanner.title()} {mode} scan could not complete: "
            f"{_compact_error(str(exc))}"
        )
    if completed.returncode not in {0, 1}:
        return [], (
            f"{scanner.title()} {mode} scan exited with status {completed.returncode}: "
            f"{_compact_error(completed.stderr or 'no diagnostic output')}"
        )
    if not report_path.is_file():
        return [], None
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"{scanner.title()} {mode} scan returned invalid JSON: {exc}"
    findings = (
        [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, list)
        else []
    )
    return findings, None


def _finding_value(finding: dict[str, object], *names: str) -> object:
    """Read current and compatibility Betterleaks/Gitleaks report fields."""
    for name in names:
        value = finding.get(name)
        if value not in (None, ""):
            return value
    attributes = finding.get("Attributes") or finding.get("attributes")
    if isinstance(attributes, dict):
        for name in names:
            value = attributes.get(name)
            if value not in (None, ""):
                return value
    return ""


def _strong_secret_rule(rule_id: str) -> bool:
    """Return whether a rule identifies a specific credential format."""
    normalized = rule_id.casefold().replace("_", "-")
    uncertain = (
        "generic-api-key",
        "generic-secret",
        "generic-password",
        "password",
        "jwt",
    )
    return not any(
        normalized == value or normalized.startswith(f"{value}.")
        for value in uncertain
    )


def scan_secrets(repo_path: str, max_target_bytes: int = 1_000_000) -> DetectorResult:
    """Scan current files and Git history without retaining matched secret values."""
    selected = _secret_scanner()
    if selected is None:
        result = DetectorResult(detector="betterleaks")
        result.errors.append(
            "No supported secret scanner is available. Install Betterleaks with "
            "`brew install betterleaks` (preferred), or Gitleaks as a fallback."
        )
        return result
    scanner, executable = selected
    display_name = "Betterleaks" if scanner == "betterleaks" else "Gitleaks"
    result = DetectorResult(detector=scanner)

    root = Path(repo_path).resolve()
    ignore_patterns = load_ignore_patterns(root)
    with tempfile.TemporaryDirectory(prefix=f"aegisscan-{scanner}-") as temporary:
        temporary_root = Path(temporary)
        current, current_error = _run_secret_scanner_mode(
            display_name,
            executable,
            root,
            "dir",
            temporary_root / "current.json",
            max_target_bytes,
        )
        history, history_error = _run_secret_scanner_mode(
            display_name,
            executable,
            root,
            "git",
            temporary_root / "history.json",
            max_target_bytes,
        )
    result.errors.extend(error for error in (current_error, history_error) if error)

    seen: set[tuple[str, str, int, int]] = set()
    for mode, findings in (("current", current), ("history", history)):
        for finding in findings:
            rule_id = str(
                _finding_value(finding, "RuleID", "rule_id") or "generic-secret"
            )
            description = _compact_error(
                str(
                    _finding_value(finding, "Description", "description")
                    or "Potential hardcoded credential"
                )
            )
            relative_file, current_file = _relative_file(
                root, _finding_value(finding, "File", "path")
            )
            try:
                line = max(
                    1,
                    int(_finding_value(finding, "StartLine", "start_line") or 1),
                )
            except (TypeError, ValueError):
                line = 1
            try:
                column = max(
                    0,
                    int(
                        _finding_value(finding, "StartColumn", "start_column")
                        or 0
                    ),
                )
            except (TypeError, ValueError):
                column = 0
            key = (rule_id, relative_file, line, column)
            if key in seen:
                continue
            seen.add(key)
            role = classify_code_role(relative_file, ignore_patterns)
            finding_id = _finding_id("SECRET", *key)
            commit = str(
                _finding_value(finding, "Commit", "git.sha", "commit") or ""
            )[:12]
            validation_status = str(
                _finding_value(
                    finding,
                    "ValidationStatus",
                    "validationStatus",
                    "validation_status",
                )
                or ""
            ).casefold()
            is_current_runtime = mode == "current" and current_file is not None and role in {
                "RUNTIME",
                "UNKNOWN",
            }
            is_confirmed = is_current_runtime and (
                validation_status in {"valid", "revoked"}
                or (not validation_status and _strong_secret_rule(rule_id))
            )
            rule_name = f"{scanner}.{rule_id}"
            if validation_status == "invalid":
                status = "FALSE_POSITIVE"
                reason = (
                    f"{display_name} validation classified the redacted candidate as invalid."
                )
                confidence = "HIGH"
            elif not is_current_runtime and role not in {"RUNTIME", "UNKNOWN"}:
                status = "NON_RUNTIME"
                reason = (
                    "Deterministic scope classification marked this redacted secret "
                    f"finding as {role.lower()}."
                )
                confidence = "HIGH"
            elif is_confirmed:
                result.issues.append(
                    ReviewIssue(
                        file=relative_file,
                        line=line,
                        severity="HIGH",
                        issue_name=f"Potential hardcoded secret: {description}",
                        description=(
                            f"{display_name} matched a specific credential pattern in current "
                            "runtime source. "
                            "The value is redacted and must be validated, rotated, and removed from history."
                        ),
                        original_code="[REDACTED SECRET]",
                        suggested_fix=(
                            "Remove the credential, load it from an approved secret store, rotate it, "
                            "and purge exposed history where required."
                        ),
                        finding_id=finding_id,
                        rule_id=rule_name,
                        confidence="HIGH",
                        code_role=role,
                        source_evidence=(
                            f"{display_name} rule {rule_id} matched a redacted value at "
                            f"{relative_file}:{line}."
                        ),
                        sink_evidence="A credential-shaped value is stored in repository source.",
                        sink_file=relative_file,
                        sink_line=line,
                        reachability_evidence=(
                            "The value is present in current runtime source; credential validity is "
                            "intentionally not tested."
                        ),
                        remediation_type="MANUAL_REQUIRED",
                    )
                )
                status = "CONFIRMED"
                reason = (
                    "A redacted credential pattern is present in current runtime source. "
                    "Rotation and history review are required."
                )
                confidence = "HIGH"
            else:
                status = "NEEDS_REVIEW"
                location = (
                    f"commit {commit}"
                    if commit
                    else "current runtime source"
                    if is_current_runtime
                    else f"{role.lower()} source"
                )
                reason = (
                    f"{display_name} matched a redacted credential pattern in {location}; "
                    "manual validation and rotation review are required."
                )
                confidence = "MEDIUM"
            result.dispositions.append(
                FindingDisposition(
                    finding_id=finding_id,
                    status=status,
                    reason=reason,
                    file=relative_file,
                    line=line,
                    rule_id=rule_name,
                    message=description,
                    code_role=role,
                    confidence=confidence,
                )
            )
    result.finding_count = len(seen)
    return result
