"""Deterministic dependency and secret scanners used alongside Semgrep."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .models import FindingDisposition, ReviewIssue
from .scope import classify_code_role, load_ignore_patterns


OSV_TIMEOUT_SECONDS = int(os.environ.get("AEGISSCAN_OSV_TIMEOUT", "300"))
DEPENDENCY_RESOLVE_TIMEOUT_SECONDS = int(
    os.environ.get("AEGISSCAN_DEPENDENCY_RESOLVE_TIMEOUT", "120")
)
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
    coverage_gaps: list[str] = field(default_factory=list)
    telemetry: dict[str, object] = field(default_factory=dict)


_DEPENDENCY_MANIFEST_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "cargo.lock",
    "go.mod",
    "gemfile.lock",
    "composer.lock",
    "packages.lock.json",
}
_DEPENDENCY_DESCRIPTOR_NAMES = {
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "cargo.toml",
    "gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}
_DEPENDENCY_SKIP_DIRS = {".git", ".venv", "node_modules", "vendor"}


@dataclass
class DependencyInventory:
    """Local dependency descriptors and resolvable scanner inputs."""

    manifests: list[str] = field(default_factory=list)
    scan_inputs: list[str] = field(default_factory=list)
    uncovered_manifests: list[str] = field(default_factory=list)
    known_package_count: int = 0
    uncounted_scan_inputs: int = 0


def _manifest_package_count(path: Path) -> int | None:
    """Return a bounded local package inventory count when cheaply available."""
    name = path.name.casefold()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            payload = json.loads(text)
            packages = payload.get("packages") if isinstance(payload, dict) else None
            if isinstance(packages, dict):
                return sum(bool(key) for key in packages)
            dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
            return len(dependencies) if isinstance(dependencies, dict) else 0
        if name == "pipfile.lock":
            payload = json.loads(text)
            return sum(
                len(payload.get(section, {}))
                for section in ("default", "develop")
                if isinstance(payload, dict) and isinstance(payload.get(section), dict)
            )
        if name == "composer.lock":
            payload = json.loads(text)
            return sum(
                len(payload.get(section, []))
                for section in ("packages", "packages-dev")
                if isinstance(payload, dict) and isinstance(payload.get(section), list)
            )
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if name in {"poetry.lock", "cargo.lock"}:
        return len(re.findall(r"(?m)^\[\[package\]\]\s*$", text))
    if name.startswith("requirements") and name.endswith(".txt"):
        return sum(
            bool(line.strip()) and not line.lstrip().startswith(("#", "-"))
            for line in text.splitlines()
        )
    if name == "go.mod":
        block_entries = len(re.findall(r"(?m)^\s+[A-Za-z0-9_.\-/]+\s+v\S+", text))
        inline_entries = len(re.findall(r"(?m)^require\s+[A-Za-z0-9_.\-/]+\s+v\S+", text))
        return block_entries + inline_entries
    return None


def _dependency_inventory(root: Path) -> DependencyInventory:
    manifests: list[str] = []
    scan_inputs: list[str] = []
    descriptor_entries: list[tuple[str, str, str]] = []
    known_package_count = 0
    uncounted_scan_inputs = 0
    for directory, child_directories, files in os.walk(root):
        child_directories[:] = [
            name for name in child_directories if name not in _DEPENDENCY_SKIP_DIRS
        ]
        directory_path = Path(directory)
        for filename in files:
            normalized = filename.casefold()
            is_scan_input = (
                normalized in _DEPENDENCY_MANIFEST_NAMES
                or (normalized.startswith("requirements") and normalized.endswith(".txt"))
                or normalized.endswith(".csproj")
            )
            is_descriptor = normalized in _DEPENDENCY_DESCRIPTOR_NAMES
            if not (is_scan_input or is_descriptor):
                continue
            path = directory_path / filename
            try:
                relative = path.resolve().relative_to(root).as_posix()
            except ValueError:
                continue
            manifests.append(relative)
            descriptor_entries.append((relative, normalized, path.parent.as_posix()))
            if not is_scan_input:
                continue
            scan_inputs.append(relative)
            package_count = _manifest_package_count(path)
            if package_count is None:
                uncounted_scan_inputs += 1
            else:
                known_package_count += package_count

    scan_names_by_directory: dict[str, set[str]] = {}
    for relative, normalized, directory in descriptor_entries:
        if relative in scan_inputs:
            scan_names_by_directory.setdefault(directory, set()).add(normalized)
    coverage_pairs = {
        "package.json": {
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lock",
            "bun.lockb",
        },
        "pyproject.toml": {
            "poetry.lock",
            "uv.lock",
            "pipfile.lock",
        },
        "setup.py": {"requirements.txt", "pipfile.lock", "poetry.lock", "uv.lock"},
        "setup.cfg": {"requirements.txt", "pipfile.lock", "poetry.lock", "uv.lock"},
        "pipfile": {"pipfile.lock"},
        "cargo.toml": {"cargo.lock"},
        "gemfile": {"gemfile.lock"},
        "composer.json": {"composer.lock"},
    }
    uncovered: list[str] = []
    for relative, normalized, directory in descriptor_entries:
        if normalized not in _DEPENDENCY_DESCRIPTOR_NAMES:
            continue
        expected = coverage_pairs.get(normalized)
        if expected is None or not expected.intersection(
            scan_names_by_directory.get(directory, set())
        ):
            uncovered.append(relative)
    return DependencyInventory(
        manifests=sorted(set(manifests)),
        scan_inputs=sorted(set(scan_inputs)),
        uncovered_manifests=sorted(set(uncovered)),
        known_package_count=known_package_count,
        uncounted_scan_inputs=uncounted_scan_inputs,
    )


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


def _run_osv_with_ephemeral_npm_locks(
    executable: str,
    root: Path,
    inventory: DependencyInventory,
) -> tuple[subprocess.CompletedProcess[str], dict[str, str], dict[str, object]]:
    """Run OSV, resolving uncovered npm manifests only in a temporary directory."""
    source_aliases: dict[str, str] = {}
    attempted = 0
    generated = 0
    resolved_packages = 0
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="aegisscan-dependencies-") as temporary:
        temporary_root = Path(temporary)
        generated_lockfiles: list[Path] = []
        npm = _executable("npm", "NPM_COMMAND")
        npm_manifests = [
            relative
            for relative in inventory.uncovered_manifests
            if Path(relative).name.casefold() == "package.json"
        ]
        attempted = len(npm_manifests)

        def resolve(relative: str) -> tuple[str, Path | None, str]:
            if npm is None:
                return relative, None, "npm is unavailable"
            source = root / relative
            destination = temporary_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(source, destination)
                executable_paths = [
                    str(Path(npm).parent),
                    "/opt/homebrew/bin",
                    "/usr/local/bin",
                    os.environ.get("PATH", ""),
                ]
                npm_result = subprocess.run(
                    [
                        npm,
                        "install",
                        "--package-lock-only",
                        "--ignore-scripts",
                        "--no-audit",
                        "--no-fund",
                        "--package-lock=true",
                        "--workspaces=false",
                    ],
                    cwd=destination.parent,
                    capture_output=True,
                    text=True,
                    timeout=DEPENDENCY_RESOLVE_TIMEOUT_SECONDS,
                    shell=False,
                    env={
                        **os.environ,
                        "PATH": os.pathsep.join(
                            dict.fromkeys(path for path in executable_paths if path)
                        ),
                        "npm_config_update_notifier": "false",
                    },
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return relative, None, _compact_error(str(exc))
            lockfile = destination.with_name("package-lock.json")
            if npm_result.returncode != 0 or not lockfile.is_file():
                detail = _compact_error(
                    npm_result.stderr or "npm did not produce package-lock.json"
                )
                return relative, None, detail
            return relative, lockfile, ""

        with ThreadPoolExecutor(max_workers=max(1, min(4, attempted))) as executor:
            resolutions = list(executor.map(resolve, npm_manifests))
        for relative, lockfile, failure in resolutions:
            if failure or lockfile is None:
                failures.append(f"{relative}: {failure or 'resolution failed'}")
                continue
            generated += 1
            resolved_packages += _manifest_package_count(lockfile) or 0
            generated_lockfiles.append(lockfile)
            source_aliases[str(lockfile.resolve())] = relative

        command = [
            executable,
            "scan",
            "source",
            "--format=json",
            "--recursive",
            str(root),
        ]
        for lockfile in generated_lockfiles:
            command.extend(["--lockfile", str(lockfile)])
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=OSV_TIMEOUT_SECONDS,
            shell=False,
        )
    return (
        completed,
        source_aliases,
        {
            "ephemeral_resolution_attempted": attempted,
            "ephemeral_lockfiles_generated": generated,
            "ephemeral_packages_resolved": resolved_packages,
            "ephemeral_resolution_failures": failures[:20],
            "repository_modified_for_resolution": False,
        },
    )


def scan_dependencies(repo_path: str) -> DetectorResult:
    """Run OSV-Scanner V2 and normalize known vulnerable dependencies."""
    result = DetectorResult(detector="osv")
    root = Path(repo_path).resolve()
    inventory = _dependency_inventory(root)
    result.telemetry = {
        "status": "not_started",
        "command_completed": False,
        "exit_code": None,
        "coverage_complete": not inventory.uncovered_manifests,
        "manifests_discovered": len(inventory.manifests),
        "manifest_files": inventory.manifests[:100],
        "manifest_files_truncated": len(inventory.manifests) > 100,
        "supported_manifests_discovered": len(inventory.scan_inputs),
        "supported_manifest_files": inventory.scan_inputs[:100],
        "uncovered_manifests": len(inventory.uncovered_manifests),
        "uncovered_manifest_files": inventory.uncovered_manifests[:100],
        "packages_in_local_inventory": inventory.known_package_count,
        "manifests_without_local_package_count": inventory.uncounted_scan_inputs,
        "manifest_inventory_complete": (
            not inventory.uncovered_manifests and inventory.uncounted_scan_inputs == 0
        ),
        "manifests_scanned": 0,
        "packages_queried": 0,
        "skip_reasons": [],
        "osv_result_sources": 0,
        "packages_with_advisory_data": 0,
    }
    executable = _executable("osv-scanner", "OSV_SCANNER_COMMAND")
    if executable is None:
        result.telemetry["status"] = "tool_unavailable"
        result.telemetry["skip_reasons"] = ["OSV-Scanner is not installed."]
        result.errors.append(
            "OSV-Scanner is unavailable. Install it with `brew install osv-scanner`."
        )
        return result

    try:
        completed, source_aliases, resolution_telemetry = _run_osv_with_ephemeral_npm_locks(
            executable, root, inventory
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        result.telemetry["status"] = "execution_failed"
        result.telemetry["skip_reasons"] = ["OSV-Scanner did not complete."]
        result.errors.append(f"OSV-Scanner could not complete: {_compact_error(str(exc))}")
        return result
    result.telemetry.update(resolution_telemetry)

    unresolved_manifests = [
        manifest
        for manifest in inventory.uncovered_manifests
        if manifest not in source_aliases.values()
    ]

    result.telemetry["exit_code"] = completed.returncode
    if completed.returncode == 128:
        # OSV-Scanner documents 128 as "no packages found". This is a valid,
        # non-applicable result for repositories without supported manifests.
        has_descriptors = bool(inventory.manifests)
        if has_descriptors:
            gap = (
                "Dependency manifests were found, but OSV-Scanner could not resolve "
                "a supported package inventory. Commit an ecosystem lockfile to enable "
                "version-based dependency coverage."
            )
            result.coverage_gaps.append(gap)
        result.telemetry.update(
            {
                "status": ("coverage_unavailable" if has_descriptors else "no_packages_found"),
                "coverage_complete": not has_descriptors,
                "command_completed": True,
                "skip_reasons": ["OSV-Scanner found no supported package inventory."],
            }
        )
        return result
    if completed.returncode not in {0, 1} or not completed.stdout.strip():
        result.telemetry["status"] = "execution_failed"
        result.telemetry["skip_reasons"] = ["OSV-Scanner exited without a usable report."]
        detail = _compact_error(completed.stderr or "no JSON output")
        result.errors.append(f"OSV-Scanner exited with status {completed.returncode}: {detail}")
        return result
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        result.telemetry["status"] = "invalid_output"
        result.telemetry["skip_reasons"] = ["OSV-Scanner returned invalid JSON."]
        result.errors.append(f"OSV-Scanner returned invalid JSON: {exc}")
        return result

    ignore_patterns = load_ignore_patterns(root)
    seen: set[tuple[str, str, str, str]] = set()
    scan_results = payload.get("results") if isinstance(payload, dict) else None
    reported_sources: set[str] = set()
    packages_with_advisory_data = 0
    unique_advisory_ids: set[str] = set()
    affected_package_versions: set[tuple[str, str]] = set()
    affected_packages: dict[str, dict[str, object]] = {}
    for scan_result in scan_results if isinstance(scan_results, list) else []:
        if not isinstance(scan_result, dict):
            continue
        source = scan_result.get("source")
        source_path = source.get("path") if isinstance(source, dict) else ""
        source_key = ""
        if source_path:
            try:
                source_key = str(Path(str(source_path)).resolve())
            except OSError:
                source_key = str(source_path)
        aliased_manifest = source_aliases.get(source_key)
        if aliased_manifest:
            relative_file = aliased_manifest
            current_file = root / aliased_manifest
        else:
            relative_file, current_file = _relative_file(root, source_path)
        reported_sources.add(relative_file)
        role = classify_code_role(relative_file, ignore_patterns)
        packages = scan_result.get("packages")
        for package_entry in packages if isinstance(packages, list) else []:
            if not isinstance(package_entry, dict):
                continue
            packages_with_advisory_data += 1
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
                vulnerability_id = grouped_ids.get(raw_vulnerability_id, raw_vulnerability_id)
                unique_advisory_ids.add(vulnerability_id)
                affected_package_versions.add((package_name, package_version))
                key = (relative_file, package_name, package_version, vulnerability_id)
                if key in seen:
                    continue
                seen.add(key)
                package_group = affected_packages.setdefault(
                    package_name,
                    {"versions": set(), "advisories": set(), "occurrences": 0},
                )
                package_group["versions"].add(package_version)  # type: ignore[union-attr]
                package_group["advisories"].add(vulnerability_id)  # type: ignore[union-attr]
                package_group["occurrences"] = int(package_group["occurrences"]) + 1
                finding_id = _finding_id("OSV", *key)
                fixed = _fixed_versions(vulnerability)
                fixed_text = ", ".join(fixed[:5]) if fixed else "a reviewed non-vulnerable release"
                advisory_summary = _compact_error(
                    str(
                        vulnerability.get("summary")
                        or "A known vulnerability affects this dependency version."
                    )
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
    if unresolved_manifests:
        result.coverage_gaps.append(
            "One or more dependency manifests have no supported lockfile, so exact "
            "version coverage is incomplete."
        )
    result.telemetry.update(
        {
            "status": ("partial_coverage" if unresolved_manifests else "completed"),
            "coverage_complete": not unresolved_manifests,
            "command_completed": True,
            "supported_manifests_discovered": (len(inventory.scan_inputs) + len(source_aliases)),
            "supported_manifest_files": sorted(
                set(inventory.scan_inputs).union(source_aliases.values())
            )[:100],
            "uncovered_manifests": len(unresolved_manifests),
            "uncovered_manifest_files": unresolved_manifests[:100],
            "manifest_inventory_complete": (
                not unresolved_manifests and inventory.uncounted_scan_inputs == 0
            ),
            "manifests_scanned": len(inventory.scan_inputs) + len(source_aliases),
            "packages_queried": inventory.known_package_count
            + int(resolution_telemetry["ephemeral_packages_resolved"]),
            "osv_result_sources": len(reported_sources),
            "packages_with_advisory_data": packages_with_advisory_data,
            "dependency_finding_occurrences": len(seen),
            "raw_dependency_finding_occurrences": len(seen),
            "unique_advisories": len(unique_advisory_ids),
            "raw_unique_advisories": len(unique_advisory_ids),
            "affected_package_versions": len(affected_package_versions),
            "affected_packages": sorted(
                (
                    {
                        "package": package_name,
                        "versions": sorted(group["versions"]),
                        "unique_advisories": len(group["advisories"]),
                        "occurrences": group["occurrences"],
                    }
                    for package_name, group in affected_packages.items()
                ),
                key=lambda item: (-int(item["occurrences"]), str(item["package"])),
            ),
        }
    )
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
        return [], (f"{scanner.title()} {mode} scan could not complete: {_compact_error(str(exc))}")
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
        [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
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
    return not any(normalized == value or normalized.startswith(f"{value}.") for value in uncertain)


def _is_localization_password_noise(rule_id: str, relative_file: str) -> bool:
    """Suppress generic password words from application translation catalogs."""
    normalized_rule = rule_id.casefold().replace("_", "-")
    path = Path(relative_file)
    parts = tuple(part.casefold() for part in path.parts)
    localization_directories = {"i18n", "l10n", "locale", "locales", "translations"}
    return (
        normalized_rule == "generic-password"
        and path.suffix.casefold() in {".json", ".json5", ".yaml", ".yml"}
        and any(part in localization_directories for part in parts[:-1])
    )


def _credential_collection_key(rule_id: str, relative_file: str) -> tuple[str, str, str] | None:
    """Group generic passwords in structured account collections by file.

    These files still produce a review item; grouping only prevents a seed/demo
    account list from overwhelming the queue with one row per credential.
    """
    normalized_rule = rule_id.casefold().replace("_", "-")
    path = Path(relative_file)
    if (
        normalized_rule == "generic-password"
        and path.suffix.casefold() in {".csv", ".json", ".json5", ".yaml", ".yml"}
        and path.stem.casefold()
        in {"account", "accounts", "credential", "credentials", "user", "users"}
    ):
        return ("credential-collection", normalized_rule, relative_file)
    return None


def _is_public_address_candidate(rule_id: str, current_file: Path | None, line: int) -> bool:
    """Recognize public blockchain addresses mislabeled as generic API keys."""
    if rule_id.casefold().replace("_", "-") != "generic-api-key":
        return False
    if current_file is None:
        return False
    try:
        lines = current_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    if line < 1 or line > len(lines):
        return False
    source_line = lines[line - 1]
    return bool(
        re.search(r"\b0x[0-9a-fA-F]{40}\b", source_line)
        and re.search(r"(?i)(?:address|contract|token)", source_line)
    )


def _current_file_digest(current_file: Path | None, cache: dict[Path, str]) -> str:
    """Hash a current source file for copied-file secret consolidation."""
    if current_file is None:
        return ""
    if current_file in cache:
        return cache[current_file]
    try:
        digest = hashlib.sha256(current_file.read_bytes()).hexdigest()
    except OSError:
        digest = ""
    cache[current_file] = digest
    return digest


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

    seen: dict[tuple[object, ...], int] = {}
    seen_occurrences: dict[tuple[object, ...], set[tuple[object, ...]]] = {}
    canonical_content_findings: dict[tuple[str, str, int, int], str] = {}
    disposition_indexes: dict[str, int] = {}
    file_digest_cache: dict[Path, str] = {}
    suppressed_localization = {"current": 0, "history": 0}
    consolidated_credential_collection_findings = 0
    for mode, findings in (("current", current), ("history", history)):
        for finding in findings:
            rule_id = str(_finding_value(finding, "RuleID", "rule_id") or "generic-secret")
            description = _compact_error(
                str(
                    _finding_value(finding, "Description", "description")
                    or "Potential hardcoded credential"
                )
            )
            relative_file, current_file = _relative_file(
                root, _finding_value(finding, "File", "path")
            )
            if _is_localization_password_noise(rule_id, relative_file):
                suppressed_localization[mode] += 1
                continue
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
                    int(_finding_value(finding, "StartColumn", "start_column") or 0),
                )
            except (TypeError, ValueError):
                column = 0
            commit = str(_finding_value(finding, "Commit", "git.sha", "commit") or "")[:12]
            collection_key = _credential_collection_key(rule_id, relative_file)
            key: tuple[object, ...] = collection_key or (
                "location",
                rule_id,
                relative_file,
                line,
                column,
            )
            occurrence = (
                mode,
                commit if mode == "history" else "",
                line,
                column,
            )
            if key in seen:
                disposition_index = seen[key]
                if occurrence in seen_occurrences[key]:
                    continue
                seen_occurrences[key].add(occurrence)
                if collection_key is not None:
                    consolidated_credential_collection_findings += 1
                existing = result.dispositions[disposition_index]
                commits = list(existing.commits)
                if commit and commit not in commits:
                    commits.append(commit)
                evidence_scope = existing.evidence_scope
                if mode == "history" and evidence_scope == "CURRENT":
                    evidence_scope = "CURRENT_AND_HISTORY"
                elif mode == "current" and evidence_scope == "GIT_HISTORY":
                    evidence_scope = "CURRENT_AND_HISTORY"
                updates: dict[str, object] = {
                    "evidence_scope": evidence_scope,
                    "commit": existing.commit or commit,
                    "commits": commits,
                    "occurrence_count": existing.occurrence_count + 1,
                }
                if (
                    mode == "history"
                    and existing.status == "FALSE_POSITIVE"
                    and "public blockchain address" in existing.reason
                ):
                    updates.update(
                        {
                            "status": "NEEDS_REVIEW",
                            "reason": (
                                "The current value is a public blockchain address, but "
                                "redacted Git-history evidence at this location cannot be "
                                "classified from the current source alone."
                            ),
                            "confidence": "MEDIUM",
                        }
                    )
                result.dispositions[disposition_index] = existing.model_copy(update=updates)
                continue
            role = classify_code_role(relative_file, ignore_patterns)
            finding_id = _finding_id("SECRET", *key)
            validation_status = str(
                _finding_value(
                    finding,
                    "ValidationStatus",
                    "validationStatus",
                    "validation_status",
                )
                or ""
            ).casefold()
            is_current_runtime = (
                mode == "current"
                and current_file is not None
                and role
                in {
                    "RUNTIME",
                    "UNKNOWN",
                }
            )
            is_confirmed = is_current_runtime and (
                validation_status in {"valid", "revoked"}
                or (not validation_status and _strong_secret_rule(rule_id))
            )
            rule_name = f"{scanner}.{rule_id}"
            content_key: tuple[str, str, int, int] | None = None
            canonical_finding_id = ""
            if is_confirmed and _strong_secret_rule(rule_id):
                file_digest = _current_file_digest(current_file, file_digest_cache)
                if file_digest:
                    content_key = (rule_id, file_digest, line, column)
                    canonical_finding_id = canonical_content_findings.get(content_key, "")
            if validation_status == "invalid":
                status = "FALSE_POSITIVE"
                reason = f"{display_name} validation classified the redacted candidate as invalid."
                confidence = "HIGH"
            elif mode == "current" and _is_public_address_candidate(rule_id, current_file, line):
                status = "FALSE_POSITIVE"
                reason = (
                    "The generic API-key match is a public blockchain address, not a "
                    "secret credential."
                )
                confidence = "HIGH"
            elif not is_current_runtime and role not in {"RUNTIME", "UNKNOWN"}:
                status = "NON_RUNTIME"
                reason = (
                    "Deterministic scope classification marked this redacted secret "
                    f"finding as {role.lower()}."
                )
                confidence = "HIGH"
            elif canonical_finding_id:
                status = "DUPLICATE"
                reason = (
                    "An identical source file contains the same specific secret pattern; "
                    f"consolidated into {canonical_finding_id}."
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
                    evidence_scope=("CURRENT" if mode == "current" else "GIT_HISTORY"),
                    commit=commit,
                    commits=[commit] if commit else [],
                    canonical_finding_id=canonical_finding_id,
                )
            )
            seen[key] = len(result.dispositions) - 1
            seen_occurrences[key] = {occurrence}
            disposition_indexes[finding_id] = len(result.dispositions) - 1
            if content_key is not None:
                if canonical_finding_id:
                    canonical_index = disposition_indexes.get(canonical_finding_id)
                    if canonical_index is not None:
                        canonical = result.dispositions[canonical_index]
                        result.dispositions[canonical_index] = canonical.model_copy(
                            update={"occurrence_count": canonical.occurrence_count + 1}
                        )
                else:
                    canonical_content_findings[content_key] = finding_id
    result.finding_count = len(result.dispositions)
    retained_raw_findings = (
        len(current)
        + len(history)
        - suppressed_localization["current"]
        - suppressed_localization["history"]
    )
    result.telemetry = {
        "current_raw_findings": len(current),
        "history_raw_findings": len(history),
        "unique_findings": result.finding_count,
        "deduplicated_occurrences": retained_raw_findings - result.finding_count,
        "suppressed_localization_findings": sum(suppressed_localization.values()),
        "suppressed_current_localization_findings": suppressed_localization["current"],
        "suppressed_history_localization_findings": suppressed_localization["history"],
        "consolidated_credential_collection_findings": (
            consolidated_credential_collection_findings
        ),
        "current_and_history_consolidations": sum(
            item.evidence_scope == "CURRENT_AND_HISTORY" for item in result.dispositions
        ),
        "duplicate_secret_locations": sum(
            item.status == "DUPLICATE" for item in result.dispositions
        ),
        "current_evidence": sum(
            item.evidence_scope in {"CURRENT", "CURRENT_AND_HISTORY"}
            for item in result.dispositions
        ),
        "history_evidence": sum(
            item.evidence_scope in {"GIT_HISTORY", "CURRENT_AND_HISTORY"}
            for item in result.dispositions
        ),
    }
    return result
