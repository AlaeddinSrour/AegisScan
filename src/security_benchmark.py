from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str
    line: int
    status: str = "DETECTED"
    fingerprint: str = ""
    suppressed: bool = False


def _normalized_path(value: str) -> str:
    return value.replace("\\", "/").removeprefix("./")


def _matches(finding: Finding, expectation: dict[str, Any]) -> bool:
    expected_path = _normalized_path(str(expectation["path"]))
    actual_path = _normalized_path(finding.path)
    path_matches = fnmatch(actual_path, expected_path) or actual_path.endswith(
        "/" + expected_path
    )
    line = expectation.get("line")
    tolerance = int(expectation.get("line_tolerance", 0))
    status = expectation.get("status")
    return (
        finding.rule_id == expectation["rule_id"]
        and path_matches
        and (line is None or abs(finding.line - int(line)) <= tolerance)
        and (status is None or finding.status == status)
    )


def findings_from_semgrep(payload: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    findings = []
    for result in payload.get("results", []):
        findings.append(
            Finding(
                rule_id=str(result.get("check_id", "")).removeprefix("src."),
                path=_normalized_path(str(result.get("path", ""))),
                line=int(result.get("start", {}).get("line", 0)),
                fingerprint=str(result.get("extra", {}).get("fingerprint", "")),
            )
        )
    errors = payload.get("errors", [])
    return findings, {"execution_successful": not errors, "errors": len(errors)}


def findings_from_sarif(payload: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    runs = payload.get("runs", [])
    if not runs:
        return [], {"execution_successful": False, "errors": 1}
    run = runs[0]
    findings = []
    for result in run.get("results", []):
        physical = (result.get("locations") or [{}])[0].get("physicalLocation", {})
        findings.append(
            Finding(
                rule_id=str(result.get("ruleId", "")),
                path=_normalized_path(
                    str(physical.get("artifactLocation", {}).get("uri", ""))
                ),
                line=int(physical.get("region", {}).get("startLine", 0)),
                status=str(result.get("properties", {}).get("status", "UNKNOWN")),
                fingerprint=str(
                    result.get("partialFingerprints", {}).get("aegisscanFindingId", "")
                ),
                suppressed=any(
                    item.get("status") == "accepted"
                    for item in result.get("suppressions", [])
                ),
            )
        )
    invocation = (run.get("invocations") or [{}])[0]
    properties = invocation.get("properties", {})
    telemetry = properties.get("aiTelemetry", {})
    duration_seconds = 0.0
    try:
        started = datetime.fromisoformat(str(properties.get("scanStartedAt", "")))
        completed = datetime.fromisoformat(str(properties.get("scanCompletedAt", "")))
        duration_seconds = max(0.0, (completed - started).total_seconds())
    except (TypeError, ValueError):
        pass
    complete = bool(invocation.get("executionSuccessful")) and not bool(
        properties.get("auditDegraded")
    )
    complete = complete and not properties.get("failedBatches")
    complete = complete and int(properties.get("runtimeScanGaps", 0)) == 0
    firmware = properties.get("detectorTelemetry", {}).get("firmware", {})
    inventories = firmware.get("openwrt_inventory", [])
    kernel_versions = sorted(
        {
            str(version)
            for inventory in inventories
            for version in inventory.get("kernel_versions", [])
        }
    )
    inventory_coverage_ratio = min(
        (
            float(inventory.get("inventory_coverage_ratio", 0.0))
            for inventory in inventories
        ),
        default=0.0,
    )
    return findings, {
        "execution_successful": complete,
        "errors": int(properties.get("runtimeScanGaps", 0)),
        "provider_request_attempts": int(telemetry.get("request_attempts", 0)),
        "provider_failures": int(telemetry.get("provider_request_failures", 0)),
        "provider_prompt_tokens": int(telemetry.get("provider_prompt_tokens", 0)),
        "provider_completion_tokens": int(telemetry.get("provider_completion_tokens", 0)),
        "provider_total_tokens": int(telemetry.get("provider_total_tokens", 0)),
        "provider_cost_usd": round(
            int(telemetry.get("provider_cost_microusd", 0)) / 1_000_000, 6
        ),
        "ai_batches": int(properties.get("aiAttemptedBatches", 0)),
        "duration_seconds": round(duration_seconds, 3),
        "repository_dirty": properties.get("repositoryDirty"),
        "semgrep_rule_mode": str(properties.get("semgrepRuleMode", "")),
        "scanner_diagnostics": int(properties.get("scannerDiagnosticCount", 0)),
        "inventory_coverage_ratio": round(inventory_coverage_ratio, 4),
        "kernel_versions": kernel_versions,
        "kernel_advisory_matches": int(
            firmware.get("official_kernel_advisories_matched", 0)
        ),
    }


def evaluate(
    findings: list[Finding], manifest: dict[str, Any], telemetry: dict[str, Any]
) -> dict[str, Any]:
    scope = manifest.get("scope", {})
    prefixes = tuple(scope.get("include_rule_prefixes", []))
    exact_rules = set(scope.get("include_rules", []))
    scoped = [
        finding
        for finding in findings
        if not finding.suppressed
        and finding.status not in {"FALSE_POSITIVE", "DUPLICATE", "NON_RUNTIME"}
        and ((not prefixes and not exact_rules)
        or finding.rule_id in exact_rules
        or finding.rule_id.startswith(prefixes))
    ]
    unique: list[Finding] = []
    seen: set[tuple[str, str, int, str]] = set()
    for finding in scoped:
        key = (finding.rule_id, finding.path, finding.line, finding.status)
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    unmatched = set(range(len(unique)))
    matched = 0
    missing: list[dict[str, Any]] = []
    for expectation in manifest.get("expected", []):
        match = next((index for index in unmatched if _matches(unique[index], expectation)), None)
        if match is None:
            missing.append(expectation)
        else:
            unmatched.remove(match)
            matched += 1

    allowed = manifest.get("allowed", [])
    unexpected = [
        unique[index]
        for index in sorted(unmatched)
        if not any(_matches(unique[index], item) for item in allowed)
    ]
    forbidden = [
        finding
        for finding in unique
        if any(_matches(finding, item) for item in manifest.get("forbidden", []))
    ]
    expected_count = len(manifest.get("expected", []))
    denominator = matched + len(unexpected)
    recall = matched / expected_count if expected_count else 1.0
    precision = matched / denominator if denominator else 1.0
    duplicate_count = len(scoped) - len(unique)
    duplicate_rate = duplicate_count / len(scoped) if scoped else 0.0
    unresolved = sum(finding.status in {"NEEDS_REVIEW", "UNKNOWN"} for finding in unique)

    gates = manifest.get("gates", {})
    failures = []
    if recall < float(gates.get("min_recall", 0.0)):
        failures.append(f"recall {recall:.3f} is below {gates['min_recall']}")
    if precision < float(gates.get("min_precision", 0.0)):
        failures.append(f"precision {precision:.3f} is below {gates['min_precision']}")
    if len(unexpected) > int(gates.get("max_unexpected", len(unexpected))):
        failures.append(f"unexpected findings {len(unexpected)} exceed {gates['max_unexpected']}")
    if len(forbidden) > int(gates.get("max_forbidden", 0)):
        failures.append(f"forbidden findings {len(forbidden)} exceed {gates.get('max_forbidden', 0)}")
    if unresolved > int(gates.get("max_unresolved", unresolved)):
        failures.append(f"unresolved findings {unresolved} exceed {gates['max_unresolved']}")
    if duplicate_rate > float(gates.get("max_duplicate_rate", duplicate_rate)):
        failures.append(
            f"duplicate rate {duplicate_rate:.3f} exceeds {gates['max_duplicate_rate']}"
        )
    if gates.get("require_complete") and not telemetry.get("execution_successful"):
        failures.append("audit or detector execution is incomplete")
    if gates.get("require_clean_repository") and telemetry.get("repository_dirty") is not False:
        failures.append("benchmark repository was not a clean Git checkout")
    required_mode = gates.get("required_semgrep_rule_mode")
    if required_mode and telemetry.get("semgrep_rule_mode") != required_mode:
        failures.append(
            f"Semgrep rule mode {telemetry.get('semgrep_rule_mode')!r} is not {required_mode!r}"
        )
    if int(telemetry.get("scanner_diagnostics", 0)) > int(
        gates.get("max_scanner_diagnostics", telemetry.get("scanner_diagnostics", 0))
    ):
        failures.append(
            f"scanner diagnostics {telemetry.get('scanner_diagnostics', 0)} exceed "
            f"{gates['max_scanner_diagnostics']}"
        )
    minimum_inventory = float(gates.get("min_inventory_coverage_ratio", 0.0))
    if float(telemetry.get("inventory_coverage_ratio", 0.0)) < minimum_inventory:
        failures.append(
            f"inventory coverage {telemetry.get('inventory_coverage_ratio', 0.0):.3f} "
            f"is below {minimum_inventory}"
        )
    expected_kernels = sorted(str(value) for value in gates.get("expected_kernel_versions", []))
    if expected_kernels and sorted(telemetry.get("kernel_versions", [])) != expected_kernels:
        failures.append(
            f"kernel inventory {telemetry.get('kernel_versions', [])!r} does not match "
            f"{expected_kernels!r}"
        )
    minimum_kernel_advisories = int(gates.get("min_kernel_advisory_matches", 0))
    if int(telemetry.get("kernel_advisory_matches", 0)) < minimum_kernel_advisories:
        failures.append(
            f"kernel advisory matches {telemetry.get('kernel_advisory_matches', 0)} "
            f"are below {minimum_kernel_advisories}"
        )

    def serialized(finding: Finding) -> dict[str, Any]:
        return {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "status": finding.status,
        }

    return {
        "benchmark": manifest.get("name", "security benchmark"),
        "passed": not failures,
        "metrics": {
            "expected": expected_count,
            "matched": matched,
            "actual_scoped": len(scoped),
            "unique_scoped": len(unique),
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "duplicate_count": duplicate_count,
            "duplicate_rate": round(duplicate_rate, 4),
            "unresolved": unresolved,
            "unexpected": len(unexpected),
            "forbidden": len(forbidden),
            **telemetry,
        },
        "missing": missing,
        "unexpected": [serialized(item) for item in unexpected],
        "forbidden": [serialized(item) for item in forbidden],
        "failures": failures,
    }


def load_payload(path: Path, payload: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    if payload.get("version") == "2.1.0" and "runs" in payload:
        return findings_from_sarif(payload)
    if "results" in payload:
        return findings_from_semgrep(payload)
    raise ValueError(f"Unsupported benchmark result format: {path}")
