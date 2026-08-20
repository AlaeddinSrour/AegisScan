"""JSON and SARIF serialization for AegisScan audit outcomes."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import __version__
from .redaction import redact_review_report


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def build_report_payload(outcome: Any) -> dict[str, Any]:
    """Build the canonical JSON report shared by the CLI and desktop app."""
    safe_report = redact_review_report(outcome.report)
    secret_scope_counts = {
        scope: sum(
            disposition.rule_id.startswith(("betterleaks.", "gitleaks."))
            and disposition.evidence_scope == scope
            for disposition in safe_report.dispositions
        )
        for scope in ("CURRENT", "GIT_HISTORY", "CURRENT_AND_HISTORY", "UNKNOWN")
    }
    return {
        "summary": {
            "raw_semgrep_findings": outcome.raw_finding_count,
            "dependency_findings": outcome.dependency_finding_count,
            "secret_findings": outcome.secret_finding_count,
            "total_detector_findings": outcome.total_finding_count,
            "finding_batches": outcome.batch_count,
            "failed_batches": outcome.failed_batches,
            "failed_batch_reasons": outcome.failed_batch_reasons,
            "ai_attempted_batches": outcome.ai_attempted_batches,
            "ai_successful_batches": outcome.ai_successful_batches,
            "ai_triage_enabled": outcome.ai_triage_enabled,
            "ai_triage_degraded": outcome.ai_triage_degraded,
            "audit_degraded": outcome.audit_degraded,
            "detector_errors": outcome.detector_errors,
            "detector_telemetry": outcome.detector_telemetry,
            "scanner_diagnostics": outcome.scanner_diagnostics,
            "scanner_diagnostic_count": outcome.scanner_diagnostic_count,
            "dependency_scan_enabled": outcome.dependency_scan_enabled,
            "secret_scan_enabled": outcome.secret_scan_enabled,
            "secret_scanner": outcome.secret_scanner,
            "semgrep_rule_mode": outcome.semgrep_rule_mode,
            "semgrep_rules_sha256": outcome.semgrep_rules_sha256,
            "runtime_scan_gaps": outcome.runtime_scan_gap_count,
            "provenance": {
                "aegisscan_version": outcome.app_version,
                "scan_started_at": outcome.scan_started_at,
                "scan_completed_at": outcome.scan_completed_at,
                "repository_name": outcome.repository_name,
                "repository_commit": outcome.repository_commit,
                "repository_branch": outcome.repository_branch,
                "repository_dirty": outcome.repository_dirty,
                "ai_models": outcome.ai_models,
            },
            "configuration": {
                "semgrep_rule_mode": outcome.semgrep_rule_mode,
                "semgrep_rules_sha256": outcome.semgrep_rules_sha256,
                "scan_exclusions": outcome.scan_exclusions,
                "max_target_bytes": outcome.max_target_bytes,
                "dependency_scan_enabled": outcome.dependency_scan_enabled,
                "secret_scan_enabled": outcome.secret_scan_enabled,
                "ai_triage_enabled": outcome.ai_triage_enabled,
            },
            "confirmed_issues": len(outcome.report.issues),
            "needs_review": outcome.disposition_count("NEEDS_REVIEW"),
            "non_runtime": outcome.disposition_count("NON_RUNTIME"),
            "false_positives": outcome.disposition_count("FALSE_POSITIVE"),
            "duplicates": outcome.disposition_count("DUPLICATE"),
            "secret_evidence_scope": secret_scope_counts,
            "fixed_files": outcome.fixed_files,
            "audit_branch": outcome.audit_branch,
            "pull_request_url": outcome.pull_request_url,
        },
        "report": safe_report.model_dump(),
    }


def write_json_report(outcome: Any, output_path: str | Path) -> None:
    Path(output_path).write_text(
        json.dumps(build_report_payload(outcome), indent=2), encoding="utf-8"
    )


def _rule_id(value: str, issue_name: str = "") -> str:
    if value.strip():
        return value.strip()
    slug = re.sub(r"[^a-z0-9]+", "-", issue_name.casefold()).strip("-")
    return f"aegisscan.{slug or 'manual-review'}"


def _cwe_tags(rule_id: str, text: str) -> list[str]:
    evidence = f"{rule_id} {text}".casefold()
    mappings = (
        ("CWE-918", ("ssrf", "server-side request forgery", "network-request")),
        ("CWE-367", ("toctou", "check-then-use", "filesystem-check")),
        ("CWE-89", ("sql injection", "sqli")),
        ("CWE-78", ("command injection", "shell injection")),
        ("CWE-95", ("code injection", "dynamic javascript", "express-code-injection")),
        ("CWE-502", ("unsafe deserialization", "unsafe-deserialization")),
        ("CWE-639", ("idor", "object authorization", "id-to-data-access")),
        ("CWE-22", ("path traversal", "zip slip")),
        ("CWE-79", ("cross-site scripting", "xss")),
        ("CWE-798", ("hardcoded", "hard-coded", "private key", "credential")),
    )
    return [cwe for cwe, terms in mappings if any(term in evidence for term in terms)]


def _location(file: str, line: int) -> list[dict[str, Any]]:
    if not file or line < 1:
        return []
    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": Path(file).as_posix()},
                "region": {"startLine": line},
            }
        }
    ]


def build_sarif_payload(outcome: Any) -> dict[str, Any]:
    """Build SARIF 2.1.0 containing confirmed and manual-review findings."""
    safe_report = redact_review_report(outcome.report)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    severity_levels = {
        "CRITICAL": ("error", "9.5"),
        "HIGH": ("error", "8.0"),
        "WARNING": ("warning", "5.0"),
        "INFO": ("note", "2.0"),
    }

    for issue in safe_report.issues:
        rule_id = _rule_id(issue.rule_id, issue.issue_name)
        level, security_severity = severity_levels[issue.severity]
        tags = ["security", *_cwe_tags(rule_id, issue.issue_name)]
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": issue.issue_name,
                "shortDescription": {"text": issue.issue_name},
                "fullDescription": {"text": issue.description},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": tags,
                    "security-severity": security_severity,
                },
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": issue.description},
            "locations": _location(issue.sink_file or issue.file, issue.sink_line or issue.line),
            "partialFingerprints": {"aegisscanFindingId": issue.finding_id or rule_id},
            "properties": {
                "status": "CONFIRMED",
                "confidence": issue.confidence,
                "codeRole": issue.code_role,
                "remediationType": issue.remediation_type,
                "remediationGuidance": issue.remediation_guidance,
                "sourceEvidence": issue.source_evidence,
                "sinkEvidence": issue.sink_evidence,
                "reachabilityEvidence": issue.reachability_evidence,
                "relatedWeaknesses": issue.related_weaknesses,
            },
        }
        results.append(result)

    for disposition in safe_report.dispositions:
        if disposition.status != "NEEDS_REVIEW":
            continue
        rule_id = _rule_id(disposition.rule_id, "Needs review")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": "AegisScan candidate requiring review",
                "shortDescription": {"text": "Security candidate requires manual review"},
                "defaultConfiguration": {"level": "warning"},
                "properties": {
                    "tags": ["security", *_cwe_tags(rule_id, disposition.message)],
                    "security-severity": "5.0",
                },
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": f"Needs review: {disposition.reason}"},
                "locations": _location(disposition.file, disposition.line),
                "partialFingerprints": {
                    "aegisscanFindingId": disposition.finding_id or rule_id
                },
                "properties": {
                    "status": disposition.status,
                    "confidence": disposition.confidence,
                    "codeRole": disposition.code_role,
                    "detectorMessage": disposition.message,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisScan",
                        "informationUri": "https://github.com/AlaeddinSrour/AegisScan",
                        "semanticVersion": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": "AegisScan/full-repository-audit"},
                "invocations": [
                    {
                        "executionSuccessful": not outcome.audit_degraded,
                        "properties": {
                            "auditDegraded": outcome.audit_degraded,
                            "aiTriageEnabled": outcome.ai_triage_enabled,
                            "semgrepRuleMode": outcome.semgrep_rule_mode,
                            "semgrepRulesSha256": outcome.semgrep_rules_sha256,
                            "runtimeScanGaps": outcome.runtime_scan_gap_count,
                            "scannerDiagnosticCount": outcome.scanner_diagnostic_count,
                            "detectorTelemetry": outcome.detector_telemetry,
                            "scanStartedAt": outcome.scan_started_at,
                            "scanCompletedAt": outcome.scan_completed_at,
                            "repositoryName": outcome.repository_name,
                            "repositoryCommit": outcome.repository_commit,
                            "repositoryBranch": outcome.repository_branch,
                            "repositoryDirty": outcome.repository_dirty,
                            "aiModels": outcome.ai_models,
                            "scanExclusions": outcome.scan_exclusions,
                            "maxTargetBytes": outcome.max_target_bytes,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def write_sarif_report(outcome: Any, output_path: str | Path) -> None:
    Path(output_path).write_text(
        json.dumps(build_sarif_payload(outcome), indent=2), encoding="utf-8"
    )
