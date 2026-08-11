"""Full-repository AegisScan orchestration for the desktop app and local CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Callable, Iterable

from google import genai

from .ast_context import build_ast_context
from .gemini_client import call_gemini_with_failover
from .github_ops import (
    apply_auto_fixes_with_paths,
    push_audit_fixes,
    validate_publishable_worktree,
)
from .models import FindingDisposition, ReviewIssue, ReviewReport
from .prompt import build_full_scan_prompt
from .scope import classify_code_role, is_runtime_role, load_ignore_patterns
from .semgrep_runner import DEFAULT_EXCLUDES, DEFAULT_MAX_TARGET_BYTES, run_semgrep_scan
from .supplemental_scanners import DetectorResult, scan_dependencies, scan_secrets

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 12
MAX_BATCH_SIZE = 15
DEFAULT_MAX_BATCH_CHARS = 100_000
SECRET_DETECTORS = {"betterleaks", "gitleaks"}
FINDING_START = re.compile(r"(?m)^Finding #\d+:\s*\nRule ID:")
FINDING_FILE = re.compile(r"(?m)^File:\s+(.+?):(\d+)\s*$")
FINDING_RULE = re.compile(r"(?m)^Rule ID:\s*(.+?)\s*$")
FINDING_MESSAGE = re.compile(r"(?m)^Message:\s*(.+?)\s*$")
FINDING_SNIPPET = re.compile(r"(?m)^Code Snippet:\s*(.*?)\s*$")


@dataclass
class SemgrepCandidate:
    finding_id: str
    rule_id: str
    message: str
    file: str
    line: int
    code_role: str
    raw_text: str

    @property
    def prompt_text(self) -> str:
        return (
            f"Candidate ID: {self.finding_id}\n"
            f"Deterministic code role: {self.code_role}\n"
            f"{self.raw_text}"
        )


@dataclass
class FindingBatch:
    findings: list[SemgrepCandidate]
    files: set[str]

    @property
    def text(self) -> str:
        return "\n\n".join(finding.prompt_text for finding in self.findings)


@dataclass
class ScanOutcome:
    report: ReviewReport
    raw_finding_count: int
    batch_count: int
    failed_batches: list[int] = field(default_factory=list)
    failed_batch_reasons: dict[int, str] = field(default_factory=dict)
    ai_attempted_batches: int = 0
    ai_successful_batches: int = 0
    dependency_finding_count: int = 0
    secret_finding_count: int = 0
    detector_errors: dict[str, list[str]] = field(default_factory=dict)
    dependency_scan_enabled: bool = True
    secret_scan_enabled: bool = True
    secret_scanner: str = ""
    fixed_files: list[str] = field(default_factory=list)
    audit_branch: str = ""
    pull_request_url: str = ""

    def disposition_count(self, status: str) -> int:
        return sum(item.status == status for item in self.report.dispositions)

    @property
    def ai_triage_degraded(self) -> bool:
        """Whether one or more batches could not be triaged by the AI provider."""
        return self.ai_successful_batches < self.ai_attempted_batches

    @property
    def all_ai_batches_failed(self) -> bool:
        """Whether AI triage was attempted but produced no successful batch."""
        return self.ai_attempted_batches > 0 and self.ai_successful_batches == 0

    @property
    def audit_degraded(self) -> bool:
        """Whether any enabled detector or AI triage stage was incomplete."""
        return self.ai_triage_degraded or any(self.detector_errors.values())

    @property
    def total_finding_count(self) -> int:
        return (
            self.raw_finding_count
            + self.dependency_finding_count
            + self.secret_finding_count
        )


def _pretriage_disposition(candidate: SemgrepCandidate) -> FindingDisposition | None:
    """Resolve candidates that must not depend on model judgment."""
    if not is_runtime_role(candidate.code_role):
        return FindingDisposition(
            finding_id=candidate.finding_id,
            status="NON_RUNTIME",
            reason=(
                "Deterministic scope classification marked this path as "
                f"{candidate.code_role.lower()}."
            ),
            file=candidate.file,
            line=candidate.line,
            rule_id=candidate.rule_id,
            message=candidate.message,
            code_role=candidate.code_role,
            confidence="HIGH",
        )
    if candidate.rule_id == "aegisscan.semgrep.runtime-scan-incomplete":
        return FindingDisposition(
            finding_id=candidate.finding_id,
            status="NEEDS_REVIEW",
            reason=(
                "Semgrep hit a file-specific resource limit, so this runtime path "
                "could not be completely analyzed."
            ),
            file=candidate.file,
            line=candidate.line,
            rule_id=candidate.rule_id,
            message=candidate.message,
            code_role=candidate.code_role,
            confidence="LOW",
        )
    return None


def split_semgrep_findings(formatted_findings: str) -> list[str]:
    """Split the stable text emitted by ``run_semgrep_scan`` into findings."""
    starts = list(FINDING_START.finditer(formatted_findings))
    findings: list[str] = []
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(formatted_findings)
        block = formatted_findings[match.start() : end].strip()
        if block:
            findings.append(block)
    return findings


def _deduplicate_semgrep_findings(findings: Iterable[str]) -> list[str]:
    """Remove exact duplicate Semgrep records while preserving scan order."""
    unique: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        finding_id = _candidate_from_text(finding).finding_id
        if finding_id in seen:
            continue
        seen.add(finding_id)
        unique.append(finding)
    return unique


def finding_file(finding: str) -> str:
    match = FINDING_FILE.search(finding)
    return match.group(1) if match else ""


def _candidate_from_text(
    finding: str,
    ignore_patterns: list[str] | None = None,
) -> SemgrepCandidate:
    file_match = FINDING_FILE.search(finding)
    rule_match = FINDING_RULE.search(finding)
    message_match = FINDING_MESSAGE.search(finding)
    snippet_match = FINDING_SNIPPET.search(finding)
    file = file_match.group(1) if file_match else ""
    line = int(file_match.group(2)) if file_match else 0
    rule_id = rule_match.group(1) if rule_match else "unknown-rule"
    message = message_match.group(1) if message_match else ""
    snippet = snippet_match.group(1) if snippet_match else ""
    fingerprint = hashlib.sha256(
        f"{rule_id}\0{file}\0{line}\0{message}\0{snippet}".encode(
            "utf-8", errors="replace"
        )
    ).hexdigest()[:12]
    return SemgrepCandidate(
        finding_id=f"SG-{fingerprint}",
        rule_id=rule_id,
        message=message,
        file=file,
        line=line,
        code_role=classify_code_role(file, ignore_patterns),
        raw_text=finding,
    )


def batch_findings(
    findings: Iterable[str],
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_batch_chars: int = DEFAULT_MAX_BATCH_CHARS,
    ignore_patterns: list[str] | None = None,
) -> list[FindingBatch]:
    """Pack findings by top-level directory while enforcing hard prompt bounds."""
    size = max(1, min(int(batch_size), MAX_BATCH_SIZE))
    char_limit = max(256, int(max_batch_chars))
    grouped: dict[str, list[SemgrepCandidate]] = defaultdict(list)
    for raw_finding in findings:
        finding = raw_finding
        if len(finding) > char_limit:
            suffix = "\n[File context truncated at the batch character limit.]"
            finding = finding[: char_limit - len(suffix)] + suffix
        candidate = _candidate_from_text(finding, ignore_patterns)
        path = candidate.file
        directory = path.split("/", 1)[0] if "/" in path else "."
        grouped[directory].append(candidate)

    batches: list[FindingBatch] = []
    current: list[SemgrepCandidate] = []
    current_chars = 0

    def flush() -> None:
        nonlocal current, current_chars
        if current:
            batches.append(
                FindingBatch(
                    findings=current,
                    files={item.file for item in current if item.file},
                )
            )
        current = []
        current_chars = 0

    for directory in sorted(grouped):
        for finding in grouped[directory]:
            finding_chars = len(finding.prompt_text)
            if current and (
                len(current) >= size
                or current_chars + finding_chars > char_limit
            ):
                flush()
            current.append(finding)
            current_chars += finding_chars
    flush()
    return batches


def _validated_issues(report: ReviewReport, repo_path: Path) -> list[ReviewIssue]:
    """Reject hallucinated paths and impossible line numbers before patching."""
    root = repo_path.resolve()
    valid: list[ReviewIssue] = []
    for issue in report.issues:
        candidate = (root / issue.file).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            logger.warning("Ignoring issue with path outside repository: %s", issue.file)
            continue
        if not candidate.is_file():
            logger.warning("Ignoring issue for missing file: %s", issue.file)
            continue
        try:
            with candidate.open("r", encoding="utf-8", errors="replace") as source:
                line_count = sum(1 for _ in source)
        except OSError:
            continue
        if issue.line < 1 or issue.line > max(1, line_count):
            logger.warning("Ignoring issue with invalid line %s:%s", issue.file, issue.line)
            continue
        valid.append(issue)
    return valid


def _requires_manual_remediation(issue: ReviewIssue) -> bool:
    evidence = " ".join(
        (issue.issue_name, issue.description, issue.original_code, issue.suggested_fix)
    ).casefold()
    secret_terms = (
        "private key",
        "hardcoded secret",
        "hard-coded secret",
        "api key",
        "jwt secret",
        "hmac secret",
        "credential",
        "password hash",
    )
    return any(term in evidence for term in secret_terms)


def _issue_family(issue: ReviewIssue) -> str:
    """Normalize names from different rules/models into a semantic family."""
    evidence = " ".join(
        (issue.issue_name, issue.description, issue.rule_id, issue.sink_evidence)
    ).casefold()
    families = (
        ("SQL_INJECTION", ("sql injection", "sqli", "sequelize")),
        ("XSS", ("cross-site scripting", "cross site scripting", "xss")),
        ("CODE_EXECUTION", ("remote code execution", "code execution", "eval")),
        ("COMMAND_INJECTION", ("command injection", "shell injection")),
        ("PATH_TRAVERSAL", ("path traversal", "zip slip")),
        ("SSRF", ("ssrf", "server-side request forgery")),
        ("SECRET", ("private key", "hardcoded secret", "hard-coded secret", "hmac key", "jwt secret", "credential")),
    )
    for family, terms in families:
        if any(term in evidence for term in terms):
            return family
    return re.sub(r"[^a-z0-9]+", "_", issue.issue_name.casefold()).strip("_")


def _valid_location(repo_path: Path, file: str, line: int) -> bool:
    root = repo_path.resolve()
    candidate = (root / file).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    if not candidate.is_file() or line < 1:
        return False
    try:
        with candidate.open("r", encoding="utf-8", errors="replace") as source:
            return line <= sum(1 for _ in source)
    except OSError:
        return False


def _source_line(repo_path: Path, issue: ReviewIssue) -> str:
    file = issue.sink_file or issue.file
    line = issue.sink_line or issue.line
    try:
        return (repo_path / file).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()[line - 1]
    except (OSError, IndexError):
        return ""


def _is_helper_location(repo_path: Path, issue: ReviewIssue) -> bool:
    """Identify verifier/assertion locations that cannot themselves be sinks."""
    line = _source_line(repo_path, issue).casefold()
    helper_markers = (
        "solveif(",
        "solve_if(",
        "assert ",
        "assert(",
        "expect(",
        "contains(",
        ".includes(",
        ".match(",
    )
    sink_markers = (
        ".query(",
        ".execute(",
        "eval(",
        "exec(",
        "spawn(",
        "innerhtml",
        "outerhtml",
        "document.write",
        "insertadjacenthtml",
        "dangerouslysetinnerhtml",
        ".replace(",
        "res.send(",
        "res.render(",
        "createhmac(",
        "private key-----",
    )
    return any(marker in line for marker in helper_markers) and not any(
        marker in line for marker in sink_markers
    )


def _reconcile_batch_report(
    report: ReviewReport,
    batch: FindingBatch,
    repo_path: Path,
) -> ReviewReport:
    """Create a complete, deterministic disposition ledger for one batch."""
    candidates = {candidate.finding_id: candidate for candidate in batch.findings}
    by_location: dict[tuple[str, int], list[SemgrepCandidate]] = defaultdict(list)
    for candidate in batch.findings:
        by_location[(candidate.file, candidate.line)].append(candidate)

    dispositions: dict[str, FindingDisposition] = {}
    for disposition in report.dispositions:
        candidate = candidates.get(disposition.finding_id)
        if candidate is None:
            continue
        status = disposition.status
        reason = disposition.reason
        if not is_runtime_role(candidate.code_role):
            status = "NON_RUNTIME"
            reason = (
                f"Deterministic scope classification marked this path as "
                f"{candidate.code_role.lower()}."
            )
        dispositions[candidate.finding_id] = disposition.model_copy(
            update={
                "status": status,
                "reason": reason,
                "file": candidate.file,
                "line": candidate.line,
                "rule_id": candidate.rule_id,
                "message": candidate.message,
                "code_role": candidate.code_role,
            }
        )

    confirmed_issues: list[ReviewIssue] = []
    confirmed_ids: set[str] = set()
    for issue in _validated_issues(report, repo_path):
        candidate = candidates.get(issue.finding_id)
        if candidate is None:
            matches = by_location.get((issue.file, issue.line), [])
            candidate = matches[0] if len(matches) == 1 else None
        if candidate is None:
            continue

        remediation_type = (
            "MANUAL_REQUIRED"
            if _requires_manual_remediation(issue)
            else issue.remediation_type
        )
        sink_file = issue.sink_file or issue.file
        sink_line = issue.sink_line or issue.line
        if not _valid_location(repo_path, sink_file, sink_line):
            dispositions[candidate.finding_id] = FindingDisposition(
                finding_id=candidate.finding_id,
                status="NEEDS_REVIEW",
                reason="The proposed canonical sink path or line could not be validated.",
                file=candidate.file,
                line=candidate.line,
                rule_id=candidate.rule_id,
                message=candidate.message,
                code_role=candidate.code_role,
                confidence="LOW",
            )
            continue
        sink_role = classify_code_role(sink_file, load_ignore_patterns(repo_path))
        enriched = issue.model_copy(
            update={
                "file": sink_file,
                "line": sink_line,
                "finding_id": candidate.finding_id,
                "rule_id": candidate.rule_id,
                "code_role": sink_role,
                "sink_file": sink_file,
                "sink_line": sink_line,
                "remediation_type": remediation_type,
            }
        )

        if not is_runtime_role(sink_role):
            dispositions[candidate.finding_id] = FindingDisposition(
                finding_id=candidate.finding_id,
                status="NON_RUNTIME",
                reason=(
                    f"Deterministic scope classification marked the canonical sink as "
                    f"{sink_role.lower()}."
                ),
                file=candidate.file,
                line=candidate.line,
                rule_id=candidate.rule_id,
                message=candidate.message,
                code_role=sink_role,
                confidence="HIGH",
            )
            continue

        evidence_complete = all(
            value.strip()
            for value in (
                enriched.source_evidence,
                enriched.sink_evidence,
                enriched.reachability_evidence,
            )
        )
        model_disposition = dispositions.get(candidate.finding_id)
        if not evidence_complete or enriched.confidence == "LOW":
            dispositions[candidate.finding_id] = FindingDisposition(
                finding_id=candidate.finding_id,
                status="NEEDS_REVIEW",
                reason=(
                    "The model proposed an issue without complete source, sink, "
                    "reachability, and confidence evidence."
                ),
                file=candidate.file,
                line=candidate.line,
                rule_id=candidate.rule_id,
                message=candidate.message,
                code_role=candidate.code_role,
                confidence=enriched.confidence,
            )
            continue
        if model_disposition and model_disposition.status in {
            "FALSE_POSITIVE",
            "NON_RUNTIME",
            "NEEDS_REVIEW",
        }:
            continue

        confirmed_issues.append(enriched)
        confirmed_ids.add(candidate.finding_id)
        dispositions[candidate.finding_id] = FindingDisposition(
            finding_id=candidate.finding_id,
            status="CONFIRMED",
            reason=(
                model_disposition.reason
                if model_disposition
                else "Source-to-sink evidence and repository location were validated."
            ),
            file=candidate.file,
            line=candidate.line,
            rule_id=candidate.rule_id,
            message=candidate.message,
            code_role=candidate.code_role,
            confidence=enriched.confidence,
        )

    complete_ledger: list[FindingDisposition] = []
    for candidate in batch.findings:
        disposition = dispositions.get(candidate.finding_id)
        if not is_runtime_role(candidate.code_role):
            disposition = FindingDisposition(
                finding_id=candidate.finding_id,
                status="NON_RUNTIME",
                reason=(
                    f"Deterministic scope classification marked this path as "
                    f"{candidate.code_role.lower()}."
                ),
                file=candidate.file,
                line=candidate.line,
                rule_id=candidate.rule_id,
                message=candidate.message,
                code_role=candidate.code_role,
                confidence="HIGH",
            )
        elif candidate.finding_id in confirmed_ids:
            disposition = dispositions[candidate.finding_id]
        elif disposition is None or disposition.status == "CONFIRMED":
            disposition = FindingDisposition(
                finding_id=candidate.finding_id,
                status="NEEDS_REVIEW",
                reason="The model did not return a complete, evidence-backed verdict for this candidate.",
                file=candidate.file,
                line=candidate.line,
                rule_id=candidate.rule_id,
                message=candidate.message,
                code_role=candidate.code_role,
                confidence="LOW",
            )
        complete_ledger.append(disposition)

    return ReviewReport(
        analysis_scratchpad=report.analysis_scratchpad,
        issues=confirmed_issues,
        dispositions=complete_ledger,
    )


def _merge_reports(
    reports: list[tuple[int, ReviewReport]], repo_path: Path
) -> ReviewReport:
    candidates: list[ReviewIssue] = []
    dispositions: list[FindingDisposition] = []
    scratchpads: list[str] = []
    for index, report in reports:
        scratchpads.append(f"Batch {index}: {report.analysis_scratchpad}")
        dispositions.extend(report.dispositions)
        candidates.extend(report.issues)

    # First consolidate every rule/model candidate that resolves to the same
    # canonical sink. Prefer stronger confidence and more complete evidence.
    by_sink: dict[tuple[str, str, int], ReviewIssue] = {}
    suppressed: dict[str, ReviewIssue] = {}

    def issue_rank(issue: ReviewIssue) -> tuple[int, int, int]:
        confidence = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[issue.confidence]
        # Semgrep findings that establish how a secret is used carry more
        # context than a pattern-only secret-scanner match at the same sink.
        contextual = int(
            not issue.rule_id.startswith(("betterleaks.", "gitleaks."))
        )
        evidence = sum(
            len(value.strip())
            for value in (
                issue.source_evidence,
                issue.sink_evidence,
                issue.reachability_evidence,
            )
        )
        return confidence, contextual, evidence

    for issue in candidates:
        key = (
            _issue_family(issue),
            issue.sink_file or issue.file,
            issue.sink_line or issue.line,
        )
        current = by_sink.get(key)
        if current is None:
            by_sink[key] = issue
        elif issue_rank(issue) > issue_rank(current):
            suppressed[current.finding_id] = issue
            by_sink[key] = issue
        else:
            suppressed[issue.finding_id] = current

    issues = list(by_sink.values())

    # A verifier can be reported separately from the real sink (for example a
    # challenge assertion checking an XSS payload). Suppress only the helper
    # when a nearby canonical sink in the same file and family is confirmed.
    for issue in list(issues):
        if not _is_helper_location(repo_path, issue):
            continue
        family = _issue_family(issue)
        replacement = next(
            (
                other
                for other in issues
                if other is not issue
                and _issue_family(other) == family
                and (other.sink_file or other.file) == (issue.sink_file or issue.file)
                and abs((other.sink_line or other.line) - (issue.sink_line or issue.line)) <= 30
                and not _is_helper_location(repo_path, other)
            ),
            None,
        )
        if replacement is not None:
            issues.remove(issue)
            suppressed[issue.finding_id] = replacement

    if suppressed:
        updated_dispositions: list[FindingDisposition] = []
        for disposition in dispositions:
            canonical = suppressed.get(disposition.finding_id)
            if canonical is not None and disposition.status == "CONFIRMED":
                disposition = disposition.model_copy(
                    update={
                        "status": "FALSE_POSITIVE",
                        "reason": (
                            "Consolidated into the canonical "
                            f"{_issue_family(canonical).lower()} sink at "
                            f"{canonical.sink_file or canonical.file}:"
                            f"{canonical.sink_line or canonical.line}."
                        ),
                    }
                )
            updated_dispositions.append(disposition)
        dispositions = updated_dispositions

    return ReviewReport(
        analysis_scratchpad="\n\n".join(scratchpads),
        issues=issues,
        dispositions=dispositions,
    )


def run_full_scan(
    repo_path: str,
    gemini_api_key: str,
    *,
    batch_size: int = DEFAULT_BATCH_SIZE,
    apply_fixes: bool = False,
    create_pull_request: bool = False,
    github_token: str = "",
    repository: str = "",
    base_branch: str = "",
    dependency_scan: bool = True,
    secret_scan: bool = True,
    exclude_patterns: Iterable[str] | None = None,
    max_target_bytes: int = DEFAULT_MAX_TARGET_BYTES,
    progress: Callable[[str], None] | None = None,
    client: genai.Client | None = None,
) -> ScanOutcome:
    """Scan an entire repository, triage bounded batches, and optionally open a PR."""
    notify = progress or logger.info
    audit_started = monotonic()
    root = Path(repo_path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository directory does not exist: {root}")
    if not gemini_api_key and client is None:
        raise ValueError("A Gemini API key is required.")
    if create_pull_request and not apply_fixes:
        raise ValueError("Pull-request creation requires auto-fix application.")
    if create_pull_request and (not github_token or not repository):
        raise ValueError("GitHub token and owner/repository are required to create a PR.")
    if create_pull_request:
        starting_branch = validate_publishable_worktree(str(root))
        notify(
            f"[SETUP] Git publishing preflight passed · clean branch {starting_branch}"
        )

    notify(f"[SETUP] Repository boundary validated: {root}")
    notify(
        f"[SETUP] Full-repository mode · batch limit {max(1, min(int(batch_size), MAX_BATCH_SIZE))} · "
        f"target limit {max(1, int(max_target_bytes)):,} bytes · "
        f"safe fixes {'enabled' if apply_fixes else 'disabled'} · "
        f"PR publishing {'enabled' if create_pull_request else 'disabled'}"
    )
    configured_excludes = tuple(
        pattern.strip()
        for pattern in (
            DEFAULT_EXCLUDES if exclude_patterns is None else exclude_patterns
        )
        if pattern.strip()
    )
    notify(
        "[SETUP] Semgrep exclusions: "
        + (", ".join(configured_excludes) if configured_excludes else "none")
    )
    notify("[DISCOVER] Starting Semgrep with bundled, security-audit, and Python rulesets")
    notify("[DISCOVER] Scope is the complete repository; pull-request diff filtering is disabled")
    semgrep_started = monotonic()
    formatted = run_semgrep_scan(
        str(root),
        changed_files_lines=None,
        exclude_patterns=configured_excludes,
        max_target_bytes=max_target_bytes,
    )
    raw_findings = split_semgrep_findings(formatted)
    findings = _deduplicate_semgrep_findings(raw_findings)
    finding_files = {path for item in findings if (path := finding_file(item))}
    notify(
        f"[DISCOVER] Semgrep completed in {monotonic() - semgrep_started:.1f}s · "
        f"{len(findings)} raw findings across {len(finding_files)} files"
    )
    if len(raw_findings) != len(findings):
        notify(
            f"[DISCOVER] Removed {len(raw_findings) - len(findings)} exact duplicate "
            "Semgrep finding(s)"
        )

    supplemental_results: list[DetectorResult] = []
    if dependency_scan:
        notify("[DEPENDENCIES] Starting OSV dependency vulnerability scan")
        dependency_started = monotonic()
        try:
            dependency_result = scan_dependencies(str(root))
        except Exception as exc:  # Keep an auditable degraded result on tool failure.
            dependency_result = DetectorResult(
                detector="osv",
                errors=[f"OSV-Scanner failed unexpectedly: {' '.join(str(exc).split())[:500]}"],
            )
        supplemental_results.append(dependency_result)
        notify(
            f"[DEPENDENCIES] Completed in {monotonic() - dependency_started:.1f}s · "
            f"{dependency_result.finding_count} vulnerable package findings"
        )
        for error in dependency_result.errors:
            notify(f"[WARNING] {error}")
    else:
        notify("[DEPENDENCIES] Dependency scanning disabled for this audit")

    if secret_scan:
        notify(
            "[SECRETS] Starting redacted current-tree and Git-history scan "
            "(Betterleaks preferred; Gitleaks fallback)"
        )
        secret_started = monotonic()
        try:
            secret_result = scan_secrets(
                str(root), max_target_bytes=max_target_bytes
            )
        except Exception as exc:  # Keep an auditable degraded result on tool failure.
            secret_result = DetectorResult(
                detector="betterleaks",
                errors=[
                    "Secret scanner failed unexpectedly: "
                    f"{' '.join(str(exc).split())[:500]}"
                ],
            )
        supplemental_results.append(secret_result)
        notify(
            f"[SECRETS] Completed in {monotonic() - secret_started:.1f}s · "
            f"{secret_result.finding_count} redacted secret findings"
        )
        for error in secret_result.errors:
            notify(f"[WARNING] {error}")
    else:
        notify("[SECRETS] Secret scanning disabled for this audit")

    ignore_patterns = load_ignore_patterns(root)
    if ignore_patterns:
        notify(f"[SCOPE] Loaded {len(ignore_patterns)} patterns from .aegisscanignore")
    batches = batch_findings(
        findings,
        batch_size=batch_size,
        ignore_patterns=ignore_patterns,
    )
    role_counts: dict[str, int] = defaultdict(int)
    for batch in batches:
        for candidate in batch.findings:
            role_counts[candidate.code_role] += 1
    role_summary = ", ".join(
        f"{count} {role.lower()}" for role, count in sorted(role_counts.items())
    )
    if role_summary:
        notify(f"[SCOPE] Deterministic path classification: {role_summary}")
    notify(
        f"[PLAN] Packed {len(findings)} findings into {len(batches)} context-bounded batches "
        f"(maximum {max(1, min(int(batch_size), MAX_BATCH_SIZE))} findings each)"
    )
    gemini_client = client or genai.Client(api_key=gemini_api_key)
    reports: list[tuple[int, ReviewReport]] = []
    failed_batches: list[int] = []
    failed_batch_reasons: dict[int, str] = {}
    failed_dispositions: list[FindingDisposition] = []
    attempted_ai_batches = 0
    successful_ai_batches = 0

    for index, batch in enumerate(batches, start=1):
        batch_started = monotonic()
        files = sorted(batch.files)
        file_summary = ", ".join(files[:4])
        if len(files) > 4:
            file_summary += f", +{len(files) - 4} more"
        notify(
            f"[BATCH {index}/{len(batches)}] Preparing {len(batch.findings)} findings "
            f"across {len(files)} files"
        )
        if file_summary:
            notify(f"[CONTEXT] Batch {index}/{len(batches)} files: {file_summary}")
        deterministic_dispositions: list[FindingDisposition] = []
        triage_findings: list[SemgrepCandidate] = []
        for candidate in batch.findings:
            disposition = _pretriage_disposition(candidate)
            if disposition is None:
                triage_findings.append(candidate)
            else:
                deterministic_dispositions.append(disposition)
        if not triage_findings:
            deterministic = ReviewReport(
                analysis_scratchpad=(
                    "Deterministic scope and scan-completeness policy resolved this "
                    "batch without sending source context to the AI provider."
                ),
                issues=[],
                dispositions=deterministic_dispositions,
            )
            reports.append((index, deterministic))
            notify(
                f"[SCOPE] Batch {index}/{len(batches)} contains only deterministic "
                "non-runtime or incomplete-scan evidence; AI triage was skipped"
            )
            notify(
                f"[BATCH {index}/{len(batches)}] Complete in "
                f"{monotonic() - batch_started:.1f}s"
            )
            continue
        triage_batch = FindingBatch(
            findings=triage_findings,
            files={item.file for item in triage_findings if item.file},
        )
        ast_started = monotonic()
        structural_context = build_ast_context(root, triage_batch.files)
        python_files = sum(
            Path(path).suffix.casefold() == ".py" for path in triage_batch.files
        )
        notify(
            f"[CONTEXT] Local AST map generated for {python_files} Python files in "
            f"{monotonic() - ast_started:.1f}s · {len(structural_context):,} context characters"
        )
        prompt = build_full_scan_prompt(
            triage_batch.text,
            structural_context,
            index,
            len(batches),
        )
        notify(
            f"[AI] Batch {index}/{len(batches)} prompt assembled · {len(prompt):,} characters · "
            "ReviewReport schema enforcement active"
        )
        attempted_ai_batches += 1
        try:
            report = call_gemini_with_failover(gemini_client, prompt, progress=notify)
        except RuntimeError as exc:
            logger.error("Batch %s failed: %s", index, exc)
            failed_batches.append(index)
            failure_reason = " ".join(str(exc).split())[:500] or "Unknown AI provider error"
            failed_batch_reasons[index] = failure_reason
            failed_dispositions.extend(
                FindingDisposition(
                    finding_id=candidate.finding_id,
                    status=(
                        "NEEDS_REVIEW"
                        if is_runtime_role(candidate.code_role)
                        else "NON_RUNTIME"
                    ),
                    reason=(
                        "AI triage failed; this candidate requires manual review."
                        if is_runtime_role(candidate.code_role)
                        else f"Deterministic scope classification marked this path as {candidate.code_role.lower()}."
                    ),
                    file=candidate.file,
                    line=candidate.line,
                    rule_id=candidate.rule_id,
                    message=candidate.message,
                    code_role=candidate.code_role,
                    confidence="LOW",
                )
                for candidate in triage_batch.findings
            )
            failed_dispositions.extend(deterministic_dispositions)
            notify(
                f"[ERROR] Batch {index}/{len(batches)} failed after model failover: "
                f"{failure_reason}"
            )
            continue
        successful_ai_batches += 1
        reconciled = _reconcile_batch_report(report, triage_batch, root)
        reconciled.dispositions.extend(deterministic_dispositions)
        confirmed_count = len(reconciled.issues)
        review_count = sum(
            disposition.status == "NEEDS_REVIEW"
            for disposition in reconciled.dispositions
        )
        non_runtime_count = sum(
            disposition.status == "NON_RUNTIME"
            for disposition in reconciled.dispositions
        )
        notify(
            f"[VALIDATE] Batch {index}/{len(batches)} · {confirmed_count} confirmed · "
            f"{review_count} needs review · {non_runtime_count} non-runtime"
        )
        reports.append((index, reconciled))
        notify(
            f"[BATCH {index}/{len(batches)}] Complete in {monotonic() - batch_started:.1f}s"
        )

    if attempted_ai_batches and not successful_ai_batches:
        notify(
            "[WARNING] AI triage is unavailable. The audit will finish in degraded "
            "mode and every untriaged runtime candidate will remain in Needs review."
        )

    merged = _merge_reports(reports, root)
    merged.dispositions.extend(failed_dispositions)
    base_scratchpad = merged.analysis_scratchpad.strip()
    supplemental_summaries: list[str] = []
    detector_errors: dict[str, list[str]] = {}
    for detector_result in supplemental_results:
        supplemental_summaries.append(
            f"{detector_result.detector}: {detector_result.finding_count} finding(s), "
            f"{len(detector_result.errors)} error(s)."
        )
        if detector_result.errors:
            detector_errors[detector_result.detector] = detector_result.errors

    accepted_before_merge = len(merged.issues) + sum(
        len(result.issues) for result in supplemental_results
    )
    if supplemental_results:
        combined_reports: list[tuple[int, ReviewReport]] = [(0, merged)]
        combined_reports.extend(
            (
                index,
                ReviewReport(
                    analysis_scratchpad="",
                    issues=result.issues,
                    dispositions=result.dispositions,
                ),
            )
            for index, result in enumerate(supplemental_results, start=1)
        )
        merged = _merge_reports(combined_reports, root)

    scratchpad_parts = [part for part in (base_scratchpad, *supplemental_summaries) if part]
    if not scratchpad_parts:
        scratchpad_parts.append("All enabled detectors completed without findings.")
    merged.analysis_scratchpad = "\n\n".join(scratchpad_parts)
    duplicate_count = accepted_before_merge - len(merged.issues)
    notify(
        f"[MERGE] Combined {len(reports)} successful batches · {len(merged.issues)} confirmed issues · "
        f"{sum(item.status == 'NEEDS_REVIEW' for item in merged.dispositions)} needs review · "
        f"{sum(item.status == 'NON_RUNTIME' for item in merged.dispositions)} non-runtime · "
        f"{duplicate_count} duplicates removed · {len(failed_batches)} failed batches"
    )
    outcome = ScanOutcome(
        report=merged,
        raw_finding_count=len(findings),
        batch_count=len(batches),
        failed_batches=failed_batches,
        failed_batch_reasons=failed_batch_reasons,
        ai_attempted_batches=attempted_ai_batches,
        ai_successful_batches=successful_ai_batches,
        dependency_finding_count=next(
            (
                result.finding_count
                for result in supplemental_results
                if result.detector == "osv"
            ),
            0,
        ),
        secret_finding_count=next(
            (
                result.finding_count
                for result in supplemental_results
                if result.detector in SECRET_DETECTORS
            ),
            0,
        ),
        detector_errors=detector_errors,
        dependency_scan_enabled=dependency_scan,
        secret_scan_enabled=secret_scan,
        secret_scanner=next(
            (
                result.detector
                for result in supplemental_results
                if result.detector in SECRET_DETECTORS
            ),
            "",
        ),
    )
    if apply_fixes and merged.issues:
        remediation_started = monotonic()
        notify(
            f"[REMEDIATE] Evaluating {len(merged.issues)} suggested fixes with deterministic safety policy"
        )
        outcome.fixed_files = apply_auto_fixes_with_paths(merged.issues, str(root))
        notify(
            f"[REMEDIATE] Safety cleansing and fuzzy patch application completed in "
            f"{monotonic() - remediation_started:.1f}s · {len(outcome.fixed_files)} files changed"
        )
        if outcome.fixed_files:
            changed_summary = ", ".join(outcome.fixed_files[:6])
            if len(outcome.fixed_files) > 6:
                changed_summary += f", +{len(outcome.fixed_files) - 6} more"
            notify(f"[REMEDIATE] Changed files: {changed_summary}")
    elif apply_fixes:
        notify("[REMEDIATE] No confirmed issues; patch application was skipped")
    else:
        notify("[REMEDIATE] Safe-fix application is disabled; repository files were not modified")

    if create_pull_request and outcome.fixed_files:
        notify(
            f"[PUBLISH] Creating a dedicated audit branch and pull request for "
            f"{len(outcome.fixed_files)} changed files"
        )
        result = push_audit_fixes(
            github_token=github_token,
            repository=repository,
            repo_path=str(root),
            changed_files=outcome.fixed_files,
            base_branch=base_branch,
            issues=merged.issues,
        )
        outcome.audit_branch = result.branch
        outcome.pull_request_url = result.pull_request_url
        notify(f"[PUBLISH] Branch created: {result.branch}")
        notify(f"[PUBLISH] Pull request opened: {result.pull_request_url}")
    elif create_pull_request:
        notify("[PUBLISH] No files changed; pull-request creation was skipped")
    else:
        notify("[PUBLISH] GitHub pull-request publishing is disabled")

    notify(
        f"[COMPLETE] Audit finished"
        f"{' in degraded mode' if outcome.audit_degraded else ''} "
        f"in {monotonic() - audit_started:.1f}s · "
        f"{outcome.total_finding_count} detector findings · "
        f"{len(merged.issues)} confirmed · {outcome.disposition_count('NEEDS_REVIEW')} needs review · "
        f"{outcome.disposition_count('NON_RUNTIME')} non-runtime · {len(outcome.fixed_files)} changed files"
    )

    return outcome


def _write_report(outcome: ScanOutcome, output_path: str) -> None:
    payload = {
        "summary": {
            "raw_semgrep_findings": outcome.raw_finding_count,
            "dependency_findings": outcome.dependency_finding_count,
            "secret_findings": outcome.secret_finding_count,
            "total_detector_findings": outcome.total_finding_count,
            "llm_batches": outcome.batch_count,
            "failed_batches": outcome.failed_batches,
            "failed_batch_reasons": outcome.failed_batch_reasons,
            "ai_attempted_batches": outcome.ai_attempted_batches,
            "ai_successful_batches": outcome.ai_successful_batches,
            "ai_triage_degraded": outcome.ai_triage_degraded,
            "audit_degraded": outcome.audit_degraded,
            "detector_errors": outcome.detector_errors,
            "dependency_scan_enabled": outcome.dependency_scan_enabled,
            "secret_scan_enabled": outcome.secret_scan_enabled,
            "secret_scanner": outcome.secret_scanner,
            "confirmed_issues": len(outcome.report.issues),
            "needs_review": outcome.disposition_count("NEEDS_REVIEW"),
            "non_runtime": outcome.disposition_count("NON_RUNTIME"),
            "false_positives": outcome.disposition_count("FALSE_POSITIVE"),
            "fixed_files": outcome.fixed_files,
            "audit_branch": outcome.audit_branch,
            "pull_request_url": outcome.pull_request_url,
        },
        "report": outcome.report.model_dump(),
    }
    Path(output_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run an AegisScan audit against an entire local repository."
    )
    parser.add_argument("--repo", default=os.getcwd(), help="Repository directory")
    parser.add_argument("--api-key", default=os.getenv("GEMINI_API_KEY", ""))
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument(
        "--max-target-bytes", type=int, default=DEFAULT_MAX_TARGET_BYTES
    )
    parser.add_argument(
        "--exclude",
        action="append",
        dest="exclude_patterns",
        help="Semgrep exclusion pattern; repeat for multiple patterns",
    )
    parser.add_argument("--no-dependency-scan", action="store_true")
    parser.add_argument("--no-secret-scan", action="store_true")
    parser.add_argument("--apply-fixes", action="store_true")
    parser.add_argument("--create-pull-request", action="store_true")
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN", ""))
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--base-branch", default="")
    parser.add_argument("--report", default="aegisscan-report.json")
    args = parser.parse_args()

    try:
        outcome = run_full_scan(
            args.repo,
            args.api_key,
            batch_size=args.batch_size,
            dependency_scan=not args.no_dependency_scan,
            secret_scan=not args.no_secret_scan,
            exclude_patterns=args.exclude_patterns,
            max_target_bytes=args.max_target_bytes,
            apply_fixes=args.apply_fixes,
            create_pull_request=args.create_pull_request,
            github_token=args.github_token,
            repository=args.repository,
            base_branch=args.base_branch,
        )
        _write_report(outcome, args.report)
        logger.info("Wrote audit report to %s", args.report)
        if outcome.audit_degraded:
            logger.error(
                "Audit completed in degraded mode; inspect detector_errors, Needs review, "
                "and failed_batch_reasons in %s",
                args.report,
            )
            sys.exit(2)
    except (RuntimeError, ValueError, OSError) as exc:
        logger.error("Full-repository audit failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
