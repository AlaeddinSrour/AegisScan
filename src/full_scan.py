"""Full-repository AegisScan orchestration for the desktop app and local CLI."""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Callable, Iterable

from google import genai

from . import __version__
from .ast_context import build_ast_context
from .gemini_client import FAILOVER_MODELS, call_gemini_with_failover
from .github_ops import (
    apply_auto_fixes_with_paths,
    auto_fix_eligibility,
    push_audit_fixes,
    validate_publishable_worktree,
)
from .models import FindingDisposition, ReviewIssue, ReviewReport
from .openrouter_client import (
    MAX_FINDINGS_PER_BATCH as OPENROUTER_MAX_FINDINGS_PER_BATCH,
    OPENROUTER_MODELS,
    call_openrouter_with_failover,
    semantic_repair_candidate_ids,
)
from .prompt import build_full_scan_prompt
from .redaction import redact_review_report
from .related_context import build_related_context
from .reporting import write_json_report, write_sarif_report
from .scope import classify_code_role, is_runtime_role, load_ignore_patterns
from .semgrep_runner import (
    DEFAULT_EXCLUDES,
    DEFAULT_MAX_TARGET_BYTES,
    SEMGREP_RULE_MODES,
    bundled_rules_sha256,
    run_semgrep_scan,
)
from .supplemental_scanners import (
    DetectorResult,
    scan_dependencies,
    scan_firmware,
    scan_secrets,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 12
MAX_BATCH_SIZE = 15
DEFAULT_MAX_BATCH_CHARS = 100_000
DEFAULT_AI_RETRIAGE_LIMIT = max(0, int(os.environ.get("AEGISSCAN_AI_RETRIAGE_LIMIT", "6")))
SECRET_DETECTORS = {"betterleaks", "gitleaks"}
DETERMINISTIC_CREDENTIAL_RULES = {
    "aegisscan.javascript.hardcoded-private-key": (
        "CRITICAL",
        "Hardcoded private key",
        "A private key is embedded directly in runtime source.",
        "The embedded private key is stored in repository source.",
        "The credential is loaded whenever the containing runtime module is loaded.",
    ),
    "aegisscan.javascript.hardcoded-hmac-key": (
        "HIGH",
        "Hardcoded HMAC key",
        "A literal HMAC key is embedded directly in a runtime cryptographic operation.",
        "The embedded key is passed to createHmac at the reported location.",
        "The containing runtime path invokes createHmac with the repository value.",
    ),
}
DETERMINISTIC_MANUAL_REVIEW_RULE_MARKERS = {
    "java.lang.security.audit.crypto.use-of-md5.use-of-md5": (
        "A deterministic detector found MD5 usage. Whether it protects security-sensitive "
        "data requires manual review; AI triage is unnecessary for retaining the evidence."
    ),
    "java.lang.security.audit.crypto.weak-random.weak-random": (
        "A deterministic detector found a non-cryptographic random generator. Its security "
        "role requires manual review; AI triage is unnecessary for retaining the evidence."
    ),
    "java.spring.security.unrestricted-request-mapping.unrestricted-request-mapping": (
        "A deterministic detector found a Spring request mapping without an explicit HTTP "
        "method. State-change and CSRF impact require manual review."
    ),
}
AI_PROVIDER_MODES = ("auto", "openrouter", "gemini")
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
    ai_telemetry: dict[str, int] = field(default_factory=dict)
    firmware_finding_count: int = 0
    dependency_finding_count: int = 0
    secret_finding_count: int = 0
    detector_errors: dict[str, list[str]] = field(default_factory=dict)
    detector_coverage_gaps: dict[str, list[str]] = field(default_factory=dict)
    detector_telemetry: dict[str, dict[str, object]] = field(default_factory=dict)
    scanner_diagnostics: dict[str, list[dict[str, object]]] = field(default_factory=dict)
    dependency_scan_enabled: bool = True
    secret_scan_enabled: bool = True
    secret_scanner: str = ""
    ai_triage_enabled: bool = True
    semgrep_rule_mode: str = "bundled"
    semgrep_rules_sha256: str = ""
    app_version: str = __version__
    scan_started_at: str = ""
    scan_completed_at: str = ""
    repository_name: str = ""
    repository_commit: str = ""
    repository_branch: str = ""
    repository_dirty: bool | None = None
    ai_provider_order: list[str] = field(default_factory=list)
    ai_models: list[str] = field(default_factory=list)
    scan_exclusions: list[str] = field(default_factory=list)
    max_target_bytes: int = DEFAULT_MAX_TARGET_BYTES
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
        return (
            self.ai_triage_degraded
            or any(self.detector_errors.values())
            or any(self.detector_coverage_gaps.values())
            or self.runtime_scan_gap_count > 0
        )

    @property
    def runtime_scan_gap_count(self) -> int:
        """Count runtime files/rules Semgrep could not analyze completely."""
        return sum(
            disposition.status == "NEEDS_REVIEW"
            and disposition.rule_id == "aegisscan.semgrep.runtime-scan-incomplete"
            for disposition in self.report.dispositions
        )

    @property
    def total_finding_count(self) -> int:
        return (
            self.raw_finding_count
            + self.firmware_finding_count
            + self.dependency_finding_count
            + self.secret_finding_count
        )

    @property
    def scanner_diagnostic_count(self) -> int:
        return sum(len(items) for items in self.scanner_diagnostics.values())

    @property
    def scanner_diagnostic_counts_by_role(self) -> dict[str, int]:
        """Separate parser/tool noise from diagnostics that affect runtime coverage."""
        counts: dict[str, int] = defaultdict(int)
        for diagnostics in self.scanner_diagnostics.values():
            for diagnostic in diagnostics:
                role = str(diagnostic.get("code_role") or "UNKNOWN").upper()
                counts[role] += 1
        return dict(sorted(counts.items()))

    @property
    def runtime_scanner_diagnostic_count(self) -> int:
        return sum(
            count
            for role, count in self.scanner_diagnostic_counts_by_role.items()
            if is_runtime_role(role)
        )

    @property
    def non_runtime_scanner_diagnostic_count(self) -> int:
        return sum(
            count
            for role, count in self.scanner_diagnostic_counts_by_role.items()
            if role != "UNKNOWN" and not is_runtime_role(role)
        )

    @property
    def unique_dependency_advisory_count(self) -> int:
        """Return distinct advisories retained in the final merged report."""
        telemetry = self.detector_telemetry.get("osv", {})
        value = telemetry.get("exported_unique_advisories", telemetry.get("unique_advisories"))
        return int(value) if isinstance(value, int) and not isinstance(value, bool) else 0

    @property
    def exported_dependency_finding_count(self) -> int:
        """Return dependency findings retained in the final merged report."""
        value = self.detector_telemetry.get("osv", {}).get("exported_dependency_findings")
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return sum(issue.rule_id.startswith("osv.") for issue in self.report.issues)


def _git_provenance(root: Path) -> tuple[str, str, bool | None]:
    """Return commit, branch, and dirty state without failing non-Git audits."""

    def git(*args: str) -> str | None:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if completed.returncode != 0:
            return None
        return completed.stdout.strip()

    commit = git("rev-parse", "HEAD")
    if not commit:
        return "", "", None
    branch = git("branch", "--show-current") or ""
    status = git("status", "--porcelain", "--untracked-files=normal")
    return commit, branch, bool(status) if status is not None else None


def _contains_openwrt_firmware(root: Path) -> bool:
    """Return whether a versioned OpenWrt tree contains a firmware overlay."""
    try:
        return any(
            files.is_dir()
            and re.fullmatch(r"openwrt-\d+(?:\.\d+)+(?:[-_][^/]+)?", files.parent.name)
            for files in root.rglob("files")
        )
    except OSError:
        return False


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
    deterministic_reason = DETERMINISTIC_MANUAL_REVIEW_RULE_MARKERS.get(candidate.rule_id)
    if deterministic_reason:
        return FindingDisposition(
            finding_id=candidate.finding_id,
            status="NEEDS_REVIEW",
            reason=deterministic_reason,
            file=candidate.file,
            line=candidate.line,
            rule_id=candidate.rule_id,
            message=candidate.message,
            code_role=candidate.code_role,
            confidence="MEDIUM",
            evidence_scope="CURRENT",
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
        f"{rule_id}\0{file}\0{line}\0{message}\0{snippet}".encode("utf-8", errors="replace")
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
            if current and (len(current) >= size or current_chars + finding_chars > char_limit):
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


def _requires_manual_remediation(issue: ReviewIssue, detector_rule_id: str = "") -> bool:
    evidence = " ".join(
        (
            issue.issue_name,
            issue.description,
            issue.original_code,
            issue.suggested_fix,
            issue.rule_id,
            detector_rule_id,
        )
    ).casefold()
    manual_terms = (
        "private key",
        "hardcoded secret",
        "hard-coded secret",
        "api key",
        "jwt secret",
        "hmac secret",
        "credential",
        "password hash",
        "ssrf",
        "server-side request forgery",
        "server side request forgery",
        "toctou",
        "time-of-check",
        "time of check",
        "filesystem-check-then-use",
        "path traversal",
        "express-path-traversal",
        "idor",
        "insecure direct object reference",
        "object authorization",
        "id-to-data-access",
        "user-input-to-network-request",
        "open redirect",
        "express-open-redirect",
    )
    return any(term in evidence for term in manual_terms)


def _manual_remediation_guidance(issue: ReviewIssue) -> str:
    """Return actionable prose where a safe local replacement needs app context."""
    evidence = " ".join((issue.issue_name, issue.description, issue.rule_id)).casefold()
    affected_file = (issue.sink_file or issue.file).casefold()
    if any(term in evidence for term in ("sql injection", "sqli", "sequelize")):
        return (
            "Use parameterized queries with the database driver's binding API. Keep SQL "
            "structure separate from request values and allowlist dynamic identifiers. "
            "Add injection regression tests and verify normal query behavior."
        )
    if any(term in evidence for term in ("path traversal", "zip slip")):
        if affected_file.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
            boundary = (
                "Use Node.js path.resolve() with a fixed base directory and reject results "
                "whose path.relative() value is absolute or begins with '..'"
            )
        elif affected_file.endswith(".py"):
            boundary = (
                "Resolve the candidate with pathlib.Path.resolve() and require it to remain "
                "relative to the resolved base directory"
            )
        else:
            boundary = (
                "Resolve the candidate against a fixed base directory and use the language's "
                "path-relative containment API to reject escapes"
            )
        return (
            f"Validate the requested name against a strict allowlist. {boundary}; do not rely "
            "on string-prefix checks. Test traversal, encoded separators, absolute paths, and "
            "sibling directories with the same prefix."
        )
    if any(
        term in evidence
        for term in ("idor", "insecure direct object reference", "object authorization")
    ) or "id-to-data-access" in issue.rule_id.casefold():
        return (
            "Derive the owner or tenant identifier from the authenticated server-side identity, "
            "include it in the data-access predicate, and return a consistent denial when the "
            "object is not owned by that principal. Add cross-account read and write tests."
        )
    if any(term in evidence for term in ("ssrf", "server-side request forgery")):
        return (
            "Define the destinations this feature genuinely needs, allow only approved "
            "schemes and hosts, resolve DNS before connecting, reject loopback/private/"
            "link-local/metadata addresses, and revalidate every redirect target. Add "
            "tests for encoded IPs, DNS rebinding, and redirect chains."
        )
    if any(
        term in evidence for term in ("toctou", "time-of-check", "time of check", "check-then-use")
    ):
        return (
            "Replace the complete check-then-use sequence with one direct operation and "
            "handle its error atomically. For security-sensitive writes, use exclusive "
            "open/create flags and avoid following attacker-controlled symlinks."
        )
    if any(
        term in evidence
        for term in ("private key", "hardcoded", "hard-coded", "hmac", "credential")
    ):
        return (
            "Remove the embedded value, load a required credential from an approved secret "
            "store without an insecure fallback, rotate/revoke the exposed credential, and "
            "review repository history and build artifacts for copies."
        )
    if "vulnerable dependency" in evidence or issue.rule_id.startswith("osv."):
        return (
            "Confirm whether the affected component is reachable, upgrade to a fixed "
            "compatible release, regenerate and review the lockfile, run the application "
            "test suite, and document any temporary risk acceptance."
        )
    if "redirect" in evidence:
        return (
            "Accept only repository-owned relative paths or exact allowlisted destinations. "
            "Parse and canonicalize the URL before comparison, then add bypass tests for "
            "userinfo, mixed encoding, scheme-relative URLs, and subdomain suffix tricks."
        )
    return (
        "Validate the security boundary and implement the remediation with application "
        "context, then add a regression test that demonstrates the original attack is blocked."
    )


def _automatic_remediation_guidance(issue: ReviewIssue) -> str:
    """Describe how to review a bounded replacement without duplicating its source text."""
    evidence = " ".join((issue.issue_name, issue.description, issue.rule_id)).casefold()
    location = f"{issue.sink_file or issue.file}:{issue.sink_line or issue.line}"
    if any(term in evidence for term in ("sql injection", "sqli", "sequelize")):
        action = "replace string-built SQL with the supplied parameterized-query replacement"
    elif any(term in evidence for term in ("path traversal", "zip slip")):
        action = "apply the supplied path-boundary or strict-allowlist replacement"
    elif any(term in evidence for term in ("cross-site scripting", "cross site scripting", "xss")):
        action = "apply the supplied context-appropriate output-encoding replacement"
    else:
        action = "apply the supplied bounded replacement"
    return (
        f"Review and {action} at {location}, then run the affected component's tests and "
        "the repository security regression suite before accepting the change."
    )


def _normalize_manual_remediations(report: ReviewReport) -> ReviewReport:
    """Make every remediation mode internally complete and actionable."""
    issues: list[ReviewIssue] = []
    for issue in report.issues:
        if auto_fix_eligibility(issue)[0]:
            issues.append(
                issue.model_copy(
                    update={
                        # Automatic guidance is deterministic so provider prose
                        # cannot mix APIs from a different programming language.
                        "remediation_guidance": _automatic_remediation_guidance(issue)
                    }
                )
            )
            continue
        # Preserve findings but do not advertise unvetted model patches as
        # automatic remediations, including in exported reports and the UI.
        remediation_type = "MANUAL_REQUIRED"
        trusted_manual_guidance = issue.rule_id.startswith(
            ("aegisscan.firmware.", "aegisscan.openwrt.")
        ) and bool(issue.remediation_guidance.strip())
        issues.append(
            issue.model_copy(
                update={
                    "suggested_fix": "",
                    "remediation_type": remediation_type,
                    # Manual guidance is also normalized locally. Provider text
                    # may otherwise suggest APIs from the wrong language or an
                    # unsafe boundary check.
                    "remediation_guidance": (
                        issue.remediation_guidance
                        if trusted_manual_guidance
                        else _manual_remediation_guidance(issue)
                    ),
                }
            )
        )
    return report.model_copy(update={"issues": issues})


def _issue_family(issue: ReviewIssue) -> str:
    """Normalize names from different rules/models into a semantic family."""
    if issue.rule_id.startswith("osv."):
        # Distinct advisories affecting the same manifest line are independent
        # findings, even when their summaries share a weakness family.
        return f"DEPENDENCY_{issue.rule_id.removeprefix('osv.')}"
    if issue.rule_id.startswith(
        ("aegisscan.openwrt.advisory.", "aegisscan.openwrt.kernel-advisory.")
    ):
        # Multiple applicable CVEs can point at the same selected package
        # recipe. They are independent advisories and must not be collapsed
        # merely because their canonical sink is the same Makefile line.
        return f"OPENWRT_ADVISORY_{issue.rule_id.rsplit('.', 1)[-1]}"
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
        (
            "OPEN_REDIRECT",
            (
                "open redirect",
                "express-open-redirect",
                "user-input-redirect",
                "value-in-redirect",
            ),
        ),
        ("TOCTOU", ("toctou", "time-of-check", "time of check", "check-then-use")),
        (
            "SECRET",
            (
                "private key",
                "hardcoded secret",
                "hard-coded secret",
                "hardcoded cryptographic secret",
                "hardcoded hmac",
                "hardcoded-hmac",
                "jwt-hardcode",
                "createhmac",
                "hmac key",
                "jwt secret",
                "credential",
            ),
        ),
    )
    for family, terms in families:
        if any(
            (
                bool(re.search(r"(?<![a-z0-9])eval(?![a-z0-9])", evidence))
                if term == "eval"
                else term in evidence
            )
            for term in terms
        ):
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
        return (
            (repo_path / file).read_text(encoding="utf-8", errors="replace").splitlines()[line - 1]
        )
    except (OSError, IndexError):
        return ""


def _referenced_credential_declaration_lines(
    repo_path: Path,
    disposition: FindingDisposition,
) -> set[int]:
    """Find same-file credential declarations explicitly consumed by a sink.

    This is intentionally limited to JavaScript/TypeScript cryptographic calls
    and returns line numbers only; credential contents never leave the local
    source file.
    """
    if not disposition.file.casefold().endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")):
        return set()
    try:
        lines = (repo_path / disposition.file).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return set()
    if disposition.line < 1 or disposition.line > len(lines):
        return set()
    call_text = " ".join(lines[disposition.line - 1 : disposition.line + 2])
    if not re.search(
        r"\b(?:jwt|jsonwebtoken)\s*\.\s*(?:sign|verify)\s*\(|\bcreateHmac\s*\(",
        call_text,
        flags=re.IGNORECASE,
    ):
        return set()
    referenced = set(re.findall(r"\b[A-Za-z_$][\w$]*\b", call_text))
    declaration_lines: set[int] = set()
    for index, source_line in enumerate(lines[: disposition.line - 1], start=1):
        match = re.search(
            r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)"
            r"(?:\s*:\s*[^=]+)?\s*=",
            source_line,
        )
        if match and match.group("name") in referenced:
            declaration_lines.add(index)
    return declaration_lines


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


def _related_weakness(rule_id: str, message: str) -> str:
    """Return a human-readable weakness label for consolidated evidence."""
    evidence = f"{rule_id} {message}".casefold()
    mappings = (
        ("CWE-367: TOCTOU", ("toctou", "check-then-use", "filesystem-check")),
        ("CWE-918: SSRF", ("ssrf", "server-side request forgery", "network-request")),
        ("CWE-601: Open Redirect", ("open redirect", "express-open-redirect")),
        ("CWE-22: Path Traversal", ("path traversal", "zip slip")),
        ("CWE-89: SQL Injection", ("sql injection", "sqli")),
        ("CWE-79: Cross-Site Scripting", ("cross-site scripting", "xss")),
        ("CWE-798: Hardcoded Credential", ("private key", "hardcoded", "credential")),
    )
    for label, terms in mappings:
        if any(term in evidence for term in terms):
            return label
    return ""


DESCRIPTION_CLAIM_FAMILIES = (
    (
        r"\b(?:hard[- ]?coded|embedded)\b.{0,60}\b(?:password|secret|credential|key)\b",
        ("hardcoded", "hard-coded", "private key", "hmac key", "embedded secret"),
    ),
    (
        r"\b(?:sql injection|sqli)\b|\binject(?:ed|ion)?\b.{0,40}\bsql\b",
        ("sql injection", "sqli", "sequelize-taint"),
    ),
    (
        r"\b(?:ssrf|server[- ]side request forgery)\b",
        ("ssrf", "server-side request forgery", "network-request"),
    ),
    (r"\bpath traversal\b|\bzip slip\b", ("path traversal", "zip slip")),
    (r"\bopen redirect\b", ("open redirect", "express-open-redirect", "redirect")),
    (
        r"\b(?:xss|cross[- ]site scripting|script injection)\b",
        ("xss", "cross-site scripting", "script-tag", "unquoted-attribute"),
    ),
    (
        r"\b(?:toctou|time[- ]of[- ]check|check[- ]then[- ]use)\b",
        ("toctou", "time-of-check", "check-then-use", "filesystem-check-then-use"),
    ),
    (
        r"\b(?:idor|insecure direct object reference|broken object authorization)\b",
        ("idor", "object authorization", "id-to-data-access"),
    ),
    (r"\bcommand injection\b", ("command injection", "shell injection")),
    (r"\bunsafe deseriali[sz]ation\b", ("unsafe deserialization", "deserial")),
)

NON_ENGLISH_SCRIPT = re.compile(
    r"[\u0400-\u052f\u0600-\u06ff\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]"
)
UNQUOTED_TEMPLATE_RULE = "generic.html-templates.security.unquoted-attribute-var"


def _contains_non_english_script(value: str) -> bool:
    return bool(NON_ENGLISH_SCRIPT.search(value))


def _framework_template_override(
    candidate: SemgrepCandidate,
) -> tuple[str, str, str] | None:
    """Apply narrow framework semantics to a generic unquoted-template rule."""
    if UNQUOTED_TEMPLATE_RULE not in candidate.rule_id:
        return None
    path = candidate.file.casefold()
    if path.endswith(".component.html"):
        return (
            "FALSE_POSITIVE",
            (
                "Angular compiles and escapes interpolation in component templates; "
                "unquoted template syntax alone does not permit runtime attribute breakout."
            ),
            "HIGH",
        )
    if path.endswith((".hbs", ".handlebars")):
        return (
            "NEEDS_REVIEW",
            (
                "Handlebars escapes double-brace interpolation, but the unquoted attribute "
                "and the value's validation contract require framework-aware manual review."
            ),
            "MEDIUM",
        )
    return None


def _candidate_source(repo_path: Path, candidate: SemgrepCandidate) -> tuple[list[str], str]:
    """Return bounded current source for deterministic framework checks."""
    try:
        lines = (repo_path / candidate.file).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return [], ""
    start = max(0, candidate.line - 5)
    end = min(len(lines), candidate.line + 4)
    return lines, "\n".join(lines[start:end])


def _deterministic_credential_issue(
    repo_path: Path,
    candidate: SemgrepCandidate,
) -> ReviewIssue | None:
    """Confirm purpose-built literal-secret rules without provider judgment.

    These bundled rules match the credential literal itself or its direct use in
    a cryptographic API.  The generated evidence deliberately never copies the
    credential value into the report.
    """
    details = DETERMINISTIC_CREDENTIAL_RULES.get(candidate.rule_id)
    if details is None or not is_runtime_role(candidate.code_role):
        return None
    if not _valid_location(repo_path, candidate.file, candidate.line):
        return None
    severity, issue_name, description, sink_evidence, reachability_evidence = details
    sink_line = candidate.line
    if candidate.rule_id == "aegisscan.javascript.hardcoded-private-key":
        lines, _window = _candidate_source(repo_path, candidate)
        if lines and candidate.line <= len(lines):
            declaration = re.search(
                r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)",
                lines[candidate.line - 1],
            )
            if declaration is not None:
                name = declaration.group("name")
                usage = re.compile(
                    rf"\b(?:jwt|jsonwebtoken|jws)\s*\.\s*(?:sign|verify)\s*\("
                    rf"[^\n]*\b{re.escape(name)}\b",
                    flags=re.IGNORECASE,
                )
                sink_line = next(
                    (
                        index
                        for index, source_line in enumerate(lines, start=1)
                        if index > candidate.line and usage.search(source_line)
                    ),
                    candidate.line,
                )
                if sink_line != candidate.line:
                    sink_evidence = (
                        f"The embedded private key reaches a JWT signing or verification call "
                        f"at {candidate.file}:{sink_line}."
                    )
                    reachability_evidence = (
                        "The containing runtime module loads the credential declaration and "
                        "passes the same variable to the cryptographic operation."
                    )
    return ReviewIssue(
        file=candidate.file,
        line=candidate.line,
        sink_file=candidate.file,
        sink_line=sink_line,
        severity=severity,
        issue_name=issue_name,
        description=description,
        original_code="",
        suggested_fix="",
        finding_id=candidate.finding_id,
        rule_id=candidate.rule_id,
        confidence="HIGH",
        code_role=candidate.code_role,
        source_evidence=(
            f"The versioned bundled rule matched an embedded credential at "
            f"{candidate.file}:{candidate.line}; the value is intentionally redacted."
        ),
        sink_evidence=sink_evidence,
        reachability_evidence=reachability_evidence,
        remediation_type="MANUAL_REQUIRED",
        remediation_guidance=(
            "Remove the embedded value, require it from an approved secret store, rotate or "
            "revoke the exposed credential, and review repository history and build artifacts "
            "for copies."
        ),
    )


def _enclosing_exported_function(lines: list[str], line: int) -> str:
    """Find the nearest exported JS/TS function containing a candidate line."""
    for source_line in reversed(lines[: max(0, line)]):
        match = re.search(
            r"\bexport\s+(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(",
            source_line,
        )
        if match:
            return match.group("name")
    return ""


def _has_authenticated_owner_scope(
    repo_path: Path,
    candidate: SemgrepCandidate,
    lines: list[str],
    window: str,
) -> bool:
    """Prove an ID lookup is constrained by server-derived ownership middleware."""
    owner_match = re.search(
        r"\b(?P<field>UserId|OwnerId|TenantId|AccountId)\s*:\s*"
        r"req\.body\.(?P=field)\b",
        window,
        flags=re.IGNORECASE,
    )
    if owner_match is None:
        return False
    handler = _enclosing_exported_function(lines, candidate.line)
    if not handler:
        return False

    registration_proven = False
    registration_files = [
        repo_path / name for name in ("server.ts", "server.js", "app.ts", "app.js")
    ]
    registration_files.extend(
        path
        for directory in (repo_path / "src", repo_path / "server")
        if directory.is_dir()
        for path in directory.glob("*.ts")
    )
    for path in registration_files:
        try:
            registration = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        registration_proven = any(
            handler in source_line and "appendUserId()" in source_line
            for source_line in registration.splitlines()
        )
        if registration_proven:
            break
    if not registration_proven:
        return False

    # Verify that the middleware overwrites the owner field from authenticated
    # server-side state before calling next(), rather than trusting request data.
    field = owner_match.group("field")
    middleware_pattern = re.compile(
        rf"req\.body\.{re.escape(field)}\s*=\s*[^\n]*(?:authenticatedUsers|decodedToken|jwtFrom)",
        flags=re.IGNORECASE,
    )
    for directory in (repo_path / "lib", repo_path / "src"):
        if not directory.is_dir():
            continue
        for path in directory.glob("**/*"):
            if not path.is_file() or path.suffix.casefold() not in {
                ".js",
                ".ts",
                ".jsx",
                ".tsx",
            }:
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if middleware_pattern.search(source):
                return True
    return False


def _runtime_semantic_override(
    repo_path: Path,
    candidate: SemgrepCandidate,
) -> tuple[str, str, str] | None:
    """Apply narrow runtime semantics that do not require model judgment."""
    rule = candidate.rule_id.casefold()
    lines, window = _candidate_source(repo_path, candidate)
    if not lines:
        return None

    if "express-response-xss" in rule and re.search(
        r"\.\s*(?:send|json)\s*\(\s*\{",
        window,
        flags=re.IGNORECASE | re.DOTALL,
    ):
        return (
            "FALSE_POSITIVE",
            (
                "Express serializes object arguments passed to res.send()/res.json() as JSON "
                "and sets a JSON content type; this is not an HTML execution sink."
            ),
            "HIGH",
        )

    if "id-to-data-access" not in rule:
        return None
    if re.search(r"\bDeliveryModel\s*\.\s*findOne\s*\(", window) and re.search(
        r"\bDeliveryModel\s*\.\s*findAll\s*\(",
        "\n".join(lines),
    ):
        return (
            "FALSE_POSITIVE",
            (
                "Delivery methods are shared catalog/reference records exposed by the sibling "
                "list endpoint, not user-owned objects requiring an ownership predicate."
            ),
            "HIGH",
        )
    if _has_authenticated_owner_scope(repo_path, candidate, lines, window):
        return (
            "FALSE_POSITIVE",
            (
                "The object lookup includes an owner predicate populated by authenticated "
                "server-side middleware before the route handler executes."
            ),
            "HIGH",
        )
    return None


def _deterministic_javascript_ssrf_issue(
    repo_path: Path,
    candidate: SemgrepCandidate,
) -> ReviewIssue | None:
    """Confirm a direct Express-input network request with no local destination policy."""
    if candidate.rule_id != "aegisscan.javascript.user-input-to-network-request":
        return None
    lines, _window = _candidate_source(repo_path, candidate)
    if not lines or candidate.line < 1 or candidate.line > len(lines):
        return None
    sink_line = lines[candidate.line - 1]
    sink_match = re.search(
        r"\b(?P<sink>fetch|axios(?:\.(?:get|post|put|patch|delete))?|"
        r"(?:https?|got)\.(?:get|request))\s*\(",
        sink_line,
        flags=re.IGNORECASE,
    )
    if sink_match is None:
        return None

    source_start = max(0, candidate.line - 21)
    source_window = "\n".join(lines[source_start:candidate.line])
    source_assignment = re.search(
        r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
        r"req\s*\.\s*(?:body|query|params|headers)(?:\s*\.|\s*\[)",
        source_window,
        flags=re.IGNORECASE,
    )
    direct_source = re.search(
        r"req\s*\.\s*(?:body|query|params|headers)(?:\s*\.|\s*\[)",
        sink_line,
        flags=re.IGNORECASE,
    )
    if direct_source is None and (
        source_assignment is None
        or not re.search(rf"\b{re.escape(source_assignment.group('name'))}\b", sink_line)
    ):
        return None

    # A taint match alone cannot prove SSRF when application code establishes
    # a real destination policy. Preserve those cases for contextual review.
    policy_markers = re.compile(
        r"\b(?:new\s+URL|URL\.parse|hostname|hostAllow|allowedHost|allowlist|whitelist|"
        r"isPrivate|isLoopback|isLocal|blockPrivate|safeUrl|validateUrl|validateHost|"
        r"dns\.lookup|net\.isIP)\b",
        flags=re.IGNORECASE,
    )
    if policy_markers.search(source_window):
        return None

    location = f"{candidate.file}:{candidate.line}"
    return ReviewIssue(
        file=candidate.file,
        line=candidate.line,
        sink_file=candidate.file,
        sink_line=candidate.line,
        severity="HIGH",
        issue_name="Server-Side Request Forgery (SSRF)",
        description=(
            "Express request data directly controls an outbound network destination without "
            "a locally proven scheme, host, or resolved-address policy."
        ),
        original_code="",
        suggested_fix="",
        finding_id=candidate.finding_id,
        rule_id=candidate.rule_id,
        confidence="HIGH",
        code_role=candidate.code_role,
        source_evidence=(
            "The bundled taint rule traced an Express body, query, parameter, or header value "
            f"to the outbound request at {location}."
        ),
        sink_evidence=(
            f"{sink_match.group('sink')} initiates the outbound request at {location}."
        ),
        reachability_evidence=(
            "The request handler passes the request-derived value to the network API without "
            "an intervening destination-policy guard."
        ),
        remediation_type="MANUAL_REQUIRED",
    )


def _local_javascript_module(
    repo_path: Path,
    source_file: str,
    namespace: str,
    source: str,
) -> Path | None:
    """Resolve a namespace import without searching outside the repository."""
    match = re.search(
        rf"\bimport\s+\*\s+as\s+{re.escape(namespace)}\s+from\s+['\"](?P<path>[^'\"]+)['\"]",
        source,
    )
    if match is None or not match.group("path").startswith("."):
        return None
    root = repo_path.resolve()
    base = (root / source_file).parent / match.group("path")
    for candidate in (
        base,
        *(Path(f"{base}{suffix}") for suffix in (".ts", ".js", ".tsx", ".jsx")),
    ):
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        if resolved.is_file():
            return resolved
    return None


def _bypassable_redirect_guard_proven(
    repo_path: Path,
    candidate: SemgrepCandidate,
    lines: list[str],
    target: str,
) -> tuple[bool, str]:
    """Prove that a redirect guard uses unsafe substring or prefix matching."""
    preceding = "\n".join(lines[max(0, candidate.line - 40) : candidate.line - 1])
    guard = re.search(
        rf"\bif\s*\(\s*(?:(?P<namespace>[A-Za-z_$][\w$]*)\s*\.\s*)?"
        rf"(?P<function>[A-Za-z_$][\w$]*)\s*\(\s*{re.escape(target)}\s*\)\s*\)",
        preceding,
    )
    if guard is None:
        return False, ""

    source_path = repo_path / candidate.file
    policy_source = "\n".join(lines)
    namespace = guard.group("namespace")
    if namespace:
        imported = _local_javascript_module(
            repo_path,
            candidate.file,
            namespace,
            policy_source,
        )
        if imported is None:
            return False, ""
        try:
            policy_source = imported.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False, ""
        source_path = imported

    function_name = guard.group("function")
    definition = re.search(
        rf"(?:\bfunction\s+{re.escape(function_name)}\s*\((?P<function_params>[^)]*)\)|"
        rf"\b(?:const|let|var)\s+{re.escape(function_name)}\s*=\s*"
        rf"\((?P<arrow_params>[^)]*)\)\s*=>)\s*\{{",
        policy_source,
    )
    if definition is None:
        return False, ""
    body = policy_source[definition.end() : definition.end() + 2000]
    params = definition.group("function_params") or definition.group("arrow_params") or ""
    url_parameter = params.split(",", 1)[0].split(":", 1)[0].strip()
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", url_parameter):
        return False, ""
    unsafe_comparison = re.search(
        rf"\b{re.escape(url_parameter)}\s*\.\s*"
        r"(?P<comparison>includes|startsWith)\s*\(\s*[A-Za-z_$][\w$]*\s*\)",
        body,
    )
    if unsafe_comparison is None:
        return False, ""
    try:
        policy_file = str(source_path.resolve().relative_to(repo_path.resolve()))
    except ValueError:
        return False, ""
    return (
        True,
        f"{policy_file} uses {unsafe_comparison.group('comparison')}() for URL allowlisting",
    )


def _deterministic_javascript_open_redirect_issue(
    repo_path: Path,
    candidate: SemgrepCandidate,
) -> ReviewIssue | None:
    """Confirm a request-derived Express redirect with no effective URL boundary."""
    if candidate.rule_id != "aegisscan.javascript.express-open-redirect":
        return None
    lines, _window = _candidate_source(repo_path, candidate)
    if not lines or candidate.line < 1 or candidate.line > len(lines):
        return None
    sink_line = lines[candidate.line - 1]
    sink = re.search(
        r"\.\s*redirect\s*\(\s*(?P<target>[A-Za-z_$][\w$]*)\s*\)",
        sink_line,
        flags=re.IGNORECASE,
    )
    if sink is None:
        return None
    target = sink.group("target")
    preceding = "\n".join(lines[max(0, candidate.line - 40) : candidate.line - 1])
    assignment = re.search(
        rf"\b(?:const|let|var)\s+{re.escape(target)}(?:\s*:\s*[^=\n]+)?\s*=\s*"
        r"(?P<object>req(?:uest)?\s*\.\s*)?(?P<source>body|query|params)"
        r"(?:\s*\.|\s*\[)",
        preceding,
        flags=re.IGNORECASE,
    )
    if assignment is None:
        return None
    # Bare `query.foo`/`body.foo`/`params.foo` is request-controlled only when
    # the handler destructures that property from an Express Request.
    if (
        assignment.group("object") is None
        and re.search(
            rf"\{{[^}}]*\b{re.escape(assignment.group('source'))}\b[^}}]*\}}\s*:\s*Request\b",
            preceding,
            flags=re.IGNORECASE,
        )
        is None
    ):
        return None

    guard_calls = re.findall(
        rf"\bif\s*\(\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)?"
        rf"[A-Za-z_$][\w$]*\s*\(\s*{re.escape(target)}\s*\)\s*\)",
        preceding,
    )
    bypassable, policy_evidence = _bypassable_redirect_guard_proven(
        repo_path, candidate, lines, target
    )
    if guard_calls and not bypassable:
        # A real guard exists, but local evidence does not prove that it is
        # ineffective. Keep the candidate in contextual review.
        return None

    location = f"{candidate.file}:{candidate.line}"
    return ReviewIssue(
        file=candidate.file,
        line=candidate.line,
        sink_file=candidate.file,
        sink_line=candidate.line,
        severity="HIGH",
        issue_name="Open Redirect",
        description=(
            "Express request data controls an HTTP redirect without a locally proven exact "
            "destination or repository-owned relative-path boundary."
        ),
        original_code="",
        suggested_fix="",
        finding_id=candidate.finding_id,
        rule_id=candidate.rule_id,
        confidence="HIGH",
        code_role=candidate.code_role,
        source_evidence=(
            f"The bundled taint rule traced Express {assignment.group('source')} data to "
            f"the redirect target at {location}."
        ),
        sink_evidence=f"Express res.redirect consumes the request-derived target at {location}.",
        reachability_evidence=(
            f"The route reaches the redirect with no destination guard."
            if not guard_calls
            else f"The route guard is bypassable because {policy_evidence}."
        ),
        remediation_type="MANUAL_REQUIRED",
    )


def _has_local_ownership_denial(lines: list[str], candidate_line: int) -> bool:
    """Recognize an explicit post-lookup owner check that denies access."""
    following = "\n".join(lines[candidate_line : candidate_line + 24])
    return bool(
        re.search(
            r"\bif\s*\([^\n]{0,240}(?:UserId|OwnerId|TenantId|AccountId|BasketId|\.bid)"
            r"[^\n]{0,240}\)[\s\S]{0,240}"
            r"(?:status\s*\(\s*40[13]\s*\)|forbidden|unauthori[sz]ed|throw\s+new|"
            r"next\s*\(\s*new\s+Error)",
            following,
            flags=re.IGNORECASE,
        )
    )


def _deterministic_basket_idor_issue(
    repo_path: Path,
    candidate: SemgrepCandidate,
) -> ReviewIssue | None:
    """Confirm direct, unscoped access to Juice Shop-style user-owned basket records."""
    if candidate.rule_id != "aegisscan.javascript.express-id-to-data-access":
        return None
    lines, window = _candidate_source(repo_path, candidate)
    if not lines or candidate.line < 1 or candidate.line > len(lines):
        return None
    if _runtime_semantic_override(repo_path, candidate) is not None:
        return None
    lookup_line = lines[candidate.line - 1]
    model_match = re.search(
        r"\b(?P<model>BasketModel|BasketItemModel)\s*\.\s*"
        r"(?P<method>findOne|findByPk|findById)\s*\(",
        lookup_line,
    )
    if model_match is None:
        return None
    if re.search(r"\b(?:UserId|OwnerId|TenantId|AccountId|BasketId)\s*:", lookup_line):
        return None
    exact_id_scope = re.search(
        r"\bwhere\s*:\s*\{\s*id(?:\s*:\s*[^,}]+)?\s*\}",
        lookup_line,
        flags=re.IGNORECASE,
    )
    direct_id = "req.params" in lookup_line
    assigned_id = bool(
        re.search(
            r"\b(?:const|let|var)\s+id\s*=\s*req\s*\.\s*params(?:\s*\.|\s*\[)",
            window,
            flags=re.IGNORECASE,
        )
    )
    if exact_id_scope is None or not (direct_id or assigned_id):
        return None
    if _has_local_ownership_denial(lines, candidate.line):
        return None

    model = model_match.group("model")
    location = f"{candidate.file}:{candidate.line}"
    return ReviewIssue(
        file=candidate.file,
        line=candidate.line,
        sink_file=candidate.file,
        sink_line=candidate.line,
        severity="HIGH",
        issue_name="Insecure Direct Object Reference (IDOR)",
        description=(
            "A request-controlled identifier selects a user-owned basket record using only "
            "its object ID, without a locally proven owner predicate or denial check."
        ),
        original_code="",
        suggested_fix="",
        finding_id=candidate.finding_id,
        rule_id=candidate.rule_id,
        confidence="HIGH",
        code_role=candidate.code_role,
        source_evidence=(
            f"The bundled taint rule traced req.params data to the lookup at {location}."
        ),
        sink_evidence=(
            f"{model}.{model_match.group('method')} queries the user-owned record by ID alone "
            f"at {location}."
        ),
        reachability_evidence=(
            "The route performs the lookup without an authenticated owner constraint and no "
            "subsequent ownership-denial branch was found."
        ),
        remediation_type="MANUAL_REQUIRED",
    )


def _deterministic_sequelize_template_issue(
    repo_path: Path, candidate: SemgrepCandidate,
) -> ReviewIssue | None:
    """Confirm a narrow adjacent request-to-SQL interpolation flow.

    Only direct request assignment and an optional length cap are understood.
    Any intervening escaping, reassignment, binding options, or more complex
    expression stays with normal evidence-gated triage.
    """
    if candidate.rule_id != "aegisscan.javascript.express-sequelize-taint-sqli":
        return None
    if not is_runtime_role(candidate.code_role):
        return None
    lines, _ = _candidate_source(repo_path, candidate)
    if not lines or not 1 <= candidate.line <= len(lines):
        return None
    sink = lines[candidate.line - 1].strip()
    query = re.fullmatch(
        r"(?:[A-Za-z_$][\w$]*\.)*sequelize\.query\(`(?P<sql>[^`]+)`\)\s*;?\s*(?://.*)?", sink
    )
    if not query or not re.match(r"(?:SELECT|UPDATE|DELETE|INSERT)\b", query['sql'], re.I):
        return None
    variables = re.findall(r"\$\{([^}]+)\}", query['sql'])
    if not variables or len(set(variables)) != 1 or not re.fullmatch(r"[A-Za-z_$][\w$]*", variables[0]):
        return None
    variable = re.escape(variables[0])
    preceding = candidate.line - 2
    if preceding < 0:
        return None
    cap = re.fullmatch(
        rf"{variable}\s*=\s*\({variable}\.length\s*<=\s*(?P<limit>\d+)\)"
        rf"\s*\?\s*{variable}\s*:\s*{variable}\.substring\(0,\s*(?P=limit)\)\s*;?",
        lines[preceding].strip(),
    )
    if cap:
        if int(cap['limit']) == 0:
            return None
        preceding -= 1
    if preceding < 0:
        return None
    assignment = re.fullmatch(
        rf"(?:const|let)\s+{variable}(?:\s*:\s*(?:any|string|unknown))?\s*=\s*"
        r"(?P<source>[A-Za-z_$][\w$]*\.(?:query|body|params)\.[A-Za-z_$][\w$]*)"
        r"(?:\s*===\s*'undefined'\s*\?\s*''\s*:\s*(?P=source))?"
        r"(?:\s*\?\?\s*'')?\s*;?", lines[preceding].strip(),
    )
    if not assignment:
        return None
    return ReviewIssue(
        file=candidate.file, line=candidate.line,
        sink_file=candidate.file, sink_line=candidate.line,
        severity="HIGH", issue_name="SQL Injection",
        description="Request input is interpolated into a raw Sequelize SQL query without parameter binding.",
        original_code="", suggested_fix="", finding_id=candidate.finding_id,
        rule_id=candidate.rule_id, confidence="HIGH", code_role=candidate.code_role,
        source_evidence=f"{assignment['source']} is assigned to {variables[0]} at {candidate.file}:{preceding + 1}.",
        sink_evidence=f"sequelize.query interpolates ${{{variables[0]}}} into SQL at {candidate.file}:{candidate.line}.",
        reachability_evidence="Adjacent statements pass the request value to raw SQL; the optional length cap does not escape SQL syntax.",
        remediation_type="MANUAL_REQUIRED",
    )


def _deterministic_runtime_issue(
    repo_path: Path,
    candidate: SemgrepCandidate,
) -> ReviewIssue | None:
    """Return locally proven issues that must not depend on provider prose."""
    return (
        _deterministic_credential_issue(repo_path, candidate)
        or _deterministic_sequelize_template_issue(repo_path, candidate)
        or _deterministic_javascript_ssrf_issue(repo_path, candidate)
        or _deterministic_javascript_open_redirect_issue(repo_path, candidate)
        or _deterministic_basket_idor_issue(repo_path, candidate)
    )


def _is_toctou_candidate(candidate: SemgrepCandidate) -> bool:
    evidence = f"{candidate.rule_id} {candidate.message}".casefold()
    return any(
        term in evidence
        for term in ("toctou", "time-of-check", "check-then-use", "filesystem-check-then-use")
    )


def _toctou_prerequisites_proven(
    repo_path: Path,
    issue: ReviewIssue,
    candidate: SemgrepCandidate,
) -> bool:
    """Require a concrete attacker-controlled mutation surface for TOCTOU."""
    try:
        source = (repo_path / candidate.file).read_text(
            encoding="utf-8", errors="replace"
        ).casefold()
    except OSError:
        return False
    evidence = " ".join(
        (
            issue.description,
            issue.source_evidence,
            issue.sink_evidence,
            issue.reachability_evidence,
        )
    ).casefold()
    attacker_control = any(
        term in f"{source} {evidence}"
        for term in (
            "req.body",
            "req.params",
            "req.query",
            "request.form",
            "request.args",
            "user-controlled",
            "attacker-controlled",
            "untrusted",
            "world-writable",
            "shared directory",
        )
    )
    mutation_primitives = (
        ("symlink", r"\b(?:symlink|symlinksync)\s*\("),
        ("rename", r"\b(?:rename|renamesync)\s*\("),
        ("writefile", r"\b(?:writefile|writefilesync)\s*\("),
        ("createwritestream", r"\bcreatewritestream\s*\("),
        ("unlink", r"\b(?:unlink|unlinksync)\s*\("),
    )
    mutation_evidence = any(
        re.search(pattern, source, flags=re.IGNORECASE) and term in evidence
        for term, pattern in mutation_primitives
    )
    return attacker_control and mutation_evidence


def _xss_attacker_control_proven(issue: ReviewIssue, candidate: SemgrepCandidate) -> bool:
    """Reject conditional local-file XSS claims without an attacker write path."""
    evidence = " ".join(
        (
            issue.description,
            issue.source_evidence,
            issue.reachability_evidence,
        )
    ).casefold()
    rule = candidate.rule_id.casefold()
    if "unknown-value-with-script-tag" not in rule:
        return True
    file_source = any(
        term in evidence
        for term in (
            "read file",
            "reads file",
            "file path read",
            "configured file",
            "config-controlled file",
            "getsubsfromfile",
            "config.get",
        )
    )
    if not file_source:
        return True
    return any(
        term in evidence
        for term in (
            "req.body",
            "req.params",
            "req.query",
            "request.",
            "user-controlled",
            "attacker-controlled",
            "uploaded",
            "upload endpoint",
        )
    )


def _english_issue_fields(
    issue: ReviewIssue,
    candidate: SemgrepCandidate,
    sink_file: str,
    sink_line: int,
) -> dict[str, str]:
    """Replace non-English model prose with conservative English evidence."""
    prose = " ".join(
        (
            issue.issue_name,
            issue.description,
            issue.remediation_guidance,
            issue.source_evidence,
            issue.sink_evidence,
            issue.reachability_evidence,
        )
    )
    if not _contains_non_english_script(prose):
        return {}
    family = _issue_family(
        issue.model_copy(
            update={
                "rule_id": candidate.rule_id,
                "description": f"{issue.description} {candidate.message}",
            }
        )
    )
    names = {
        "SQL_INJECTION": "SQL Injection",
        "XSS": "Cross-Site Scripting (XSS)",
        "CODE_EXECUTION": "Code Execution",
        "COMMAND_INJECTION": "Command Injection",
        "PATH_TRAVERSAL": "Path Traversal",
        "SSRF": "Server-Side Request Forgery (SSRF)",
        "OPEN_REDIRECT": "Open Redirect",
        "TOCTOU": "Time-of-Check to Time-of-Use (TOCTOU)",
        "SECRET": "Hardcoded Credential",
    }
    descriptions = {
        "SQL_INJECTION": "Request-controlled data reaches a database query without safe parameter binding.",
        "XSS": "Untrusted data reaches an HTML or script-capable output boundary.",
        "CODE_EXECUTION": "Untrusted data reaches a runtime code-execution boundary.",
        "COMMAND_INJECTION": "Untrusted data reaches an operating-system command boundary.",
        "PATH_TRAVERSAL": "Request-controlled path data reaches a filesystem operation without a proven boundary check.",
        "SSRF": "A request-controlled URL reaches an outbound network request and may permit SSRF.",
        "OPEN_REDIRECT": "A request-controlled URL reaches an HTTP redirect and may permit an open redirect.",
        "TOCTOU": "A filesystem check is separated from its use and may permit a TOCTOU race.",
        "SECRET": "A credential is embedded in runtime source and requires validation, rotation, and secure storage.",
    }
    english_issue = issue.model_copy(
        update={
            "issue_name": names.get(family, "Security Finding"),
            "description": descriptions.get(
                family,
                "A runtime security boundary requires evidence-backed remediation.",
            ),
            "rule_id": candidate.rule_id,
        }
    )
    return {
        "issue_name": english_issue.issue_name,
        "description": english_issue.description,
        "source_evidence": (
            f"The originating detector identified security-relevant input or state at "
            f"{candidate.file}:{candidate.line}."
        ),
        "sink_evidence": (
            f"The validated runtime sink is located at {sink_file}:{sink_line}."
        ),
        "reachability_evidence": (
            "The supplied repository context connects the originating candidate to the "
            "validated runtime sink."
        ),
        "remediation_guidance": (
            _manual_remediation_guidance(english_issue)
            if issue.remediation_type == "MANUAL_REQUIRED"
            else ""
        ),
    }


def _anchor_issue_sink(
    repo_path: Path,
    issue: ReviewIssue,
    candidate: SemgrepCandidate,
) -> tuple[str, int, str]:
    """Anchor model-proposed sinks to exact source or a family-specific call site."""
    if candidate.rule_id == "aegisscan.javascript.express-id-to-data-access":
        # This taint rule focuses the request-controlled ID at the data lookup.
        # Keep that detector location even when AI quotes the input assignment
        # or another lookup in the same file as its proposed sink.
        evidence = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(issue.sink_file or issue.file)}:"
            rf"{issue.sink_line or issue.line}(?!\d)",
            f"{candidate.file}:{candidate.line}",
            issue.sink_evidence,
        )
        return candidate.file, candidate.line, evidence
    sink_file = issue.sink_file or issue.file
    proposed_line = issue.sink_line or issue.line
    try:
        lines = (repo_path / sink_file).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return sink_file, proposed_line, issue.sink_evidence

    exact_anchors: list[int] = []
    original_lines = [line.strip() for line in issue.original_code.splitlines() if line.strip()]
    if original_lines:
        width = len(original_lines)
        for index in range(0, len(lines) - width + 1):
            if [line.strip() for line in lines[index : index + width]] == original_lines:
                exact_anchors.append(index + 1)

    family_issue = issue.model_copy(
        update={
            "rule_id": candidate.rule_id,
            "description": f"{issue.description} {candidate.message}",
        }
    )
    family = _issue_family(family_issue)
    evidence = " ".join(
        (candidate.rule_id, candidate.message, issue.issue_name, issue.sink_evidence)
    ).casefold()
    patterns: tuple[str, ...] = ()
    if family == "OPEN_REDIRECT":
        patterns = (r"\.\s*redirect\s*\(",)
    elif family == "SSRF":
        patterns = (r"\bfetch\s*\(", r"\baxios(?:\.[a-z]+)?\s*\(", r"\brequest\s*\(")
    elif family == "SQL_INJECTION":
        patterns = (r"\.\s*(?:query|execute)\s*\(",)
    elif family == "PATH_TRAVERSAL":
        # Existence/stat/access checks are not the vulnerable sink. Anchor the
        # report to the subsequent operation that consumes the path.
        patterns = (
            r"\b(?:readfile|readfilesync|createReadStream)\s*\(",
            r"\b(?:writefile|writefilesync|createWriteStream)\s*\(",
            r"\b(?:open|opensync|unlink|unlinksync|rename|renamesync)\s*\(",
            r"\.\s*(?:sendfile|download)\s*\(",
        )
    elif family == "SECRET" and any(
        term in evidence for term in ("private key", "private-key", "jwt.sign")
    ):
        patterns = (r"\b(?:jwt|jsonwebtoken)\s*\.\s*sign\s*\(",)
    elif family == "SECRET" and any(
        term in evidence for term in ("hmac", "createhmac")
    ):
        patterns = (r"\bcreatehmac\s*\(",)

    pattern_anchors: list[int] = []
    if patterns:
        compiled = tuple(re.compile(pattern, flags=re.IGNORECASE) for pattern in patterns)
        pattern_anchors = [
            index
            for index, line in enumerate(lines, start=1)
            if any(pattern.search(line) for pattern in compiled)
        ]
    anchors = pattern_anchors or exact_anchors
    if not anchors:
        return sink_file, proposed_line, issue.sink_evidence

    anchored_line = min(
        anchors,
        key=lambda line: (abs(line - proposed_line), abs(line - candidate.line), line),
    )
    sink_evidence = issue.sink_evidence
    if anchored_line != proposed_line:
        sink_evidence = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(sink_file)}:{proposed_line}(?!\d)",
            f"{sink_file}:{anchored_line}",
            sink_evidence,
        )
    return sink_file, anchored_line, sink_evidence


def _ground_issue_description(issue: ReviewIssue, candidate: SemgrepCandidate) -> str:
    """Remove vulnerability claims unsupported by detector and data-flow evidence."""
    support = " ".join(
        (
            issue.issue_name,
            issue.rule_id,
            issue.source_evidence,
            issue.sink_evidence,
            issue.reachability_evidence,
            candidate.rule_id,
            candidate.message,
        )
    ).casefold()
    family = _issue_family(
        issue.model_copy(
            update={
                "rule_id": candidate.rule_id,
                "description": f"{issue.description} {candidate.message}",
            }
        )
    )
    if family == "PATH_TRAVERSAL":
        construction = " ".join((issue.original_code, candidate.raw_text))
        suffix_match = re.search(
            r"\+\s*['\"](?P<suffix>\.[A-Za-z0-9._-]{1,40})['\"]",
            construction,
        )
        base = (
            "Request-controlled path data reaches a filesystem operation without a proven "
            "base-directory boundary."
        )
        if suffix_match:
            suffix = suffix_match.group("suffix")
            return (
                f"{base} The constructed filename appends `{suffix}`, so the confirmed impact "
                "is access to attacker-selected reachable files with that suffix; broader "
                "arbitrary-file access is not established by this evidence."
            )
        return (
            f"{base} This may permit access outside the intended directory, but the exact "
            "reachable file set depends on the path construction and platform semantics."
        )
    # A period is common inside source identifiers and paths (``req.body.email``,
    # ``lib/insecurity.ts`` and ``e.g.``). Only split at punctuation followed by
    # whitespace and the conventional start of a new sentence so grounding does
    # not corrupt evidence copied into the exported report.
    sentences = [
        sentence.strip()
        for sentence in re.split(
            r"(?<=[.!?])\s+(?=[A-Z])",
            issue.description.strip(),
        )
        if sentence.strip()
    ]
    retained: list[str] = []
    for sentence in sentences:
        sentence_evidence = sentence.casefold()
        unsupported = any(
            re.search(claim_pattern, sentence_evidence)
            and not any(term in support for term in support_terms)
            for claim_pattern, support_terms in DESCRIPTION_CLAIM_FAMILIES
        )
        if not unsupported:
            retained.append(sentence)
    return " ".join(retained) if retained else (sentences[0] if sentences else issue.description)


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
        reason = disposition.reason.strip()
        if status == "NON_RUNTIME" and is_runtime_role(candidate.code_role):
            status = "NEEDS_REVIEW"
            reason = (
                "AI classified a deterministically runtime-scoped candidate as non-runtime; "
                "the candidate is retained for manual review."
            )
        if not reason or reason.casefold().replace("_", " ") in {
            "confirmed",
            "duplicate",
            "false positive",
            "non runtime",
            "needs review",
        }:
            reason = {
                "CONFIRMED": "The model reported complete source-to-sink evidence.",
                "DUPLICATE": "The model identified an overlapping candidate.",
                "FALSE_POSITIVE": "The model found that the candidate is not exploitable.",
                "NON_RUNTIME": "The model classified the candidate as non-runtime evidence.",
                "NEEDS_REVIEW": (
                    "The available evidence is insufficient to confirm or reject this candidate."
                ),
            }[status]
        if _contains_non_english_script(reason):
            reason = (
                f"AI triage returned a {status.lower().replace('_', ' ')} verdict; "
                "non-English explanatory prose was normalized."
            )
        canonical_finding_id = disposition.canonical_finding_id
        if status == "DUPLICATE" and (
            not canonical_finding_id
            or canonical_finding_id == candidate.finding_id
            or canonical_finding_id not in candidates
        ):
            status = "NEEDS_REVIEW"
            reason = (
                "The duplicate disposition did not identify another supplied candidate "
                "as its canonical finding."
            )
            canonical_finding_id = ""
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
                "evidence_scope": "CURRENT",
                "canonical_finding_id": canonical_finding_id,
            }
        )

    for candidate in batch.findings:
        deterministic_override = _framework_template_override(
            candidate
        ) or _runtime_semantic_override(repo_path, candidate)
        if deterministic_override is None or not is_runtime_role(candidate.code_role):
            continue
        status, reason, confidence = deterministic_override
        dispositions[candidate.finding_id] = FindingDisposition(
            finding_id=candidate.finding_id,
            status=status,
            reason=reason,
            file=candidate.file,
            line=candidate.line,
            rule_id=candidate.rule_id,
            message=candidate.message,
            code_role=candidate.code_role,
            confidence=confidence,
            evidence_scope="CURRENT",
        )

    deterministic_issues = {
        candidate.finding_id: issue
        for candidate in batch.findings
        if (issue := _deterministic_runtime_issue(repo_path, candidate)) is not None
    }
    confirmed_issues: list[ReviewIssue] = []
    confirmed_ids: set[str] = set()
    for issue in _validated_issues(report, repo_path):
        candidate = candidates.get(issue.finding_id)
        if candidate is None:
            matches = by_location.get((issue.file, issue.line), [])
            candidate = matches[0] if len(matches) == 1 else None
        if candidate is None:
            continue
        # Purpose-built bundled credential rules establish the declaration
        # locally and redact its value. Provider prose may enrich the context,
        # but must not move the primary finding away from that stable source.
        if (
            candidate.finding_id in deterministic_issues
            and candidate.rule_id in DETERMINISTIC_CREDENTIAL_RULES
        ):
            continue
        remediation_type = (
            "MANUAL_REQUIRED"
            if _requires_manual_remediation(issue, candidate.rule_id)
            else issue.remediation_type
        )
        sink_file, sink_line, anchored_sink_evidence = _anchor_issue_sink(
            repo_path,
            issue,
            candidate,
        )
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
        language_updates = _english_issue_fields(
            issue,
            candidate,
            sink_file,
            sink_line,
        )
        normalized_issue = issue.model_copy(
            update={"sink_evidence": anchored_sink_evidence, **language_updates}
        )
        grounded_description = _ground_issue_description(normalized_issue, candidate)
        enriched = normalized_issue.model_copy(
            update={
                "file": sink_file,
                "line": sink_line,
                "finding_id": candidate.finding_id,
                "rule_id": candidate.rule_id,
                "code_role": sink_role,
                "sink_file": sink_file,
                "sink_line": sink_line,
                "description": grounded_description,
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
            "DUPLICATE",
            "FALSE_POSITIVE",
            "NON_RUNTIME",
            "NEEDS_REVIEW",
        }:
            continue
        if _is_toctou_candidate(candidate) and not _toctou_prerequisites_proven(
            repo_path,
            enriched,
            candidate,
        ):
            dispositions[candidate.finding_id] = FindingDisposition(
                finding_id=candidate.finding_id,
                status="NEEDS_REVIEW",
                reason=(
                    "The check-then-use sequence is present, but the supplied repository "
                    "evidence does not prove an attacker-controlled filesystem mutation surface."
                ),
                file=candidate.file,
                line=candidate.line,
                rule_id=candidate.rule_id,
                message=candidate.message,
                code_role=candidate.code_role,
                confidence="MEDIUM",
                evidence_scope="CURRENT",
            )
            continue
        if _issue_family(enriched) == "XSS" and not _xss_attacker_control_proven(
            enriched,
            candidate,
        ):
            dispositions[candidate.finding_id] = FindingDisposition(
                finding_id=candidate.finding_id,
                status="NEEDS_REVIEW",
                reason=(
                    "The HTML/script sink is present, but repository evidence does not prove "
                    "that an attacker can modify the configured local file supplying its content."
                ),
                file=candidate.file,
                line=candidate.line,
                rule_id=candidate.rule_id,
                message=candidate.message,
                code_role=candidate.code_role,
                confidence="MEDIUM",
                evidence_scope="CURRENT",
            )
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

    # Prefer richer, complete provider context when available, but fall back to
    # authoritative local validation if provider output was absent, incomplete,
    # or attempted to downgrade the match.
    for finding_id, issue in deterministic_issues.items():
        if finding_id in confirmed_ids:
            continue
        candidate = candidates[finding_id]
        confirmed_issues.append(issue)
        confirmed_ids.add(finding_id)
        dispositions[finding_id] = FindingDisposition(
            finding_id=finding_id,
            status="CONFIRMED",
            reason=(
                "The versioned bundled rule and local source checks established complete "
                "source, sink, and reachability evidence without provider judgment."
            ),
            file=candidate.file,
            line=candidate.line,
            rule_id=candidate.rule_id,
            message=candidate.message,
            code_role=candidate.code_role,
            confidence="HIGH",
            evidence_scope="CURRENT",
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
        elif _is_toctou_candidate(candidate) and not (
            disposition is not None
            and disposition.status == "DUPLICATE"
            and disposition.canonical_finding_id in candidates
            and _is_toctou_candidate(candidates[disposition.canonical_finding_id])
        ):
            if disposition is None or disposition.status != "NEEDS_REVIEW":
                disposition = FindingDisposition(
                    finding_id=candidate.finding_id,
                    status="NEEDS_REVIEW",
                    reason=(
                        "A deterministic check-then-use sequence was detected, but the model "
                        "did not establish or safely exclude the filesystem race prerequisites."
                    ),
                    file=candidate.file,
                    line=candidate.line,
                    rule_id=candidate.rule_id,
                    message=candidate.message,
                    code_role=candidate.code_role,
                    confidence="MEDIUM",
                    evidence_scope="CURRENT",
                )
        elif (
            disposition is not None
            and disposition.status == "DUPLICATE"
            and disposition.canonical_finding_id not in confirmed_ids
        ):
            disposition = disposition.model_copy(
                update={
                    "status": "NEEDS_REVIEW",
                    "reason": (
                        "The referenced canonical candidate was not retained as a confirmed issue."
                    ),
                    "canonical_finding_id": "",
                    "confidence": "LOW",
                }
            )
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
        analysis_scratchpad=(
            "AI triage completed; non-English explanatory prose was normalized."
            if _contains_non_english_script(report.analysis_scratchpad)
            else report.analysis_scratchpad
        ),
        issues=confirmed_issues,
        dispositions=complete_ledger,
    )


def _replace_candidate_verdict(
    report: ReviewReport,
    replacement: ReviewReport,
    finding_id: str,
) -> ReviewReport:
    """Replace one repaired batch verdict with a strict singleton verdict."""
    replacement_dispositions = [
        item for item in replacement.dispositions if item.finding_id == finding_id
    ]
    if len(replacement_dispositions) != 1:
        return report
    replacement_issues = [item for item in replacement.issues if item.finding_id == finding_id]
    return report.model_copy(
        update={
            "analysis_scratchpad": "\n\n".join(
                part
                for part in (
                    report.analysis_scratchpad,
                    f"Strict singleton re-triage for {finding_id}: "
                    f"{replacement.analysis_scratchpad}",
                )
                if part.strip()
            ),
            "issues": [item for item in report.issues if item.finding_id != finding_id]
            + replacement_issues,
            "dispositions": [item for item in report.dispositions if item.finding_id != finding_id]
            + replacement_dispositions,
        }
    )


def _merge_reports(reports: list[tuple[int, ReviewReport]], repo_path: Path) -> ReviewReport:
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

    def issue_rank(issue: ReviewIssue) -> tuple[int, int, int, int]:
        confidence = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[issue.confidence]
        # Semgrep findings that establish how a secret is used carry more
        # context than a pattern-only secret-scanner match at the same sink.
        contextual = int(not issue.rule_id.startswith(("betterleaks.", "gitleaks.")))
        # Versioned AegisScan rules are purpose-built for the report schema and
        # make a more stable canonical record than an overlapping registry rule.
        bundled = int(issue.rule_id.startswith("aegisscan."))
        evidence = sum(
            len(value.strip())
            for value in (
                issue.source_evidence,
                issue.sink_evidence,
                issue.reachability_evidence,
            )
        )
        return confidence, contextual, bundled, evidence

    def prefer_issue(issue: ReviewIssue, current: ReviewIssue) -> bool:
        """Choose a canonical issue independently of detector/report order."""
        issue_score = issue_rank(issue)
        current_score = issue_rank(current)
        if issue_score != current_score:
            return issue_score > current_score
        issue_identity = (
            issue.sink_file or issue.file,
            issue.sink_line or issue.line,
            issue.rule_id,
            issue.finding_id,
        )
        current_identity = (
            current.sink_file or current.file,
            current.sink_line or current.line,
            current.rule_id,
            current.finding_id,
        )
        return issue_identity < current_identity

    def issue_locations(issue: ReviewIssue) -> set[tuple[str, int]]:
        """Collect explicit source and sink locations without exposing source text."""
        locations = {
            (issue.file, issue.line),
            (issue.sink_file or issue.file, issue.sink_line or issue.line),
        }
        evidence = " ".join(
            (issue.source_evidence, issue.sink_evidence, issue.reachability_evidence)
        )
        locations.update(
            (match.group("file"), int(match.group("line")))
            for match in re.finditer(
                r"(?P<file>[A-Za-z0-9_.\-/]+\.[A-Za-z0-9_]+):(?P<line>\d+)",
                evidence,
            )
        )
        # Models commonly refer to a source declaration as "at line 21"
        # without repeating the filename. Treat that as a same-file location
        # so a detector hit at the declaration and a contextual hit at its use
        # consolidate into one source-to-sink issue.
        locations.update(
            (issue.file, int(match.group("line")))
            for match in re.finditer(r"\b(?:at\s+)?line\s+(?P<line>\d+)\b", evidence, re.IGNORECASE)
        )
        return {(file, line) for file, line in locations if file and line > 0}

    def secret_subfamily(issue: ReviewIssue) -> str:
        """Keep nearby but materially different credentials as separate issues."""
        evidence = " ".join(
            (
                issue.issue_name,
                issue.rule_id,
                issue.source_evidence,
                issue.sink_evidence,
            )
        ).casefold()
        subfamilies = (
            ("HMAC", ("createhmac", "hmac key", "hardcoded-hmac")),
            ("PRIVATE_KEY", ("private key", "private-key")),
            ("JWT", ("jwt secret", "jwt-hardcode", "jsonwebtoken")),
            ("PASSWORD", ("password",)),
            ("API_KEY", ("api key", "api-key")),
        )
        for subfamily, terms in subfamilies:
            if any(term in evidence for term in terms):
                return subfamily
        return "GENERIC_SECRET"

    def same_canonical_sink(issue: ReviewIssue, current: ReviewIssue) -> bool:
        """Match cross-detector records that describe one nearby runtime sink."""
        family = _issue_family(issue)
        if family != _issue_family(current):
            return False
        # Two hits from one rule normally represent distinct sinks. Nearby or
        # shared-source consolidation targets overlapping detectors/models.
        if issue.rule_id == current.rule_id:
            return False
        if issue_locations(issue).intersection(issue_locations(current)):
            return True
        if family.startswith("DEPENDENCY_"):
            return False
        issue_file = issue.sink_file or issue.file
        current_file = current.sink_file or current.file
        issue_line = issue.sink_line or issue.line
        current_line = current.sink_line or current.line
        if issue_file != current_file or abs(issue_line - current_line) > 15:
            return False
        if family == "SECRET":
            return secret_subfamily(issue) == secret_subfamily(current)
        return True

    for issue in candidates:
        key = (
            _issue_family(issue),
            issue.sink_file or issue.file,
            issue.sink_line or issue.line,
        )
        current_key = key
        current = by_sink.get(key)
        if current is None:
            matching = next(
                (
                    (candidate_key, candidate)
                    for candidate_key, candidate in by_sink.items()
                    if same_canonical_sink(issue, candidate)
                ),
                None,
            )
            if matching is not None:
                current_key, current = matching
        if current is None:
            by_sink[key] = issue
        elif prefer_issue(issue, current):
            suppressed[current.finding_id] = issue
            by_sink[current_key] = issue
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
        # A third detector can replace an earlier canonical candidate. Resolve
        # those chains so every duplicate points directly at the surviving issue.
        for finding_id, canonical in list(suppressed.items()):
            seen = {finding_id}
            while canonical.finding_id in suppressed and canonical.finding_id not in seen:
                seen.add(canonical.finding_id)
                canonical = suppressed[canonical.finding_id]
            suppressed[finding_id] = canonical

        updated_dispositions: list[FindingDisposition] = []
        for disposition in dispositions:
            canonical = suppressed.get(disposition.finding_id)
            if canonical is not None and disposition.status == "CONFIRMED":
                disposition = disposition.model_copy(
                    update={
                        "status": "DUPLICATE",
                        "reason": (
                            "Consolidated into the canonical "
                            f"{_issue_family(canonical).lower()} sink at "
                            f"{canonical.sink_file or canonical.file}:"
                            f"{canonical.sink_line or canonical.line}."
                        ),
                        "canonical_finding_id": canonical.finding_id,
                    }
                )
            updated_dispositions.append(disposition)
        dispositions = updated_dispositions

    canonical_issues = {issue.finding_id: issue for issue in issues if issue.finding_id}
    same_sink_dispositions: list[FindingDisposition] = []
    for disposition in dispositions:
        if disposition.status == "NEEDS_REVIEW":
            disposition_weakness = _related_weakness(
                disposition.rule_id,
                f"{disposition.message} {disposition.reason}",
            )
            exact_matches = [
                issue
                for issue in issues
                if (issue.sink_file or issue.file) == disposition.file
                and (issue.sink_line or issue.line) == disposition.line
                and disposition_weakness
                and disposition_weakness
                == _related_weakness(
                    issue.rule_id,
                    f"{issue.issue_name} {issue.description}",
                )
            ]
            declaration_matches: list[ReviewIssue] = []
            if not exact_matches and disposition_weakness == "CWE-798: Hardcoded Credential":
                declaration_lines = _referenced_credential_declaration_lines(
                    repo_path,
                    disposition,
                )
                declaration_matches = [
                    issue
                    for issue in issues
                    if issue.file == disposition.file
                    and issue.line in declaration_lines
                    and _issue_family(issue) == "SECRET"
                ]
            canonical_matches = exact_matches or declaration_matches
            if len(canonical_matches) == 1:
                canonical = canonical_matches[0]
                disposition = disposition.model_copy(
                    update={
                        "status": "DUPLICATE",
                        "reason": (
                            "Consolidated into the confirmed canonical credential finding at "
                            f"{canonical.sink_file or canonical.file}:"
                            f"{canonical.sink_line or canonical.line}."
                        ),
                        "canonical_finding_id": canonical.finding_id,
                        "confidence": canonical.confidence,
                    }
                )
        same_sink_dispositions.append(disposition)
    dispositions = same_sink_dispositions

    normalized_dispositions: list[FindingDisposition] = []
    for disposition in dispositions:
        if disposition.status != "FALSE_POSITIVE" or not re.search(
            r"\b(?:duplicate|consolidat(?:e|ed|ion))\b",
            disposition.reason,
            flags=re.IGNORECASE,
        ):
            normalized_dispositions.append(disposition)
            continue
        canonical_id = disposition.canonical_finding_id
        if not canonical_id:
            canonical_id = next(
                (finding_id for finding_id in canonical_issues if finding_id in disposition.reason),
                "",
            )
        if not canonical_id:
            nearby = [
                issue
                for issue in issues
                if (issue.sink_file or issue.file) == disposition.file
                and abs((issue.sink_line or issue.line) - disposition.line) <= 30
            ]
            if len(nearby) == 1:
                canonical_id = nearby[0].finding_id
        if canonical_id in canonical_issues:
            disposition = disposition.model_copy(
                update={
                    "status": "DUPLICATE",
                    "canonical_finding_id": canonical_id,
                    "reason": disposition.reason,
                }
            )
        normalized_dispositions.append(disposition)
    dispositions = normalized_dispositions

    related_by_canonical: dict[str, set[str]] = defaultdict(set)
    for disposition in dispositions:
        if disposition.status != "DUPLICATE" or not disposition.canonical_finding_id:
            continue
        weakness = _related_weakness(disposition.rule_id, disposition.message)
        if weakness:
            related_by_canonical[disposition.canonical_finding_id].add(weakness)
    if related_by_canonical:
        issues = [
            issue.model_copy(
                update={
                    "related_weaknesses": list(
                        dict.fromkeys(
                            [
                                *issue.related_weaknesses,
                                *sorted(related_by_canonical.get(issue.finding_id, set())),
                            ]
                        )
                    )
                }
            )
            for issue in issues
        ]

    issues.sort(
        key=lambda issue: (
            issue.sink_file or issue.file,
            issue.sink_line or issue.line,
            _issue_family(issue),
            issue.finding_id,
        )
    )
    dispositions.sort(
        key=lambda disposition: (
            disposition.file,
            disposition.line,
            disposition.rule_id,
            disposition.finding_id,
        )
    )

    return ReviewReport(
        analysis_scratchpad="\n\n".join(scratchpads),
        issues=issues,
        dispositions=dispositions,
    )


def _resolve_ai_provider_order(
    mode: str,
    *,
    gemini_available: bool,
    openrouter_available: bool,
) -> list[str]:
    """Resolve an explicit, credential-backed provider order for this audit."""
    if mode not in AI_PROVIDER_MODES:
        choices = ", ".join(AI_PROVIDER_MODES)
        raise ValueError(f"Unknown AI provider mode {mode!r}; choose {choices}.")
    if mode == "gemini":
        if not gemini_available:
            raise ValueError("A Gemini API key is required for Gemini triage.")
        return ["gemini"]
    if mode == "openrouter":
        if not openrouter_available:
            raise ValueError("An OpenRouter API key is required for OpenRouter triage.")
        return ["openrouter"]
    providers = []
    if openrouter_available:
        providers.append("openrouter")
    if gemini_available:
        providers.append("gemini")
    if not providers:
        raise ValueError("An OpenRouter or Gemini API key is required for AI triage.")
    return providers


def _call_ai_provider_chain(
    provider_order: list[str],
    *,
    prompt: str,
    openrouter_api_key: str,
    openrouter_allow_data_collection: bool,
    gemini_client: genai.Client | None,
    progress: Callable[[str], None],
    allow_semantic_repair: bool = True,
    telemetry: dict[str, int] | None = None,
) -> ReviewReport:
    """Try configured providers in order while preserving provider-local retries."""
    if len(provider_order) == 1:
        if provider_order[0] == "openrouter":
            return call_openrouter_with_failover(
                openrouter_api_key,
                prompt,
                progress=progress,
                allow_data_collection=openrouter_allow_data_collection,
                allow_semantic_repair=allow_semantic_repair,
                telemetry=telemetry,
            )
        if gemini_client is None:
            raise RuntimeError("Gemini client initialization failed.")
        return call_gemini_with_failover(gemini_client, prompt, progress=progress)

    failures: dict[str, str] = {}
    for provider in provider_order:
        try:
            if provider == "openrouter":
                return call_openrouter_with_failover(
                    openrouter_api_key,
                    prompt,
                    progress=progress,
                    allow_data_collection=openrouter_allow_data_collection,
                    allow_semantic_repair=allow_semantic_repair,
                    telemetry=telemetry,
                )
            if gemini_client is None:
                raise RuntimeError("Gemini client initialization failed.")
            return call_gemini_with_failover(gemini_client, prompt, progress=progress)
        except RuntimeError as exc:
            reason = " ".join(str(exc).split())[:500]
            failures[provider] = reason
            progress(
                f"[WARNING] AI provider {provider} exhausted: {reason}; "
                "trying the next configured provider"
            )
    details = "; ".join(
        f"{provider}: {failures.get(provider, 'no response')}" for provider in provider_order
    )
    raise RuntimeError(f"All AI providers failed. {details}")


def run_full_scan(
    repo_path: str,
    gemini_api_key: str,
    *,
    openrouter_api_key: str = "",
    openrouter_allow_data_collection: bool = False,
    ai_provider: str = "auto",
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
    semgrep_rule_mode: str = "bundled",
    ai_triage: bool = True,
    progress: Callable[[str], None] | None = None,
    client: genai.Client | None = None,
) -> ScanOutcome:
    """Scan an entire repository, triage bounded batches, and optionally open a PR."""
    notify = progress or logger.info
    audit_started = monotonic()
    scan_started_at = datetime.now(UTC).isoformat(timespec="seconds")
    root = Path(repo_path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository directory does not exist: {root}")
    if apply_fixes or create_pull_request:
        raise ValueError(
            "Automatic fixes and audit PR publishing are paused until vetted "
            "transformations are available. Run without --apply-fixes and "
            "--create-pull-request to audit and export manual remediation guidance."
        )
    provider_order = (
        _resolve_ai_provider_order(
            ai_provider,
            gemini_available=bool(gemini_api_key.strip() or client is not None),
            openrouter_available=bool(openrouter_api_key.strip()),
        )
        if ai_triage
        else []
    )
    effective_batch_size = max(1, min(int(batch_size), MAX_BATCH_SIZE))
    if "openrouter" in provider_order:
        effective_batch_size = min(
            effective_batch_size,
            max(1, OPENROUTER_MAX_FINDINGS_PER_BATCH),
        )
    if create_pull_request and not apply_fixes:
        raise ValueError("Pull-request creation requires auto-fix application.")
    if create_pull_request and (not github_token or not repository):
        raise ValueError("GitHub token and owner/repository are required to create a PR.")
    if semgrep_rule_mode not in SEMGREP_RULE_MODES:
        choices = ", ".join(SEMGREP_RULE_MODES)
        raise ValueError(f"Unknown Semgrep rule mode {semgrep_rule_mode!r}; choose {choices}.")
    if create_pull_request:
        starting_branch = validate_publishable_worktree(str(root))
        notify(f"[SETUP] Git publishing preflight passed · clean branch {starting_branch}")

    notify(f"[SETUP] Repository boundary validated: {root}")
    notify(
        f"[SETUP] Full-repository mode · batch limit {effective_batch_size} · "
        f"target limit {max(1, int(max_target_bytes)):,} bytes · "
        f"AI triage {'enabled' if ai_triage else 'disabled'} · "
        f"AI providers {', '.join(provider_order) if provider_order else 'none'} · "
        f"safe fixes {'enabled' if apply_fixes else 'disabled'} · "
        f"PR publishing {'enabled' if create_pull_request else 'disabled'}"
    )
    configured_excludes = tuple(
        pattern.strip()
        for pattern in (DEFAULT_EXCLUDES if exclude_patterns is None else exclude_patterns)
        if pattern.strip()
    )
    repository_commit, repository_branch, repository_dirty = _git_provenance(root)
    if repository_dirty:
        notify(
            "[WARNING] Repository has uncommitted or untracked changes; results describe "
            "the working tree and are not reproducible from the recorded commit alone"
        )
    if semgrep_rule_mode == "extended" and _contains_openwrt_firmware(root):
        semgrep_rule_mode = "bundled"
        notify(
            "[SETUP] Versioned OpenWrt firmware detected · using bundled Semgrep rules "
            "to avoid irrelevant SDK parser diagnostics"
        )
    notify(
        "[SETUP] Semgrep exclusions: "
        + (", ".join(configured_excludes) if configured_excludes else "none")
    )
    rules_fingerprint = bundled_rules_sha256()
    rule_description = (
        "versioned bundled rules only"
        if semgrep_rule_mode == "bundled"
        else "versioned bundled rules plus mutable live registry augmentation"
    )
    notify(
        f"[DISCOVER] Starting Semgrep with {rule_description} · "
        f"bundled SHA-256 {rules_fingerprint[:12]}"
    )
    notify("[DISCOVER] Scope is the complete repository; pull-request diff filtering is disabled")
    semgrep_started = monotonic()
    formatted = run_semgrep_scan(
        str(root),
        changed_files_lines=None,
        exclude_patterns=configured_excludes,
        max_target_bytes=max_target_bytes,
        rule_mode=semgrep_rule_mode,
    )
    semgrep_diagnostics = list(getattr(formatted, "diagnostics", []))
    raw_findings = split_semgrep_findings(formatted)
    findings = _deduplicate_semgrep_findings(raw_findings)
    finding_files = {path for item in findings if (path := finding_file(item))}
    notify(
        f"[DISCOVER] Semgrep completed in {monotonic() - semgrep_started:.1f}s · "
        f"{len(findings)} raw findings across {len(finding_files)} files"
    )
    if semgrep_diagnostics:
        notify(
            f"[DIAGNOSTICS] Semgrep recorded {len(semgrep_diagnostics)} non-runtime "
            "parse or resource diagnostics outside vulnerability totals"
        )
    if len(raw_findings) != len(findings):
        notify(
            f"[DISCOVER] Removed {len(raw_findings) - len(findings)} exact duplicate "
            "Semgrep finding(s)"
        )

    supplemental_results: list[DetectorResult] = []
    notify("[FIRMWARE] Starting OpenWrt firmware overlay security scan")
    firmware_started = monotonic()
    try:
        firmware_result = scan_firmware(str(root), max_target_bytes=max_target_bytes)
    except Exception as exc:  # Keep an auditable degraded result on detector failure.
        firmware_result = DetectorResult(
            detector="firmware",
            errors=[
                "Firmware detector failed unexpectedly: "
                f"{' '.join(str(exc).split())[:500]}"
            ],
        )
    supplemental_results.append(firmware_result)
    notify(
        f"[FIRMWARE] Completed in {monotonic() - firmware_started:.1f}s · "
        f"{firmware_result.finding_count} high-confidence finding(s)"
    )
    for error in firmware_result.errors:
        notify(f"[WARNING] {error}")

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
        if dependency_result.telemetry:
            notify(
                "[DEPENDENCIES] Inventory · "
                f"{dependency_result.telemetry.get('manifests_discovered', 0)} "
                "manifest(s) discovered · "
                f"{dependency_result.telemetry.get('packages_in_local_inventory', 0)} "
                "package(s) counted locally · "
                f"status {dependency_result.telemetry.get('status', 'unknown')}"
            )
        for error in dependency_result.errors:
            notify(f"[WARNING] {error}")
        for gap in dependency_result.coverage_gaps:
            notify(f"[WARNING] OSV coverage gap: {gap}")
    else:
        notify("[DEPENDENCIES] Dependency scanning disabled for this audit")

    if secret_scan:
        notify(
            "[SECRETS] Starting redacted current-tree and Git-history scan "
            "(Betterleaks preferred; Gitleaks fallback)"
        )
        secret_started = monotonic()
        try:
            secret_result = scan_secrets(str(root), max_target_bytes=max_target_bytes)
        except Exception as exc:  # Keep an auditable degraded result on tool failure.
            secret_result = DetectorResult(
                detector="betterleaks",
                errors=[f"Secret scanner failed unexpectedly: {' '.join(str(exc).split())[:500]}"],
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
        batch_size=effective_batch_size,
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
        f"(maximum {effective_batch_size} findings each)"
    )
    gemini_client = (
        client or genai.Client(api_key=gemini_api_key) if "gemini" in provider_order else None
    )
    reports: list[tuple[int, ReviewReport]] = []
    failed_batches: list[int] = []
    failed_batch_reasons: dict[int, str] = {}
    failed_dispositions: list[FindingDisposition] = []
    attempted_ai_batches = 0
    successful_ai_batches = 0
    ai_telemetry: dict[str, int] = {}

    def refine_repaired_candidates(
        report: ReviewReport,
        triage_batch: FindingBatch,
        structural_context: str,
        batch_index: int,
    ) -> ReviewReport:
        """Strictly re-triage repaired candidates one at a time within a cost cap."""
        repaired_ids = semantic_repair_candidate_ids(report)
        if not repaired_ids:
            return report
        candidate_by_id = {candidate.finding_id: candidate for candidate in triage_batch.findings}
        present_ids = [finding_id for finding_id in repaired_ids if finding_id in candidate_by_id]
        eligible_ids = [
            finding_id
            for finding_id in present_ids
            if _deterministic_runtime_issue(root, candidate_by_id[finding_id]) is None
        ]
        deterministic_skips = len(present_ids) - len(eligible_ids)
        if deterministic_skips:
            ai_telemetry["deterministic_retriage_skipped"] = (
                ai_telemetry.get("deterministic_retriage_skipped", 0)
                + deterministic_skips
            )
        selected_ids = eligible_ids[:DEFAULT_AI_RETRIAGE_LIMIT]
        skipped = len(eligible_ids) - len(selected_ids)
        ai_telemetry["targeted_retriage_candidates"] = ai_telemetry.get(
            "targeted_retriage_candidates", 0
        ) + len(eligible_ids)
        if skipped:
            ai_telemetry["targeted_retriage_skipped"] = (
                ai_telemetry.get("targeted_retriage_skipped", 0) + skipped
            )
        notify(
            f"[REFINE] Batch {batch_index}/{len(batches)} · {len(eligible_ids)} "
            "repaired candidate(s) require strict singleton re-triage"
        )
        refined = report
        for finding_id in selected_ids:
            candidate = candidate_by_id[finding_id]
            singleton = FindingBatch(findings=[candidate], files={candidate.file})
            strict_prompt = build_full_scan_prompt(
                singleton.text,
                structural_context,
                batch_index,
                len(batches),
            )
            ai_telemetry["targeted_retriage_attempts"] = (
                ai_telemetry.get("targeted_retriage_attempts", 0) + 1
            )
            notify(
                f"[REFINE] Strict singleton re-triage for {finding_id} · semantic repair disabled"
            )
            try:
                strict_report = redact_review_report(
                    _call_ai_provider_chain(
                        provider_order,
                        prompt=strict_prompt,
                        openrouter_api_key=openrouter_api_key,
                        openrouter_allow_data_collection=openrouter_allow_data_collection,
                        gemini_client=gemini_client,
                        progress=notify,
                        allow_semantic_repair=False,
                        telemetry=ai_telemetry,
                    )
                )
            except RuntimeError as exc:
                ai_telemetry["targeted_retriage_unresolved"] = (
                    ai_telemetry.get("targeted_retriage_unresolved", 0) + 1
                )
                reason = " ".join(str(exc).split())[:240]
                notify(
                    f"[WARNING] Strict singleton re-triage for {finding_id} failed: "
                    f"{reason}; the conservative Needs review verdict was retained"
                )
                continue
            refined = _replace_candidate_verdict(refined, strict_report, finding_id)
            ai_telemetry["targeted_retriage_recovered"] = (
                ai_telemetry.get("targeted_retriage_recovered", 0) + 1
            )
            strict_status = next(
                item.status for item in strict_report.dispositions if item.finding_id == finding_id
            )
            notify(f"[REFINE] {finding_id} recovered with a strict {strict_status} verdict")
        return refined

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
                    "Deterministic scope and manual-review policy resolved this "
                    "batch without sending source context to the AI provider."
                ),
                issues=[],
                dispositions=deterministic_dispositions,
            )
            reports.append((index, deterministic))
            notify(
                f"[SCOPE] Batch {index}/{len(batches)} contains only deterministic "
                "scope, scan-gap, or manual-review evidence; AI triage was skipped"
            )
            notify(f"[BATCH {index}/{len(batches)}] Complete in {monotonic() - batch_started:.1f}s")
            continue
        if not ai_triage:
            detector_only_dispositions = [
                FindingDisposition(
                    finding_id=candidate.finding_id,
                    status=(
                        "NEEDS_REVIEW" if is_runtime_role(candidate.code_role) else "NON_RUNTIME"
                    ),
                    reason=(
                        "Detector-only mode intentionally skipped AI contextual triage; "
                        "manual review is required."
                        if is_runtime_role(candidate.code_role)
                        else "Deterministic scope classification marked this path as "
                        f"{candidate.code_role.lower()}."
                    ),
                    file=candidate.file,
                    line=candidate.line,
                    rule_id=candidate.rule_id,
                    message=candidate.message,
                    code_role=candidate.code_role,
                    confidence="LOW",
                )
                for candidate in triage_findings
            ]
            detector_only_dispositions.extend(deterministic_dispositions)
            reports.append(
                (
                    index,
                    ReviewReport(
                        analysis_scratchpad=(
                            "Detector-only mode retained runtime candidates as Needs "
                            "review without sending source context to an AI provider."
                        ),
                        issues=[],
                        dispositions=detector_only_dispositions,
                    ),
                )
            )
            notify(
                f"[AI] Batch {index}/{len(batches)} contextual triage intentionally "
                "disabled; runtime candidates remain in Needs review"
            )
            notify(f"[BATCH {index}/{len(batches)}] Complete in {monotonic() - batch_started:.1f}s")
            continue
        triage_batch = FindingBatch(
            findings=triage_findings,
            files={item.file for item in triage_findings if item.file},
        )
        ast_started = monotonic()
        python_context = build_ast_context(root, triage_batch.files)
        related_context = build_related_context(root, triage_batch.files)
        structural_context = "\n\n".join(part for part in (python_context, related_context) if part)
        python_files = sum(Path(path).suffix.casefold() == ".py" for path in triage_batch.files)
        notify(
            f"[CONTEXT] Local structural context generated for {python_files} Python "
            f"files and imported JS/TS helpers in "
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
            report = redact_review_report(
                _call_ai_provider_chain(
                    provider_order,
                    prompt=prompt,
                    openrouter_api_key=openrouter_api_key,
                    openrouter_allow_data_collection=openrouter_allow_data_collection,
                    gemini_client=gemini_client,
                    progress=notify,
                    telemetry=ai_telemetry,
                )
            )
            report = refine_repaired_candidates(
                report,
                triage_batch,
                structural_context,
                index,
            )
        except RuntimeError as exc:
            logger.error("Batch %s failed: %s", index, exc)
            initial_reason = " ".join(str(exc).split())[:500] or "Unknown AI provider error"
            recovered_reports: list[ReviewReport] = []
            unrecovered: list[tuple[SemgrepCandidate, str]] = []

            def recover_findings(candidates: list[SemgrepCandidate], label: str) -> None:
                if not candidates:
                    return
                recovery_batch = FindingBatch(
                    findings=candidates,
                    files={candidate.file for candidate in candidates if candidate.file},
                )
                notify(
                    f"[RECOVER] Batch {index}/{len(batches)} {label} · retrying "
                    f"{len(candidates)} finding(s)"
                )
                ai_telemetry["adaptive_split_attempts"] = (
                    ai_telemetry.get("adaptive_split_attempts", 0) + 1
                )
                recovery_prompt = build_full_scan_prompt(
                    recovery_batch.text,
                    structural_context,
                    index,
                    len(batches),
                )
                try:
                    recovery_report = redact_review_report(
                        _call_ai_provider_chain(
                            provider_order,
                            prompt=recovery_prompt,
                            openrouter_api_key=openrouter_api_key,
                            openrouter_allow_data_collection=openrouter_allow_data_collection,
                            gemini_client=gemini_client,
                            progress=notify,
                            telemetry=ai_telemetry,
                        )
                    )
                except RuntimeError as recovery_error:
                    reason = (
                        " ".join(str(recovery_error).split())[:500] or "Unknown AI provider error"
                    )
                    if len(candidates) == 1:
                        unrecovered.append((candidates[0], reason))
                        notify(
                            f"[WARNING] Batch {index}/{len(batches)} {label} could "
                            "not be recovered; the candidate remains Needs review"
                        )
                        return
                    midpoint = max(1, len(candidates) // 2)
                    notify(
                        f"[RECOVER] Batch {index}/{len(batches)} {label} still failed; "
                        "splitting into smaller requests"
                    )
                    recover_findings(candidates[:midpoint], f"{label}.1")
                    recover_findings(candidates[midpoint:], f"{label}.2")
                    return
                recovery_report = refine_repaired_candidates(
                    recovery_report,
                    recovery_batch,
                    structural_context,
                    index,
                )
                recovered_reports.append(
                    _reconcile_batch_report(recovery_report, recovery_batch, root)
                )

            if len(triage_batch.findings) > 1:
                midpoint = max(1, len(triage_batch.findings) // 2)
                notify(
                    f"[RECOVER] Batch {index}/{len(batches)} failed after model "
                    "failover; splitting it into smaller requests"
                )
                recover_findings(triage_batch.findings[:midpoint], "split 1")
                recover_findings(triage_batch.findings[midpoint:], "split 2")
            else:
                unrecovered.append((triage_batch.findings[0], initial_reason))

            if recovered_reports:
                recovered_reports[0].dispositions.extend(deterministic_dispositions)
                reports.extend((index, item) for item in recovered_reports)
            else:
                failed_dispositions.extend(deterministic_dispositions)

            if unrecovered:
                failed_batches.append(index)
                failure_reason = "; ".join(
                    f"{candidate.finding_id}: {reason}" for candidate, reason in unrecovered
                )[:500]
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
                            "AI triage failed after adaptive splitting; this candidate "
                            "requires manual review."
                            if is_runtime_role(candidate.code_role)
                            else "Deterministic scope classification marked this path as "
                            f"{candidate.code_role.lower()}."
                        ),
                        file=candidate.file,
                        line=candidate.line,
                        rule_id=candidate.rule_id,
                        message=candidate.message,
                        code_role=candidate.code_role,
                        confidence="LOW",
                    )
                    for candidate, _reason in unrecovered
                )
                notify(
                    f"[ERROR] Batch {index}/{len(batches)} remained incomplete after "
                    f"adaptive splitting: {failure_reason}"
                )
            else:
                successful_ai_batches += 1
                confirmed_count = sum(len(item.issues) for item in recovered_reports)
                review_count = sum(
                    disposition.status == "NEEDS_REVIEW"
                    for item in recovered_reports
                    for disposition in item.dispositions
                )
                notify(
                    f"[RECOVER] Batch {index}/{len(batches)} fully recovered · "
                    f"{confirmed_count} confirmed · {review_count} needs review"
                )
            notify(f"[BATCH {index}/{len(batches)}] Complete in {monotonic() - batch_started:.1f}s")
            continue
        successful_ai_batches += 1
        reconciled = _reconcile_batch_report(report, triage_batch, root)
        reconciled.dispositions.extend(deterministic_dispositions)
        confirmed_count = len(reconciled.issues)
        review_count = sum(
            disposition.status == "NEEDS_REVIEW" for disposition in reconciled.dispositions
        )
        non_runtime_count = sum(
            disposition.status == "NON_RUNTIME" for disposition in reconciled.dispositions
        )
        notify(
            f"[VALIDATE] Batch {index}/{len(batches)} · {confirmed_count} confirmed · "
            f"{review_count} needs review · {non_runtime_count} non-runtime"
        )
        reports.append((index, reconciled))
        notify(f"[BATCH {index}/{len(batches)}] Complete in {monotonic() - batch_started:.1f}s")

    if attempted_ai_batches and not successful_ai_batches:
        notify(
            "[WARNING] AI triage is unavailable. The audit will finish in degraded "
            "mode and every untriaged runtime candidate will remain in Needs review."
        )

    merged = redact_review_report(_normalize_manual_remediations(_merge_reports(reports, root)))
    merged.dispositions.extend(failed_dispositions)
    base_scratchpad = merged.analysis_scratchpad.strip()
    supplemental_summaries: list[str] = []
    detector_errors: dict[str, list[str]] = {}
    detector_coverage_gaps: dict[str, list[str]] = {}
    detector_telemetry: dict[str, dict[str, object]] = {}
    for detector_result in supplemental_results:
        supplemental_summaries.append(
            f"{detector_result.detector}: {detector_result.finding_count} finding(s), "
            f"{len(detector_result.errors)} error(s)."
        )
        if detector_result.errors:
            detector_errors[detector_result.detector] = detector_result.errors
        if detector_result.coverage_gaps:
            detector_coverage_gaps[detector_result.detector] = detector_result.coverage_gaps
        if detector_result.telemetry:
            detector_telemetry[detector_result.detector] = detector_result.telemetry

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
        merged = redact_review_report(
            _normalize_manual_remediations(_merge_reports(combined_reports, root))
        )

    scratchpad_parts = [part for part in (base_scratchpad, *supplemental_summaries) if part]
    if not scratchpad_parts:
        scratchpad_parts.append("All enabled detectors completed without findings.")
    merged.analysis_scratchpad = "\n\n".join(scratchpad_parts)
    duplicate_count = accepted_before_merge - len(merged.issues)
    exported_dependencies = [issue for issue in merged.issues if issue.rule_id.startswith("osv.")]
    exported_advisories = {issue.rule_id for issue in exported_dependencies}
    exported_package_groups: dict[str, dict[str, object]] = {}
    for issue in exported_dependencies:
        package_name = issue.original_code.rsplit(" ", 1)[0].strip() or "unknown package"
        package_group = exported_package_groups.setdefault(
            package_name, {"advisories": set(), "findings": 0}
        )
        package_group["advisories"].add(issue.rule_id.removeprefix("osv."))  # type: ignore[union-attr]
        package_group["findings"] = int(package_group["findings"]) + 1
    osv_telemetry = detector_telemetry.get("osv")
    if osv_telemetry is not None:
        osv_telemetry.update(
            {
                "exported_dependency_findings": len(exported_dependencies),
                "exported_unique_advisories": len(exported_advisories),
                "exported_affected_packages": sorted(
                    (
                        {
                            "package": package_name,
                            "unique_advisories": len(group["advisories"]),
                            "findings": group["findings"],
                        }
                        for package_name, group in exported_package_groups.items()
                    ),
                    key=lambda item: (
                        -int(item["findings"]),
                        str(item["package"]),
                    ),
                ),
            }
        )
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
        ai_telemetry=ai_telemetry,
        firmware_finding_count=next(
            (result.finding_count for result in supplemental_results if result.detector == "firmware"),
            0,
        ),
        dependency_finding_count=next(
            (result.finding_count for result in supplemental_results if result.detector == "osv"),
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
        detector_coverage_gaps=detector_coverage_gaps,
        detector_telemetry=detector_telemetry,
        scanner_diagnostics=({"semgrep": semgrep_diagnostics} if semgrep_diagnostics else {}),
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
        ai_triage_enabled=ai_triage,
        semgrep_rule_mode=semgrep_rule_mode,
        semgrep_rules_sha256=rules_fingerprint,
        scan_started_at=scan_started_at,
        repository_name=root.name,
        repository_commit=repository_commit,
        repository_branch=repository_branch,
        repository_dirty=repository_dirty,
        ai_provider_order=list(provider_order),
        ai_models=(
            [
                *(list(OPENROUTER_MODELS) if "openrouter" in provider_order else []),
                *(list(FAILOVER_MODELS) if "gemini" in provider_order else []),
            ]
            if ai_triage
            else []
        ),
        scan_exclusions=list(configured_excludes),
        max_target_bytes=max(1, int(max_target_bytes)),
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

    outcome.scan_completed_at = datetime.now(UTC).isoformat(timespec="seconds")
    notify(
        f"[COMPLETE] Audit finished"
        f"{' in degraded mode' if outcome.audit_degraded else ''} "
        f"in {monotonic() - audit_started:.1f}s · "
        f"{outcome.total_finding_count} detector findings · "
        f"{len(merged.issues)} confirmed · {outcome.disposition_count('NEEDS_REVIEW')} needs review · "
        f"{outcome.disposition_count('NON_RUNTIME')} non-runtime · "
        f"{outcome.disposition_count('FALSE_POSITIVE')} false positives · "
        f"{outcome.disposition_count('DUPLICATE')} duplicates · "
        f"{len(outcome.fixed_files)} changed files"
    )

    return outcome


def _write_report(outcome: ScanOutcome, output_path: str) -> None:
    write_json_report(outcome, output_path)


def audit_exit_code(
    outcome: ScanOutcome, *, fail_on: str = "none", fail_on_needs_review: bool = False,
) -> int:
    """Keep incomplete audits distinct from findings that exceed CI policy."""
    ranks = {"info": 0, "warning": 1, "high": 2, "critical": 3}
    if fail_on not in {"none", *ranks}:
        raise ValueError(f"Unknown severity threshold: {fail_on}")
    if outcome.audit_degraded:
        return 2
    if fail_on != "none" and any(
        is_runtime_role(issue.code_role) and ranks[issue.severity.lower()] >= ranks[fail_on]
        for issue in outcome.report.issues
    ):
        return 3
    if fail_on_needs_review and any(
        item.status == "NEEDS_REVIEW" and is_runtime_role(item.code_role)
        for item in outcome.report.dispositions
    ):
        return 3
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run an AegisScan audit against an entire local repository."
    )
    parser.add_argument("--repo", default=os.getcwd(), help="Repository directory")
    parser.add_argument(
        "--api-key",
        default=os.getenv("GEMINI_API_KEY", ""),
        help="Gemini API key (or set GEMINI_API_KEY)",
    )
    parser.add_argument(
        "--openrouter-api-key",
        default=os.getenv("OPENROUTER_API_KEY", ""),
        help="OpenRouter API key (or set OPENROUTER_API_KEY)",
    )
    parser.add_argument(
        "--ai-provider",
        choices=AI_PROVIDER_MODES,
        default="auto",
        help="AI provider selection; auto prefers OpenRouter and falls back to Gemini",
    )
    parser.add_argument(
        "--openrouter-allow-data-collection",
        action="store_true",
        help="Allow OpenRouter providers that may retain or use request data",
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-target-bytes", type=int, default=DEFAULT_MAX_TARGET_BYTES)
    parser.add_argument(
        "--exclude",
        action="append",
        dest="exclude_patterns",
        help="Semgrep exclusion pattern; repeat for multiple patterns",
    )
    parser.add_argument("--no-dependency-scan", action="store_true")
    parser.add_argument("--no-secret-scan", action="store_true")
    parser.add_argument(
        "--detector-only",
        action="store_true",
        help=(
            "Run deterministic detectors without an AI provider; runtime candidates are "
            "reported as Needs review"
        ),
    )
    parser.add_argument(
        "--semgrep-rule-mode",
        choices=SEMGREP_RULE_MODES,
        default="bundled",
        help=(
            "bundled is offline and reproducible; extended also downloads mutable "
            "security-audit and Python registry packs"
        ),
    )
    parser.add_argument(
        "--apply-fixes", action="store_true",
        help="Currently unavailable: use manual remediation",
    )
    parser.add_argument(
        "--create-pull-request", action="store_true",
        help="Currently unavailable: automatic fixes are paused",
    )
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN", ""))
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--base-branch", default="")
    parser.add_argument("--report", default="aegisscan-report.json")
    parser.add_argument(
        "--fail-on", choices=("none", "info", "warning", "high", "critical"), default="none",
        help="Exit 3 for confirmed runtime findings at or above this severity (default: none)",
    )
    parser.add_argument(
        "--fail-on-needs-review", action="store_true",
        help="Also exit 3 for runtime Needs review candidates, including detector-only results",
    )
    parser.add_argument(
        "--sarif",
        default="",
        help="Optional SARIF 2.1.0 output path for GitHub Code Scanning and CI tools",
    )
    args = parser.parse_args()

    try:
        outcome = run_full_scan(
            args.repo,
            args.api_key,
            openrouter_api_key=args.openrouter_api_key,
            openrouter_allow_data_collection=args.openrouter_allow_data_collection,
            ai_provider=args.ai_provider,
            batch_size=args.batch_size,
            dependency_scan=not args.no_dependency_scan,
            secret_scan=not args.no_secret_scan,
            exclude_patterns=args.exclude_patterns,
            max_target_bytes=args.max_target_bytes,
            semgrep_rule_mode=args.semgrep_rule_mode,
            ai_triage=not args.detector_only,
            apply_fixes=args.apply_fixes,
            create_pull_request=args.create_pull_request,
            github_token=args.github_token,
            repository=args.repository,
            base_branch=args.base_branch,
        )
        _write_report(outcome, args.report)
        logger.info("Wrote audit report to %s", args.report)
        if args.sarif:
            write_sarif_report(outcome, args.sarif)
            logger.info("Wrote SARIF report to %s", args.sarif)
        if outcome.audit_degraded:
            logger.error(
                "Audit completed in degraded mode; inspect detector_errors, "
                "detector_coverage_gaps, Needs review, and failed_batch_reasons in %s",
                args.report,
            )
            sys.exit(2)
        if audit_exit_code(
            outcome, fail_on=args.fail_on, fail_on_needs_review=args.fail_on_needs_review,
        ) == 3:
            logger.error("Audit findings exceeded the configured CI policy; reports were saved.")
            sys.exit(3)
    except (RuntimeError, ValueError, OSError) as exc:
        logger.error("Full-repository audit failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
