"""Privacy-conscious persistent audit summaries and finding comparisons."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


MAX_HISTORY_ENTRIES = 100


def _fingerprint(*parts: object) -> str:
    canonical = "\0".join(str(part).strip() for part in parts)
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:24]


def actionable_fingerprints(outcome: Any) -> set[str]:
    """Return opaque identities for confirmed and needs-review findings."""
    fingerprints: set[str] = set()
    for issue in outcome.report.issues:
        identity = issue.finding_id or _fingerprint(
            issue.rule_id,
            issue.sink_file or issue.file,
            issue.sink_line or issue.line,
            issue.issue_name,
        )
        fingerprints.add(_fingerprint(identity))
    for disposition in outcome.report.dispositions:
        if disposition.status != "NEEDS_REVIEW":
            continue
        identity = disposition.finding_id or _fingerprint(
            disposition.rule_id,
            disposition.file,
            disposition.line,
            disposition.message,
        )
        fingerprints.add(_fingerprint(identity))
    return fingerprints


def compare_fingerprints(
    current: Iterable[str], previous: Iterable[str]
) -> dict[str, int]:
    current_set = set(current)
    previous_set = set(previous)
    return {
        "new": len(current_set - previous_set),
        "resolved": len(previous_set - current_set),
        "unchanged": len(current_set & previous_set),
    }


def latest_completed_entry(
    entries: Iterable[dict[str, object]], repository: str
) -> dict[str, object] | None:
    canonical_repository = str(Path(repository).expanduser().resolve())
    for entry in reversed(list(entries)):
        if entry.get("status") == "Failed":
            continue
        raw_repository = str(entry.get("repository", ""))
        try:
            entry_repository = str(Path(raw_repository).expanduser().resolve())
        except (OSError, RuntimeError):
            continue
        if entry_repository == canonical_repository and isinstance(
            entry.get("fingerprints"), list
        ):
            return entry
    return None


def build_history_entry(
    outcome: Any,
    repository: str,
    previous: dict[str, object] | None = None,
    *,
    timestamp: datetime | None = None,
) -> dict[str, object]:
    fingerprints = sorted(actionable_fingerprints(outcome))
    previous_fingerprints = (
        [str(item) for item in previous.get("fingerprints", [])]
        if previous is not None and isinstance(previous.get("fingerprints"), list)
        else []
    )
    comparison = compare_fingerprints(fingerprints, previous_fingerprints)
    completed_at = timestamp or datetime.now(UTC)
    return {
        "timestamp": completed_at.astimezone(UTC).isoformat(timespec="seconds"),
        "repository": str(Path(repository).expanduser().resolve()),
        "findings": outcome.total_finding_count,
        "batches": outcome.batch_count,
        "issues": len(outcome.report.issues),
        "needs_review": outcome.disposition_count("NEEDS_REVIEW"),
        "non_runtime": outcome.disposition_count("NON_RUNTIME"),
        "duplicates": outcome.disposition_count("DUPLICATE"),
        "status": "Needs review" if outcome.audit_degraded else "Completed",
        "audit_mode": "AI triage" if outcome.ai_triage_enabled else "Detector only",
        "fingerprints": fingerprints,
        "comparison": comparison,
    }


def build_failure_entry(
    repository: str, *, timestamp: datetime | None = None
) -> dict[str, object]:
    completed_at = timestamp or datetime.now(UTC)
    return {
        "timestamp": completed_at.astimezone(UTC).isoformat(timespec="seconds"),
        "repository": str(Path(repository).expanduser().resolve()),
        "findings": "—",
        "batches": "—",
        "issues": "—",
        "needs_review": "—",
        "non_runtime": "—",
        "status": "Failed",
        "audit_mode": "—",
        "fingerprints": [],
        "comparison": {"new": "—", "resolved": "—", "unchanged": "—"},
    }


def load_history(raw_value: object) -> list[dict[str, object]]:
    """Parse stored summaries defensively; malformed preferences become empty."""
    if not raw_value:
        return []
    try:
        payload = json.loads(str(raw_value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    entries = [entry for entry in payload if isinstance(entry, dict)]
    return entries[-MAX_HISTORY_ENTRIES:]


def dump_history(entries: Iterable[dict[str, object]]) -> str:
    return json.dumps(list(entries)[-MAX_HISTORY_ENTRIES:], separators=(",", ":"))
