"""Central, defense-in-depth redaction for prompts, UI state, and exports."""

from __future__ import annotations

import math
import re
from collections import Counter

from .models import FindingDisposition, ReviewIssue, ReviewReport


REDACTED_SECRET = "[REDACTED SECRET]"

_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?:[ _-](?:RSA|EC|DSA|OPENSSH))?[ _-]PRIVATE[ _-]KEY-----"
    r".*?"
    r"-----END(?:[ _-](?:RSA|EC|DSA|OPENSSH))?[ _-]PRIVATE[ _-]KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_PEM_PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN(?:[ _-](?:RSA|EC|DSA|OPENSSH))?[ _-]PRIVATE[ _-]KEY-----",
    re.IGNORECASE,
)
_KNOWN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{20,}|"
    r"gh[pousr]_[0-9A-Za-z]{20,}|"
    r"github_pat_[0-9A-Za-z_]{20,}|"
    r"sk_(?:live|test)_[0-9A-Za-z]{16,}|"
    r"xox[baprs]-[0-9A-Za-z-]{16,}"
    r")(?![A-Za-z0-9])"
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\."
    r"[0-9A-Za-z_-]{8,}(?![A-Za-z0-9_-])"
)
_NAMED_SECRET = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"private[_-]?key|secret|password|passwd|pwd)\b\s*(?:=|:)\s*)"
    r"(?P<quote>['\"`])[^'\"`\r\n]+(?P=quote)"
)
_HMAC_SECRET = re.compile(
    r"(?i)(\bcreateHmac\s*\(\s*['\"][^'\"]+['\"]\s*,\s*)"
    r"(?P<quote>['\"`])[^'\"`\r\n]+(?P=quote)"
)
_BASIC_AUTH_URL = re.compile(
    r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s/@]+@",
    re.IGNORECASE,
)
_QUOTED_TOKEN = re.compile(r"(?P<quote>['\"`])(?P<value>[A-Za-z0-9_+/=.-]{24,})(?P=quote)")


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact_quoted_token(match: re.Match[str]) -> str:
    value = match.group("value")
    character_classes = sum(
        (
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        )
    )
    if character_classes < 2 or _entropy(value) < 3.5:
        return match.group(0)
    quote = match.group("quote")
    return f"{quote}{REDACTED_SECRET}{quote}"


def redact_text(value: str) -> str:
    """Remove credential material while retaining enough structure for triage."""
    if not value:
        return value
    redacted = _PEM_PRIVATE_KEY.sub(REDACTED_SECRET, value)
    redacted = _PEM_PRIVATE_KEY_HEADER.sub(REDACTED_SECRET, redacted)
    redacted = _KNOWN_TOKEN.sub(REDACTED_SECRET, redacted)
    redacted = _JWT.sub(REDACTED_SECRET, redacted)
    redacted = _NAMED_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group('quote')}{REDACTED_SECRET}{match.group('quote')}",
        redacted,
    )
    redacted = _HMAC_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group('quote')}{REDACTED_SECRET}{match.group('quote')}",
        redacted,
    )
    redacted = _BASIC_AUTH_URL.sub(
        lambda match: f"{match.group('prefix')}{REDACTED_SECRET}@",
        redacted,
    )
    return _QUOTED_TOKEN.sub(_redact_quoted_token, redacted)


def _redact_issue(issue: ReviewIssue) -> ReviewIssue:
    return issue.model_copy(
        update={
            field: redact_text(str(getattr(issue, field)))
            for field in (
                "description",
                "original_code",
                "suggested_fix",
                "remediation_guidance",
                "source_evidence",
                "sink_evidence",
                "reachability_evidence",
            )
        }
    )


def _redact_disposition(disposition: FindingDisposition) -> FindingDisposition:
    return disposition.model_copy(
        update={
            "reason": redact_text(disposition.reason),
            "message": redact_text(disposition.message),
        }
    )


def redact_review_report(report: ReviewReport) -> ReviewReport:
    """Return a scrubbed copy suitable for retention outside repository files."""
    return report.model_copy(
        update={
            "analysis_scratchpad": redact_text(report.analysis_scratchpad),
            "issues": [_redact_issue(issue) for issue in report.issues],
            "dispositions": [
                _redact_disposition(disposition)
                for disposition in report.dispositions
            ],
        }
    )
