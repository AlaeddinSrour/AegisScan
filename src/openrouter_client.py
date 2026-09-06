"""OpenRouter client with strict ReviewReport output and bounded retries."""

from __future__ import annotations

import logging
import json
import os
import queue
import re
import threading
import time
from typing import Callable

import requests

from .models import FindingDisposition, ReviewIssue, ReviewReport
from .ai_budget import AIBudgetExceeded, RequestBudget, ensure_budget, timed_request

logger = logging.getLogger(__name__)

OPENROUTER_API_URL = os.environ.get(
    "AEGISSCAN_OPENROUTER_URL",
    "https://openrouter.ai/api/v1/chat/completions",
)
OPENROUTER_MODELS = [
    model.strip()
    for model in os.environ.get(
        "AEGISSCAN_OPENROUTER_MODELS",
        "deepseek/deepseek-v4-flash",
    ).split(",")
    if model.strip()
]
MAX_FINDINGS_PER_BATCH = int(os.environ.get("AEGISSCAN_OPENROUTER_MAX_FINDINGS_PER_BATCH", "3"))
MAX_RETRIES = int(os.environ.get("AEGISSCAN_OPENROUTER_MAX_RETRIES", "3"))
API_TIMEOUT_SECONDS = int(os.environ.get("AEGISSCAN_OPENROUTER_TIMEOUT", "180"))
MULTI_FINDING_TIMEOUT_SECONDS = max(
    1,
    int(os.environ.get("AEGISSCAN_OPENROUTER_MULTI_TIMEOUT", "90")),
)
MAX_OUTPUT_TOKENS = int(os.environ.get("AEGISSCAN_OPENROUTER_MAX_OUTPUT_TOKENS", "16384"))
INITIAL_BACKOFF_SECONDS = int(os.environ.get("AEGISSCAN_OPENROUTER_INITIAL_BACKOFF", "15"))

SEMANTIC_REPAIR_REASON_MARKERS = (
    "deterministic repair retained",
    "model omitted this candidate",
    "invalid duplicate reference",
)


class OpenRouterRequestError(RuntimeError):
    """Provider failure with an optional HTTP status for retry policy."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class OpenRouterDeadlineExceeded(OpenRouterRequestError):
    """A hard wall-clock deadline expired regardless of socket activity."""


class OpenRouterSemanticError(OpenRouterRequestError):
    """The provider responded, but its structured content could not be parsed."""


def _post_with_deadline(*, deadline_seconds: float, **kwargs: object) -> requests.Response:
    """Bound requests by wall-clock time, not only per-socket inactivity."""
    completed: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def request() -> None:
        try:
            completed.put((True, requests.post(**kwargs)))
        except Exception as exc:
            completed.put((False, exc))

    worker = threading.Thread(
        target=request,
        name="aegisscan-openrouter-request",
        daemon=True,
    )
    worker.start()
    worker.join(deadline_seconds)
    if worker.is_alive():
        raise OpenRouterDeadlineExceeded(
            f"OpenRouter exceeded the {deadline_seconds:g}s wall-clock deadline."
        )
    succeeded, value = completed.get_nowait()
    if not succeeded:
        if isinstance(value, Exception):
            raise value
        raise OpenRouterRequestError("OpenRouter request failed without an exception.")
    if not isinstance(value, requests.Response):
        # Test doubles and compatible requests adapters implement the same response
        # surface without necessarily inheriting from requests.Response.
        return value  # type: ignore[return-value]
    return value


def _safe_error_summary(error: Exception, limit: int = 240) -> str:
    summary = " ".join(str(error).split()) or type(error).__name__
    summary = re.sub(r"(?i)(authorization:\s*bearer\s+)\S+", r"\1[REDACTED]", summary)
    summary = re.sub(r"sk-or-v1-[0-9A-Za-z_-]+", "[REDACTED_API_KEY]", summary)
    return summary[:limit]


def _response_error(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    if isinstance(error, dict):
        message = str(error.get("message") or error.get("code") or "").strip()
        if message:
            return f"HTTP {response.status_code}: {message}"
    return f"HTTP {response.status_code}"


def _is_retryable(error: Exception) -> bool:
    if isinstance(error, OpenRouterDeadlineExceeded):
        # The underlying daemon request may still be draining at the socket layer.
        # Do not create more concurrent requests for the same audit batch.
        return False
    status_code = getattr(error, "status_code", None)
    if status_code is None:
        return True
    return status_code in {408, 409, 429} or status_code >= 500


def _structured_content(message: dict[str, object]) -> object:
    parsed = message.get("parsed")
    if isinstance(parsed, dict):
        return parsed
    content = message.get("content")
    if isinstance(content, list):
        content = "".join(
            str(part.get("text", ""))
            for part in content
            if isinstance(part, dict) and part.get("type") in {None, "text"}
        )
    if not isinstance(content, str) or not content.strip():
        return content
    cleaned = content.strip()
    fence = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", cleaned, flags=re.DOTALL | re.I)
    if fence:
        cleaned = fence.group(1)
    return json.loads(cleaned)


def _normalized_model_item(model: type[ReviewIssue] | type[FindingDisposition], item: object):
    """Conservatively normalize common provider transport defects."""
    if not isinstance(item, dict):
        return None
    cleaned = {key: value for key, value in item.items() if key in model.model_fields}
    for key in (
        "severity",
        "status",
        "confidence",
        "code_role",
        "evidence_scope",
        "remediation_type",
    ):
        value = cleaned.get(key)
        if isinstance(value, str):
            cleaned[key] = re.sub(r"[\s-]+", "_", value.strip()).upper()
    for key in ("line", "sink_line", "occurrence_count"):
        value = cleaned.get(key)
        if isinstance(value, str) and value.strip().isdigit():
            cleaned[key] = int(value)
    for key in ("related_weaknesses", "commits"):
        if key in model.model_fields and cleaned.get(key) is None:
            cleaned[key] = []
    try:
        return model.model_validate(cleaned)
    except (TypeError, ValueError):
        return None


def _coerce_review_report(content: object) -> ReviewReport:
    if not isinstance(content, dict):
        raise ValueError("OpenRouter returned a non-object structured response.")
    raw_issues = content.get("issues", [])
    raw_dispositions = content.get("dispositions", [])
    if isinstance(raw_issues, dict):
        raw_issues = [raw_issues]
    if isinstance(raw_dispositions, dict):
        raw_dispositions = [raw_dispositions]
    issues = [
        normalized
        for item in raw_issues if isinstance(raw_issues, list)
        if (normalized := _normalized_model_item(ReviewIssue, item)) is not None
    ]
    dispositions = [
        normalized
        for item in raw_dispositions if isinstance(raw_dispositions, list)
        if (normalized := _normalized_model_item(FindingDisposition, item)) is not None
    ]
    scratchpad = content.get("analysis_scratchpad", "Provider response normalized locally.")
    if not isinstance(scratchpad, str):
        scratchpad = "Provider response normalized locally."
    return ReviewReport(
        analysis_scratchpad=scratchpad,
        issues=issues,
        dispositions=dispositions,
    )


def _parse_review_report(payload: object) -> ReviewReport:
    if not isinstance(payload, dict):
        raise ValueError("OpenRouter returned a non-object response.")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("OpenRouter returned no completion choices.")
    choice = choices[0]
    message = choice.get("message", {}) if isinstance(choice, dict) else {}
    content = _structured_content(message) if isinstance(message, dict) else None
    if content is None or content == "":
        raise ValueError("OpenRouter returned an empty structured response.")
    return _coerce_review_report(content)


def _report_completeness_error(report: ReviewReport, prompt: str) -> str:
    """Return a retryable reason when a structured report is semantically incomplete."""
    expected_ids = set(re.findall(r"(?m)^Candidate ID:\s*(\S+)\s*$", prompt))
    if not expected_ids:
        return ""
    dispositions = {item.finding_id: item for item in report.dispositions}
    if len(dispositions) != len(report.dispositions):
        return "ReviewReport contains duplicate candidate disposition IDs."
    missing = sorted(expected_ids - dispositions.keys())
    unexpected = sorted(dispositions.keys() - expected_ids)
    if missing:
        return f"ReviewReport omitted {len(missing)} candidate disposition(s)."
    if unexpected:
        return f"ReviewReport invented {len(unexpected)} candidate disposition(s)."
    confirmed_ids = {item.finding_id for item in report.dispositions if item.status == "CONFIRMED"}
    issue_ids = {issue.finding_id for issue in report.issues}
    if len(issue_ids) != len(report.issues):
        return "ReviewReport contains duplicate confirmed issue IDs."
    if issue_ids != confirmed_ids:
        return "Confirmed dispositions and issue finding IDs do not match."
    for issue in report.issues:
        if (
            issue.confidence == "LOW"
            or not all(
                value.strip()
                for value in (
                    issue.source_evidence,
                    issue.sink_evidence,
                    issue.reachability_evidence,
                    issue.sink_file,
                )
            )
            or issue.sink_line < 1
        ):
            return f"Confirmed issue {issue.finding_id} lacks complete evidence."
    for disposition in report.dispositions:
        if disposition.status != "DUPLICATE":
            continue
        canonical = dispositions.get(disposition.canonical_finding_id)
        if canonical is None or canonical.status != "CONFIRMED":
            return (
                f"Duplicate {disposition.finding_id} does not reference a retained "
                "confirmed candidate."
            )
    return ""


def _repair_review_report(report: ReviewReport, prompt: str) -> tuple[ReviewReport, int]:
    """Repair cross-field semantic defects without promoting uncertain findings."""
    expected_ids = set(re.findall(r"(?m)^Candidate ID:\s*(\S+)\s*$", prompt))
    if not expected_ids:
        return report, 0
    repairs = 0
    issues = {}
    for issue in report.issues:
        if issue.finding_id not in expected_ids:
            repairs += 1
            continue
        current = issues.get(issue.finding_id)
        if current is None:
            issues[issue.finding_id] = issue
        else:
            repairs += 1
            current_evidence = sum(
                len(value.strip())
                for value in (
                    current.source_evidence,
                    current.sink_evidence,
                    current.reachability_evidence,
                )
            )
            new_evidence = sum(
                len(value.strip())
                for value in (
                    issue.source_evidence,
                    issue.sink_evidence,
                    issue.reachability_evidence,
                )
            )
            if new_evidence > current_evidence:
                issues[issue.finding_id] = issue

    dispositions = {}
    for disposition in report.dispositions:
        if disposition.finding_id not in expected_ids:
            repairs += 1
            continue
        if disposition.finding_id in dispositions:
            repairs += 1
            current = dispositions[disposition.finding_id]
            if (
                disposition.finding_id in issues
                and disposition.status == "CONFIRMED"
                and current.status != "CONFIRMED"
            ):
                dispositions[disposition.finding_id] = disposition
            continue
        dispositions[disposition.finding_id] = disposition

    for finding_id in sorted(expected_ids):
        disposition = dispositions.get(finding_id)
        issue = issues.get(finding_id)
        if disposition is None:
            repairs += 1
            dispositions[finding_id] = FindingDisposition(
                finding_id=finding_id,
                status="NEEDS_REVIEW",
                reason=(
                    "The model omitted this candidate; deterministic repair retained "
                    "it for manual review."
                ),
                confidence="LOW",
            )
            issues.pop(finding_id, None)
            continue
        if disposition.status == "CONFIRMED":
            complete = (
                issue is not None
                and issue.confidence != "LOW"
                and all(
                    value.strip()
                    for value in (
                        issue.source_evidence,
                        issue.sink_evidence,
                        issue.reachability_evidence,
                        issue.sink_file,
                    )
                )
                and issue.sink_line > 0
            )
            if not complete:
                repairs += 1
                dispositions[finding_id] = disposition.model_copy(
                    update={
                        "status": "NEEDS_REVIEW",
                        "reason": (
                            "The model's confirmed verdict lacked complete evidence; "
                            "deterministic repair retained it for manual review."
                        ),
                        "confidence": "LOW",
                        "canonical_finding_id": "",
                    }
                )
                issues.pop(finding_id, None)
        else:
            if issue is not None:
                repairs += 1
                issues.pop(finding_id, None)

    for finding_id, disposition in list(dispositions.items()):
        if disposition.status != "DUPLICATE":
            continue
        canonical = dispositions.get(disposition.canonical_finding_id)
        if canonical is None or canonical.status != "CONFIRMED":
            repairs += 1
            dispositions[finding_id] = disposition.model_copy(
                update={
                    "status": "NEEDS_REVIEW",
                    "reason": (
                        "The model supplied an invalid duplicate reference; deterministic "
                        "repair retained this candidate for manual review."
                    ),
                    "confidence": "LOW",
                    "canonical_finding_id": "",
                }
            )

    retained_issues = [
        issue
        for finding_id, issue in issues.items()
        if dispositions[finding_id].status == "CONFIRMED"
    ]
    repaired = report.model_copy(
        update={
            "issues": retained_issues,
            "dispositions": [dispositions[finding_id] for finding_id in sorted(expected_ids)],
        }
    )
    return repaired, repairs


def semantic_repair_candidate_ids(report: ReviewReport) -> list[str]:
    """Return candidates whose verdict was conservatively repaired by this client."""
    return sorted(
        {
            disposition.finding_id
            for disposition in report.dispositions
            if any(
                marker in disposition.reason.casefold() for marker in SEMANTIC_REPAIR_REASON_MARKERS
            )
        }
    )


def _increment_telemetry(telemetry: dict[str, int] | None, key: str, amount: int = 1) -> None:
    if telemetry is not None:
        telemetry[key] = telemetry.get(key, 0) + amount


def _record_usage(telemetry: dict[str, int] | None, payload: object) -> None:
    """Retain aggregate token/cost metadata without retaining provider content."""
    if telemetry is None or not isinstance(payload, dict):
        return
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return
    for provider_key, telemetry_key in (
        ("prompt_tokens", "provider_prompt_tokens"),
        ("completion_tokens", "provider_completion_tokens"),
        ("total_tokens", "provider_total_tokens"),
    ):
        value = usage.get(provider_key)
        if isinstance(value, int) and value >= 0:
            _increment_telemetry(telemetry, telemetry_key, value)
    cost = usage.get("cost")
    if isinstance(cost, (int, float)) and cost >= 0:
        _increment_telemetry(telemetry, "provider_cost_microusd", round(cost * 1_000_000))


def call_openrouter_with_failover(
    api_key: str,
    prompt: str,
    progress: Callable[[str], None] | None = None,
    *,
    allow_data_collection: bool = False,
    allow_semantic_repair: bool = True,
    telemetry: dict[str, int] | None = None,
    budget: RequestBudget | None = None,
) -> ReviewReport:
    """Call configured OpenRouter models without retaining prompt content locally."""
    if not api_key.strip():
        raise RuntimeError("An OpenRouter API key is required.")
    notify = progress or (lambda _message: None)
    failures: dict[str, str] = {}
    schema = ReviewReport.model_json_schema()
    candidate_count = len(set(re.findall(r"(?m)^Candidate ID:\s*(\S+)\s*$", prompt)))
    request_timeout = (
        min(API_TIMEOUT_SECONDS, MULTI_FINDING_TIMEOUT_SECONDS)
        if candidate_count > 1
        else API_TIMEOUT_SECONDS
    )
    request_kind = "multi_finding" if candidate_count > 1 else "singleton"

    for model_name in OPENROUTER_MODELS:
        retry_delay = INITIAL_BACKOFF_SECONDS
        retry_instruction = ""
        for attempt in range(MAX_RETRIES):
            ensure_budget(telemetry, budget)
            try:
                _increment_telemetry(telemetry, "request_attempts")
                _increment_telemetry(telemetry, f"{request_kind}_request_attempts")
                notify(
                    f"[AI] OpenRouter model {model_name} · attempt "
                    f"{attempt + 1}/{MAX_RETRIES} · timeout {request_timeout}s · "
                    f"{candidate_count or 1} candidate(s)"
                )
                with timed_request(telemetry, "openrouter", budget):
                    response = _post_with_deadline(
                        deadline_seconds=request_timeout,
                        url=OPENROUTER_API_URL,
                        headers={
                            "Authorization": f"Bearer {api_key.strip()}",
                            "Content-Type": "application/json",
                            "HTTP-Referer": "https://github.com/AlaeddinSrour/AegisScan",
                            "X-OpenRouter-Title": "AegisScan",
                        },
                        json={
                            "model": model_name,
                            "messages": [
                                {
                                    "role": "user",
                                    "content": prompt + retry_instruction,
                                }
                            ],
                            "max_tokens": MAX_OUTPUT_TOKENS,
                            "temperature": 0,
                            "response_format": {
                                "type": "json_schema",
                                "json_schema": {
                                    "name": "aegisscan_review_report",
                                    "strict": True,
                                    "schema": schema,
                                },
                            },
                            "provider": {
                                "require_parameters": True,
                                "data_collection": ("allow" if allow_data_collection else "deny"),
                            },
                        },
                        timeout=(15, request_timeout),
                    )
                if not response.ok:
                    raise OpenRouterRequestError(_response_error(response), response.status_code)
                try:
                    response_payload = response.json()
                    _record_usage(telemetry, response_payload)
                    report = _parse_review_report(response_payload)
                    repair_count = 0
                    if allow_semantic_repair:
                        report, repair_count = _repair_review_report(report, prompt)
                    completeness_error = _report_completeness_error(report, prompt)
                    if completeness_error:
                        raise OpenRouterSemanticError(completeness_error)
                except (TypeError, ValueError):
                    raise OpenRouterSemanticError(
                        "Structured ReviewReport validation failed."
                    ) from None
                routed_model = str(response_payload.get("model") or model_name)
                routed_provider = str(response_payload.get("provider") or "").strip()
                if repair_count:
                    repaired_candidates = semantic_repair_candidate_ids(report)
                    _increment_telemetry(telemetry, "repaired_responses")
                    _increment_telemetry(
                        telemetry,
                        "semantic_defects_repaired",
                        repair_count,
                    )
                    _increment_telemetry(
                        telemetry,
                        "repair_candidates",
                        len(repaired_candidates),
                    )
                    notify(
                        f"[AI] Deterministically repaired {repair_count} semantic "
                        "response defect(s); uncertain candidates remain Needs review"
                    )
                notify(
                    f"[AI] OpenRouter model {routed_model} returned a schema-valid "
                    f"ReviewReport with {len(report.issues)} candidate issues"
                    + (f" via {routed_provider}" if routed_provider else "")
                )
                return report
            except AIBudgetExceeded:
                raise
            except Exception as exc:
                if isinstance(exc, OpenRouterDeadlineExceeded):
                    _increment_telemetry(telemetry, "deadline_failures")
                _increment_telemetry(
                    telemetry,
                    (
                        "semantic_validation_failures"
                        if isinstance(exc, OpenRouterSemanticError)
                        else "provider_request_failures"
                    ),
                )
                reason = _safe_error_summary(exc)
                failures[model_name] = reason
                retry_instruction = (
                    "\n\n=== RETRY CORRECTION ===\n"
                    f"The prior response was rejected: {reason} "
                    "Return exactly one disposition for every Candidate ID, make "
                    "confirmed issues evidence-complete, and reference only retained "
                    "confirmed candidates as duplicates."
                )
                logger.warning("OpenRouter request to %s failed: %s", model_name, reason)
                notify(
                    f"[WARNING] OpenRouter model {model_name} attempt "
                    f"{attempt + 1} failed: {reason}"
                )
                if not _is_retryable(exc):
                    notify(
                        "[WARNING] OpenRouter returned a non-retryable response; "
                        "skipping remaining attempts for this model"
                    )
                    break
                if attempt < MAX_RETRIES - 1 and (budget is None or budget.used < budget.limit):
                    if isinstance(exc, OpenRouterSemanticError):
                        notify(
                            "[AI] Retrying OpenRouter immediately after semantic validation failure"
                        )
                    else:
                        notify(
                            f"[AI] Retrying OpenRouter in {retry_delay}s with exponential backoff"
                        )
                        time.sleep(retry_delay)
                        retry_delay *= 2
        notify(f"[WARNING] OpenRouter model {model_name} exhausted; moving to the next model")

    details = "; ".join(
        f"{model}: {failures.get(model, 'no response')}" for model in OPENROUTER_MODELS
    )
    raise RuntimeError(f"All OpenRouter models failed. {details}")
