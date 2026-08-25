import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

import src.openrouter_client as oc
from src.models import FindingDisposition, ReviewIssue, ReviewReport
from src.openrouter_client import call_openrouter_with_failover


def _response(payload, status_code=200):
    response = MagicMock()
    response.ok = 200 <= status_code < 300
    response.status_code = status_code
    response.json.return_value = payload
    return response


def test_default_model_uses_stable_deepseek_v4_flash():
    assert oc.OPENROUTER_MODELS == ["deepseek/deepseek-v4-flash"]


@patch("src.openrouter_client.requests.post")
def test_openrouter_enforces_schema_and_private_provider_routing(post):
    report = ReviewReport(analysis_scratchpad="validated", issues=[])
    post.return_value = _response(
        {
            "model": "deepseek/deepseek-v4-flash",
            "provider": "OpenRouter automatic routing",
            "choices": [{"message": {"content": report.model_dump_json()}}],
        }
    )
    progress = []

    result = call_openrouter_with_failover(
        "sk-or-v1-secret",
        "audit prompt",
        progress=progress.append,
    )

    assert result == report
    request = post.call_args
    assert request.kwargs["headers"]["Authorization"] == "Bearer sk-or-v1-secret"
    body = request.kwargs["json"]
    assert body["model"] == "deepseek/deepseek-v4-flash"
    assert body["provider"] == {
        "require_parameters": True,
        "data_collection": "deny",
    }
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["temperature"] == 0
    assert body["messages"][0]["content"] == "audit prompt"
    assert any("via OpenRouter automatic routing" in event for event in progress)


@patch("src.openrouter_client.requests.post")
def test_openrouter_can_explicitly_allow_data_collecting_routes(post):
    report = ReviewReport(analysis_scratchpad="validated", issues=[])
    post.return_value = _response(
        {"choices": [{"message": {"content": report.model_dump_json()}}]}
    )

    call_openrouter_with_failover(
        "sk-or-v1-secret",
        "audit prompt",
        allow_data_collection=True,
    )

    assert post.call_args.kwargs["json"]["provider"]["data_collection"] == "allow"


@patch("src.openrouter_client.requests.post")
def test_multi_finding_requests_use_shorter_adaptive_timeout(post):
    candidate_ids = ("SG-one", "SG-two")
    report = ReviewReport(
        analysis_scratchpad="both candidates resolved",
        issues=[],
        dispositions=[
            FindingDisposition(
                finding_id=finding_id,
                status="FALSE_POSITIVE",
                reason="No sensitive sink is reachable.",
                confidence="HIGH",
            )
            for finding_id in candidate_ids
        ],
    )
    post.return_value = _response({"choices": [{"message": {"content": report.model_dump_json()}}]})
    telemetry = {}
    prompt = "\n".join(f"Candidate ID: {finding_id}" for finding_id in candidate_ids)

    result = call_openrouter_with_failover("sk-or-v1-secret", prompt, telemetry=telemetry)

    assert result == report
    assert post.call_args.kwargs["timeout"] == (15, 90)
    assert telemetry["multi_finding_request_attempts"] == 1
    assert "singleton_request_attempts" not in telemetry


@patch("src.openrouter_client.requests.post")
def test_openrouter_records_aggregate_usage_and_cost(post):
    report = ReviewReport(analysis_scratchpad="validated", issues=[])
    post.return_value = _response(
        {
            "choices": [{"message": {"content": report.model_dump_json()}}],
            "usage": {
                "prompt_tokens": 120,
                "completion_tokens": 30,
                "total_tokens": 150,
                "cost": 0.0000425,
            },
        }
    )
    telemetry = {}

    call_openrouter_with_failover("sk-or-v1-secret", "audit prompt", telemetry=telemetry)

    assert telemetry["provider_prompt_tokens"] == 120
    assert telemetry["provider_completion_tokens"] == 30
    assert telemetry["provider_total_tokens"] == 150
    assert telemetry["provider_cost_microusd"] == 42


@patch("src.openrouter_client.time.sleep")
@patch("src.openrouter_client.requests.post")
def test_non_retryable_openrouter_error_is_not_retried(post, sleep):
    post.return_value = _response({"error": {"message": "insufficient credits"}}, status_code=402)

    with pytest.raises(RuntimeError, match="insufficient credits"):
        call_openrouter_with_failover("sk-or-v1-secret", "prompt")

    assert post.call_count == 1
    sleep.assert_not_called()


@patch("src.openrouter_client.MAX_RETRIES", 1)
@patch(
    "src.openrouter_client.OPENROUTER_MODELS",
    ["deepseek/deepseek-v4-flash", "fallback/model"],
)
@patch("src.openrouter_client.requests.post")
def test_configured_openrouter_models_fail_over_in_order(post):
    report = ReviewReport(analysis_scratchpad="fallback succeeded", issues=[])
    post.side_effect = [
        _response({"choices": [{"message": {"content": "not-json"}}]}),
        _response(
            {
                "model": "fallback/model",
                "choices": [{"message": {"content": report.model_dump_json()}}],
            }
        ),
    ]

    assert call_openrouter_with_failover("sk-or-v1-secret", "prompt") == report
    assert [call.kwargs["json"]["model"] for call in post.call_args_list] == [
        "deepseek/deepseek-v4-flash",
        "fallback/model",
    ]


@patch("src.openrouter_client.MAX_RETRIES", 2)
@patch("src.openrouter_client.time.sleep")
@patch("src.openrouter_client.requests.post")
def test_invalid_openrouter_output_is_retried(post, sleep):
    valid = ReviewReport(analysis_scratchpad="second attempt", issues=[])
    post.side_effect = [
        _response({"choices": [{"message": {"content": "not json"}}]}),
        _response({"choices": [{"message": {"content": valid.model_dump_json()}}]}),
    ]

    result = call_openrouter_with_failover("sk-or-v1-secret", "prompt")

    assert result == valid
    assert post.call_count == 2
    sleep.assert_not_called()


@patch("src.openrouter_client.MAX_RETRIES", 2)
@patch("src.openrouter_client.time.sleep")
@patch("src.openrouter_client.requests.post")
def test_semantically_incomplete_openrouter_report_is_repaired(post, sleep):
    candidate_id = "SG-123456789abc"
    incomplete = ReviewReport(analysis_scratchpad="incomplete", issues=[])
    post.return_value = _response(
        {"choices": [{"message": {"content": incomplete.model_dump_json()}}]}
    )

    telemetry = {}
    result = call_openrouter_with_failover(
        "sk-or-v1-secret",
        f"Candidate ID: {candidate_id}\n",
        telemetry=telemetry,
    )

    assert result.dispositions[0].finding_id == candidate_id
    assert result.dispositions[0].status == "NEEDS_REVIEW"
    assert post.call_count == 1
    sleep.assert_not_called()
    assert telemetry["repaired_responses"] == 1
    assert telemetry["repair_candidates"] == 1
    assert telemetry["semantic_defects_repaired"] == 1


@patch("src.openrouter_client.requests.post")
def test_parseable_deepseek_shape_defects_are_normalized_conservatively(post):
    candidate_id = "SG-normalized"
    payload = {
        "analysis_scratchpad": "validated",
        "issues": {
            "file": "app.java",
            "line": "7",
            "severity": "high",
            "issue_name": "Weak hash",
            "description": "MD5 protects a security value.",
            "original_code": 'getInstance("MD5")',
            "suggested_fix": "",
            "finding_id": candidate_id,
            "confidence": "high",
            "code_role": "runtime",
            "source_evidence": "request password",
            "sink_evidence": "MD5 digest",
            "sink_file": "app.java",
            "sink_line": "7",
            "reachability_evidence": "direct data flow",
            "remediation_type": "manual-required",
            "provider_only_field": "discard me",
        },
        "dispositions": {
            "finding_id": candidate_id,
            "status": "confirmed",
            "reason": "Complete evidence.",
            "confidence": "high",
        },
        "provider_only_field": "discard me",
    }
    post.return_value = _response(
        {"choices": [{"message": {"content": f"```json\n{json.dumps(payload)}\n```"}}]}
    )

    result = call_openrouter_with_failover(
        "sk-or-v1-secret", f"Candidate ID: {candidate_id}\n"
    )

    assert result.dispositions[0].status == "CONFIRMED"
    assert result.issues[0].line == 7
    assert result.issues[0].remediation_type == "MANUAL_REQUIRED"
    assert post.call_count == 1


@patch("src.openrouter_client.MAX_RETRIES", 1)
@patch("src.openrouter_client.requests.post")
def test_strict_retriage_rejects_semantically_incomplete_output(post):
    candidate_id = "SG-strict"
    incomplete = ReviewReport(analysis_scratchpad="incomplete", issues=[])
    post.return_value = _response(
        {"choices": [{"message": {"content": incomplete.model_dump_json()}}]}
    )
    telemetry = {}

    with pytest.raises(RuntimeError, match="omitted 1 candidate"):
        call_openrouter_with_failover(
            "sk-or-v1-secret",
            f"Candidate ID: {candidate_id}\n",
            allow_semantic_repair=False,
            telemetry=telemetry,
        )

    assert telemetry["semantic_validation_failures"] == 1
    assert "repaired_responses" not in telemetry


@patch("src.openrouter_client.requests.post")
def test_invalid_duplicate_reference_is_repaired_without_losing_confirmed_issue(post):
    confirmed_id = "SG-confirmed"
    duplicate_id = "SG-duplicate"
    report = ReviewReport(
        analysis_scratchpad="one valid issue and one invalid duplicate",
        issues=[
            ReviewIssue(
                file="app.py",
                line=1,
                severity="HIGH",
                issue_name="SQL injection",
                description="Untrusted input reaches a query.",
                original_code="query(value)",
                suggested_fix="",
                finding_id=confirmed_id,
                rule_id="test.sqli",
                confidence="HIGH",
                source_evidence="request input",
                sink_evidence="database query",
                sink_file="app.py",
                sink_line=1,
                reachability_evidence="direct call",
                remediation_type="MANUAL_REQUIRED",
            )
        ],
        dispositions=[
            FindingDisposition(
                finding_id=confirmed_id,
                status="CONFIRMED",
                reason="Complete evidence.",
            ),
            FindingDisposition(
                finding_id=duplicate_id,
                status="DUPLICATE",
                reason="Same issue.",
                canonical_finding_id="SG-missing",
            ),
        ],
    )
    post.return_value = _response({"choices": [{"message": {"content": report.model_dump_json()}}]})
    prompt = f"Candidate ID: {confirmed_id}\nCandidate ID: {duplicate_id}\n"

    result = call_openrouter_with_failover("sk-or-v1-secret", prompt)

    assert [issue.finding_id for issue in result.issues] == [confirmed_id]
    assert {item.finding_id: item.status for item in result.dispositions} == {
        confirmed_id: "CONFIRMED",
        duplicate_id: "NEEDS_REVIEW",
    }
    assert post.call_count == 1


@patch("src.openrouter_client.API_TIMEOUT_SECONDS", 0.01)
@patch("src.openrouter_client.time.sleep")
@patch("src.openrouter_client.requests.post")
def test_openrouter_wall_clock_deadline_does_not_wait_for_socket_activity(post, sleep):
    release = threading.Event()
    post.side_effect = lambda **_kwargs: release.wait(1)
    started = time.monotonic()

    try:
        with pytest.raises(RuntimeError, match="wall-clock deadline"):
            call_openrouter_with_failover("sk-or-v1-secret", "prompt")
    finally:
        release.set()

    assert time.monotonic() - started < 0.5
    assert post.call_count == 1
    sleep.assert_not_called()
