from unittest.mock import MagicMock, patch

import pytest

from src.ai_budget import AIBudgetExceeded, RequestBudget, timed_request
from src.full_scan import run_full_scan
from src.gemini_client import call_gemini_with_failover
from src.openrouter_client import call_openrouter_with_failover


def test_timing_records_transport_failure_without_content():
    telemetry = {}
    with patch("src.ai_budget.time.monotonic", side_effect=[10, 10.25]):
        with pytest.raises(RuntimeError):
            with timed_request(telemetry, "openrouter", RequestBudget(batch=2)):
                raise RuntimeError("private provider content")
    assert telemetry["request_1_openrouter_milliseconds"] == 250
    assert telemetry["request_1_transport_failed"] == 1
    assert telemetry["request_1_batch"] == 2
    assert "private" not in str(telemetry)


def test_retries_and_new_calls_share_budget_and_skip_final_backoff():
    budget, telemetry = RequestBudget(2), {}
    with patch("src.openrouter_client._post_with_deadline", side_effect=RuntimeError("offline")) as post:
        with patch("src.openrouter_client.time.sleep") as sleep:
            with pytest.raises(AIBudgetExceeded):
                call_openrouter_with_failover("test-key", "prompt", budget=budget, telemetry=telemetry)
            assert post.call_count == 2
            assert sleep.call_count == 1
            with pytest.raises(AIBudgetExceeded):
                call_openrouter_with_failover("test-key", "recovery", budget=budget, telemetry=telemetry)
            assert post.call_count == 2
            assert telemetry["budget_exhaustions"] == 2
    client = MagicMock()
    with pytest.raises(AIBudgetExceeded):
        call_gemini_with_failover(client, "fallback", budget=budget, telemetry=telemetry)
    client.models.generate_content.assert_not_called()


def test_scan_retains_candidates_when_shared_budget_exhausted(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISSCAN_BATCH_REQUEST_LIMIT", "1")
    (tmp_path / "app.py").write_text("print('example')\nprint('another')\n")
    finding = ("Finding #1:\nRule ID: test.rule\nFile: app.py:1\n"
               "Message: unsafe\nCode Snippet: print('example')\n\n"
               "Finding #2:\nRule ID: test.rule\nFile: app.py:2\n"
               "Message: unsafe\nCode Snippet: print('another')\n")
    client = MagicMock()
    client.models.generate_content.side_effect = RuntimeError("offline")
    with patch("src.full_scan.run_semgrep_scan", return_value=finding):
        outcome = run_full_scan(str(tmp_path), "test", client=client,
                                dependency_scan=False, secret_scan=False)
    assert client.models.generate_content.call_count == 1
    assert outcome.audit_degraded
    assert len(outcome.report.dispositions) == 2
    assert all(item.status == "NEEDS_REVIEW" for item in outcome.report.dispositions)
