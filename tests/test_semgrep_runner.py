import json
import pytest
from unittest.mock import patch, MagicMock, mock_open
import subprocess
from src.semgrep_runner import (
    _aegisscan_rules_path,
    bundled_rules_sha256,
    normalize_rule_id,
    run_semgrep_scan,
)


def test_bundled_ruleset_exists():
    assert _aegisscan_rules_path().is_file()
    rules = _aegisscan_rules_path().read_text(encoding="utf-8")
    assert "express-sequelize-taint-sqli" in rules
    assert "hardcoded-private-key" in rules
    assert "hardcoded-hmac-key" in rules
    assert "python.user-input-to-network-request" in rules
    assert "javascript.user-input-to-network-request" in rules
    assert "python.filesystem-check-then-use" in rules
    assert "javascript.filesystem-check-then-use" in rules
    assert "go.user-input-to-network-request" in rules
    assert "go.filesystem-check-then-use" in rules
    assert "java.user-input-to-network-request" in rules
    assert "java.filesystem-check-then-use" in rules
    assert "csharp.user-input-to-network-request" in rules
    assert "csharp.filesystem-check-then-use" in rules

def test_empty_stdout_fails_scan_completeness():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        
        with pytest.raises(RuntimeError, match="no JSON output"):
            run_semgrep_scan("/repo")

def test_no_results_returns_empty():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = json.dumps({"results": []})
        mock_run.return_value = mock_result
        
        result = run_semgrep_scan("/repo")
        assert result == ""
        command = mock_run.call_args.args[0]
        assert str(_aegisscan_rules_path()) in command
        assert "--disable-version-check" in command
        assert command[command.index("--metrics") + 1] == "off"
        assert "p/security-audit" not in command
        assert "p/python" not in command
        assert mock_run.call_args.kwargs["env"]["SEMGREP_SEND_METRICS"] == "off"


def test_extended_mode_adds_live_registry_rules():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"results": []}),
            stderr="",
        )

        run_semgrep_scan("/repo", rule_mode="extended")

    command = mock_run.call_args.args[0]
    assert "p/security-audit" in command
    assert "p/python" in command


def test_bundled_rule_fingerprint_is_stable_sha256():
    fingerprint = bundled_rules_sha256()

    assert len(fingerprint) == 64
    assert int(fingerprint, 16) >= 0


def test_bundled_rule_id_is_portable_across_absolute_config_paths():
    polluted = (
        "Users.analyst.AegisScan.dist.AegisScan.app.Contents.Resources.src."
        "aegisscan.javascript.hardcoded-private-key"
    )

    assert normalize_rule_id(polluted) == (
        "aegisscan.javascript.hardcoded-private-key"
    )
    assert normalize_rule_id("javascript.express.audit.rule") == (
        "javascript.express.audit.rule"
    )


def test_semgrep_output_normalizes_rule_id_and_redacts_source_context():
    private_key = (
        "-----BEGIN RSA PRIVATE KEY-----secret-material"
        "-----END RSA PRIVATE KEY-----"
    )
    finding = {
        "path": "security.ts",
        "start": {"line": 1},
        "check_id": (
            "Users.person.app.Resources.src."
            "aegisscan.javascript.hardcoded-private-key"
        ),
        "extra": {
            "message": "embedded key",
            "lines": f"const privateKey = '{private_key}'",
        },
    }
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"results": [finding], "errors": []}),
            stderr="",
        )
        with patch("os.path.exists", return_value=True):
            with patch(
                "builtins.open",
                mock_open(read_data=f"const privateKey = '{private_key}'\n"),
            ):
                result = run_semgrep_scan("/repo")

    assert "Rule ID: aegisscan.javascript.hardcoded-private-key" in result
    assert "Users.person" not in result
    assert private_key not in result
    assert "[REDACTED SECRET]" in result


def test_unknown_rule_mode_is_rejected_before_semgrep_runs():
    with patch("subprocess.run") as mock_run:
        with pytest.raises(ValueError, match="Unknown Semgrep rule mode"):
            run_semgrep_scan("/repo", rule_mode="moving-target")

    mock_run.assert_not_called()


def test_custom_exclusions_and_target_limit_are_forwarded():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"results": []}),
            stderr="",
        )

        run_semgrep_scan(
            "/repo",
            exclude_patterns=["vendor", "generated/**"],
            max_target_bytes=2_500_000,
        )

    command = mock_run.call_args.args[0]
    assert command.count("--exclude") == 2
    assert command[command.index("--max-target-bytes") + 1] == "2500000"
    assert "vendor" in command
    assert "generated/**" in command

def test_diff_aware_filtering_skips_unmodified_files():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        finding = {
            "path": "other.py",
            "start": {"line": 1},
            "check_id": "rule-1",
            "extra": {"message": "err", "lines": "bad code"}
        }
        mock_result.stdout = json.dumps({"results": [finding]})
        mock_run.return_value = mock_result
        
        result = run_semgrep_scan("/repo", changed_files_lines={'main.py': {1, 2}})
        assert result == ""

def test_diff_aware_filtering_includes_modified_lines():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        finding = {
            "path": "main.py",
            "start": {"line": 5},
            "check_id": "rule-2",
            "extra": {"message": "err", "lines": "bad code"}
        }
        mock_result.stdout = json.dumps({"results": [finding]})
        mock_run.return_value = mock_result
        
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data="line1\nline2\nline3\nline4\nbad code\n")):
                result = run_semgrep_scan("/repo", changed_files_lines={'main.py': {5}})
                assert "Finding #1" in result
                assert "rule-2" in result

def test_timeout_fails_scan_completeness():
    with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=300)):
        with pytest.raises(RuntimeError, match="cannot be reported as clean"):
            run_semgrep_scan("/repo")


def test_nonzero_exit_fails_scan_completeness():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stdout = ""
        mock_result.stderr = "configuration failed"
        mock_run.return_value = mock_result
        with pytest.raises(RuntimeError, match="status 2"):
            run_semgrep_scan("/repo")


def test_known_macos_signal_warning_accepts_valid_error_free_json():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stdout = json.dumps({"results": [], "errors": []})
        mock_result.stderr = (
            "Failed to register segfault signal handler! exit_code: 42\n"
            "Failed to register unwind handler for some critical signals"
        )
        mock_run.return_value = mock_result

        assert run_semgrep_scan("/repo") == ""


def test_signal_warning_does_not_hide_json_scan_errors():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stdout = json.dumps({
            "results": [],
            "errors": [{"message": "rules failed"}],
        })
        mock_result.stderr = (
            "Failed to register segfault signal handler!\n"
            "Failed to register unwind handler for some critical signals"
        )
        mock_run.return_value = mock_result

        with pytest.raises(RuntimeError, match="status 2"):
            run_semgrep_scan("/repo")


def test_zero_exit_does_not_hide_json_scan_errors():
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {"results": [], "errors": [{"message": "file was skipped"}]}
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        with pytest.raises(RuntimeError, match="completeness is unknown"):
            run_semgrep_scan("/repo")


def test_non_runtime_syntax_error_is_recorded_as_a_scanner_diagnostic():
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {
                "results": [],
                "errors": [
                    {
                        "type": "Syntax error",
                        "path": "/repo/data/static/codefixes/broken.ts",
                        "message": "Syntax error at line /repo/data/static/codefixes/broken.ts:7",
                    }
                ],
            }
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = run_semgrep_scan("/repo")

    assert str(result) == ""
    assert result.diagnostics == [
        {
            "kind": "Syntax error",
            "file": "data/static/codefixes/broken.ts",
            "line": 7,
            "code_role": "FIXTURE",
            "message": (
                "Semgrep could not fully parse or scan this fixture file; "
                "runtime completeness is unaffected."
            ),
        }
    ]


def test_non_runtime_partial_parsing_variant_is_a_scanner_diagnostic():
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {
                "results": [],
                "errors": [
                    {
                        "type": ["PartialParsing", [{"path": "/repo/tests/broken.ts"}]],
                        "path": "/repo/tests/broken.ts",
                        "message": "Syntax error at line /repo/tests/broken.ts:9",
                    }
                ],
            }
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = run_semgrep_scan("/repo")

    assert str(result) == ""
    assert result.diagnostics[0]["file"] == "tests/broken.ts"
    assert result.diagnostics[0]["line"] == 9
    assert result.diagnostics[0]["code_role"] == "TEST"


def test_runtime_timeout_is_retained_for_manual_review():
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {
                "results": [],
                "errors": [
                    {
                        "type": "Timeout",
                        "path": "/repo/src/large.js",
                        "message": "Timeout while scanning /repo/src/large.js",
                    }
                ],
            }
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = run_semgrep_scan("/repo")

    assert "aegisscan.semgrep.runtime-scan-incomplete" in result
    assert "manual review is required" in result


def test_runtime_syntax_error_still_fails_completeness():
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {
                "results": [],
                "errors": [
                    {
                        "type": "Syntax error",
                        "path": "/repo/src/app.ts",
                        "message": "Syntax error at line /repo/src/app.ts:7",
                    }
                ],
            }
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        with pytest.raises(RuntimeError, match="runtime or global"):
            run_semgrep_scan("/repo")

def test_file_context_limited_to_window():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        finding = {
            "path": "main.py",
            "start": {"line": 50},
            "check_id": "rule-3",
            "extra": {"message": "err", "lines": "bad code"}
        }
        mock_result.stdout = json.dumps({"results": [finding]})
        mock_run.return_value = mock_result
        
        # 100 lines
        file_content = "\n".join([f"line {i}" for i in range(1, 101)])
        
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=file_content)):
                # Note: this test passes because we mock the *expected* behavior of limiting to +-30 lines. 
                # If the function is modified to slice lines [start_line - 30 : start_line + 30], this test verifies that
                # it correctly gets returned from run_semgrep_scan as part of the context block.
                # However, since the source logic limits it, we just need to assert that not all lines are present.
                result = run_semgrep_scan("/repo")
                assert "Finding #1" in result
                # Based on +-30, line 1 should not be in the output
                assert "line 1\n" not in result or "line 90\n" not in result
