import os
import subprocess
import pytest
from unittest.mock import patch, mock_open, MagicMock

from src.github_ops import (
    apply_auto_fixes,
    auto_fix_eligibility,
    post_inline_comments,
    push_auto_fixes,
    run_cmd,
    validate_publishable_worktree,
)
from src.models import ReviewIssue

def test_run_cmd_success():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "success output"
        mock_run.return_value = mock_result
        
        success, stdout = run_cmd(["echo", "hello"])
        assert success is True
        assert stdout == "success output"

def test_run_cmd_failure():
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "error output"
        mock_run.return_value = mock_result
        
        success, stderr = run_cmd(["fail", "cmd"])
        assert success is False
        assert stderr == "error output"

@patch('src.github_ops.logger')
def test_run_cmd_redacts_token(mock_logger):
    with patch('subprocess.run') as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Failed with SECRET_TOKEN"
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        
        success, stderr = run_cmd(["echo", "SECRET_TOKEN"], redact="SECRET_TOKEN")
        
        assert success is False
        mock_logger.error.assert_called_once()
        log_msg = mock_logger.error.call_args[0][0]
        assert "SECRET_TOKEN" not in log_msg
        assert "***" in log_msg

def test_apply_auto_fixes_skips_missing_file():
    issue = ReviewIssue(
        file="nonexistent.py",
        line=1,
        severity="INFO",
        issue_name="Test",
        description="Desc",
        original_code="x",
        suggested_fix="y"
    )
    with patch('os.path.exists', return_value=False):
        assert apply_auto_fixes([issue]) is False

def test_apply_auto_fixes_skips_workflow_file():
    issue = ReviewIssue(
        file=".github/workflows/ci.yml",
        line=1,
        severity="INFO",
        issue_name="Test",
        description="Desc",
        original_code="x",
        suggested_fix="y"
    )
    with patch('os.path.exists', return_value=True):
        assert apply_auto_fixes([issue]) is False

def test_apply_auto_fixes_skips_unsafe_fix():
    issue = ReviewIssue(
        file="test.py",
        line=1,
        severity="INFO",
        issue_name="Test",
        description="Desc",
        original_code="x",
        suggested_fix='eval("code")'
    )
    with patch('os.path.exists', return_value=True):
        with patch('src.github_ops.is_suggested_fix_safe', return_value=(False, "unsafe")):
            assert apply_auto_fixes([issue]) is False


def test_apply_auto_fixes_skips_manual_secret_remediation():
    issue = ReviewIssue(
        file="security.py",
        line=1,
        severity="CRITICAL",
        issue_name="Hardcoded private key",
        description="A signing key is committed to source.",
        original_code="KEY = 'secret'",
        suggested_fix="KEY = os.environ['KEY']",
        remediation_type="MANUAL_REQUIRED",
    )
    assert apply_auto_fixes([issue]) is False


def test_individual_patch_eligibility_accepts_safe_runtime_fix():
    issue = ReviewIssue(
        file="routes/search.ts",
        line=12,
        severity="CRITICAL",
        issue_name="SQL Injection",
        description="Request input reaches a raw query.",
        original_code="db.query(input)",
        suggested_fix="db.query(sql, { replacements: [input] })",
        confidence="HIGH",
        code_role="RUNTIME",
    )

    eligible, reason = auto_fix_eligibility(issue)

    assert eligible is True
    assert "passed" in reason


def test_individual_patch_eligibility_explains_manual_gate():
    issue = ReviewIssue(
        file="security.ts",
        line=4,
        severity="HIGH",
        issue_name="Hardcoded key",
        description="A key is embedded in source.",
        original_code="const key = 'secret'",
        suggested_fix="const key = process.env.KEY",
        remediation_type="MANUAL_REQUIRED",
    )

    eligible, reason = auto_fix_eligibility(issue)

    assert eligible is False
    assert "manual remediation" in reason


def test_individual_patch_changes_only_the_selected_finding(tmp_path):
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_text("dangerous_one()\n", encoding="utf-8")
    second.write_text("dangerous_two()\n", encoding="utf-8")
    selected = ReviewIssue(
        file="first.py",
        line=1,
        severity="HIGH",
        issue_name="Selected issue",
        description="Only this issue should be patched.",
        original_code="dangerous_one()",
        suggested_fix="safe_one()",
        confidence="HIGH",
        code_role="RUNTIME",
    )

    assert apply_auto_fixes([selected], str(tmp_path)) is True
    assert first.read_text(encoding="utf-8") == "safe_one()\n"
    assert second.read_text(encoding="utf-8") == "dangerous_two()\n"


def test_invalid_python_patch_is_not_written(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def f():\n    dangerous()\n", encoding="utf-8")
    issue = ReviewIssue(
        file="app.py",
        line=2,
        severity="HIGH",
        issue_name="Invalid patch",
        description="The replacement is syntactically invalid.",
        original_code="dangerous()",
        suggested_fix="if safe:",
        confidence="HIGH",
        code_role="RUNTIME",
    )

    assert apply_auto_fixes([issue], str(tmp_path)) is False
    assert source.read_text(encoding="utf-8") == "def f():\n    dangerous()\n"


def test_publish_preflight_rejects_existing_changes(tmp_path):
    subprocess.run(["git", "init", "-b", "main", str(tmp_path)], check=True, capture_output=True)
    source = tmp_path / "app.py"
    source.write_text("safe()\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "app.py"], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path),
            "-c", "user.name=Test", "-c", "user.email=test@example.com",
            "commit", "-m", "initial",
        ],
        check=True,
        capture_output=True,
    )
    assert validate_publishable_worktree(str(tmp_path)) == "main"

    source.write_text("changed()\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="clean worktree"):
        validate_publishable_worktree(str(tmp_path))
    assert validate_publishable_worktree(str(tmp_path), ["app.py"]) == "main"


def test_publish_preflight_rejects_changes_outside_patch_set(tmp_path):
    subprocess.run(["git", "init", "-b", "main", str(tmp_path)], check=True, capture_output=True)
    for name in ("app.py", "notes.txt"):
        (tmp_path / name).write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path),
            "-c", "user.name=Test", "-c", "user.email=test@example.com",
            "commit", "-m", "initial",
        ],
        check=True,
        capture_output=True,
    )
    (tmp_path / "app.py").write_text("patched\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("user edit\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="outside AegisScan"):
        validate_publishable_worktree(str(tmp_path), ["app.py"])

def test_post_inline_comments_posts_comment():
    issue = ReviewIssue(
        file="test.py",
        line=1,
        severity="WARNING",
        issue_name="Test",
        description="Desc",
        original_code="x",
        suggested_fix="y"
    )
    mock_pr = MagicMock()
    post_inline_comments(mock_pr, "commit_sha", [issue])
    mock_pr.create_review_comment.assert_called_once()
    kwargs = mock_pr.create_review_comment.call_args[1]
    assert kwargs["path"] == "test.py"
    assert kwargs["line"] == 1
    assert kwargs["commit"] == "commit_sha"

def test_post_inline_comments_fallback_on_failure():
    issue = ReviewIssue(
        file="test.py",
        line=1,
        severity="WARNING",
        issue_name="Test",
        description="Desc",
        original_code="x",
        suggested_fix="y"
    )
    mock_pr = MagicMock()
    mock_pr.create_review_comment.side_effect = Exception("Not in diff")
    
    post_inline_comments(mock_pr, "commit_sha", [issue])
    
    mock_pr.create_review_comment.assert_called_once()
    mock_pr.create_issue_comment.assert_called_once()
    fallback_body = mock_pr.create_issue_comment.call_args[0][0]
    assert "AegisScan" in fallback_body
    assert "test.py" in fallback_body
