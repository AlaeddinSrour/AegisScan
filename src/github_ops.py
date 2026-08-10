"""
GitHub operations: PR commenting, git commit/push, and auto-fix application.

Handles all interactions with the GitHub API and local git operations,
including token-safe logging to prevent credential leaks in CI output.
"""

import base64
import ast
import json
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from github import Auth, Github

from .models import ReviewIssue
from .safety import is_suggested_fix_safe
from .fuzzy import fuzzy_replace

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditPushResult:
    branch: str
    pull_request_url: str


def auto_fix_eligibility(issue: ReviewIssue) -> tuple[bool, str]:
    """Return whether an issue may enter the deterministic patching path."""
    if issue.remediation_type != "AUTOMATIC":
        return False, "This finding requires manual remediation."
    if issue.code_role not in {"RUNTIME", "UNKNOWN"}:
        return False, f"{issue.code_role.title()} code cannot be patched automatically."
    if issue.confidence == "LOW":
        return False, "Low-confidence findings require manual review."
    if not issue.original_code or not issue.suggested_fix:
        return False, "No complete replacement patch is available."
    if issue.original_code == issue.suggested_fix:
        return False, "The suggested patch does not change the reviewed code."
    if issue.line < 1:
        return False, "The reviewed patch does not have a valid line anchor."
    is_safe, reason = is_suggested_fix_safe(issue.suggested_fix)
    if not is_safe:
        return False, f"Safety policy rejected this patch: {reason}"
    return True, "Patch passed the deterministic eligibility checks."


def run_cmd(
    cmd: list[str],
    redact: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> tuple[bool, str]:
    """
    Execute a shell command safely.

    Args:
        cmd: The command as a list of arguments.
        redact: Optional string to redact from error logs (e.g., tokens).

    Returns:
        (success, stdout_or_stderr)
    """
    result = subprocess.run(
        cmd, shell=False, text=True, capture_output=True, env=env
    )
    if result.returncode != 0:
        display_cmd = ' '.join(cmd)
        if redact:
            display_cmd = display_cmd.replace(redact, "***")
        log_stderr = result.stderr.replace(redact, "***") if redact else result.stderr
        log_stdout = result.stdout.replace(redact, "***") if redact else result.stdout
        logger.error(
            f"Command failed: {display_cmd}\nStdout: {log_stdout}\nStderr: {log_stderr}"
        )
        return False, result.stderr
    return True, result.stdout


def validate_publishable_worktree(
    repo_path: str,
    allowed_changes: list[str] | None = None,
) -> str:
    """Validate Git state and return the current branch.

    Before an audit, ``allowed_changes`` is omitted and the tree must be clean.
    Before publishing, every dirty path must be one produced by AegisScan.
    """
    root = str(Path(repo_path).expanduser().resolve())

    def git(*args: str) -> tuple[bool, str]:
        return run_cmd(["git", "-c", f"safe.directory={root}", "-C", root, *args])

    success, output = git("rev-parse", "--is-inside-work-tree")
    if not success or output.strip() != "true":
        raise RuntimeError("Pull-request publishing requires a local Git repository.")
    success, branch = git("branch", "--show-current")
    branch = branch.strip()
    if not success or not branch:
        raise RuntimeError("Pull-request publishing requires a checked-out local branch.")

    if allowed_changes is None:
        success, status = git("status", "--porcelain", "--untracked-files=all")
        if not success:
            raise RuntimeError(f"Could not inspect repository state: {status.strip()}")
        if status.strip():
            raise RuntimeError(
                "Pull-request publishing requires a clean worktree before the audit; "
                "commit or stash existing changes first."
            )
        return branch

    dirty_paths: set[str] = set()
    for args in (
        ("diff", "--name-only"),
        ("diff", "--cached", "--name-only"),
        ("ls-files", "--others", "--exclude-standard"),
    ):
        success, output = git(*args)
        if not success:
            raise RuntimeError(f"Could not inspect repository changes: {output.strip()}")
        dirty_paths.update(line for line in output.splitlines() if line)
    allowed = {Path(path).as_posix().lstrip("./") for path in allowed_changes}
    unexpected = sorted(dirty_paths - allowed)
    if unexpected:
        raise RuntimeError(
            "Repository changed during the audit outside AegisScan's patch set: "
            + ", ".join(unexpected[:10])
        )
    return branch


def apply_auto_fixes_with_paths(
    issues: List[ReviewIssue], repo_path: str = "."
) -> list[str]:
    """
    Apply AI-suggested auto-fixes to local files using fuzzy matching.

    Each fix is validated by the safety validator before application.
    Workflow files under .github/workflows are skipped to prevent
    permission crashes.

    Returns the repository-relative paths that were changed.
    """
    root = Path(repo_path).expanduser().resolve()
    issues_by_file: dict[Path, list[ReviewIssue]] = {}
    relative_paths: dict[Path, str] = {}
    for issue in issues:
        eligible, eligibility_reason = auto_fix_eligibility(issue)
        if not eligible:
            logger.warning(
                "Skipping auto-fix for %s:%s: %s",
                issue.file,
                issue.line,
                eligibility_reason,
            )
            continue

        relative_path = issue.file.replace("\\", "/")
        file_path = (root / relative_path).resolve()
        try:
            file_path.relative_to(root)
        except ValueError:
            logger.warning("File %s resolves outside the repository. Skipping.", relative_path)
            continue

        if not file_path.is_file():
            logger.warning(f"File {relative_path} not found locally. Skipping auto-fix.")
            continue

        if relative_path.replace("\\", "/").startswith(".github/workflows/"):
            logger.warning(
                f"Skipping auto-fix for {relative_path}. "
                "GitHub Actions tokens cannot push modifications to workflow files."
            )
            continue

        issues_by_file.setdefault(file_path, []).append(issue)
        relative_paths[file_path] = file_path.relative_to(root).as_posix()

    originals: dict[Path, str] = {}
    prepared: dict[Path, str] = {}
    for file_path, file_issues in issues_by_file.items():
        relative_path = relative_paths[file_path]
        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            logger.error("Could not read %s as UTF-8; no patch was applied: %s", relative_path, exc)
            continue
        originals[file_path] = content
        candidate_content = content
        applied = False
        # Apply bottom-up so earlier replacements cannot shift later line anchors.
        for issue in sorted(file_issues, key=lambda item: item.line, reverse=True):
            new_content, fixed = fuzzy_replace(
                candidate_content,
                issue.original_code,
                issue.suggested_fix,
                target_line=issue.line,
            )
            if not fixed:
                logger.warning(
                    "Could not apply auto-fix to %s:%s: the reviewed snippet was missing or ambiguous.",
                    relative_path,
                    issue.line,
                )
                continue
            valid, reason = _validate_patched_content(file_path, new_content)
            if not valid:
                logger.warning(
                    "Rejected auto-fix for %s:%s after validation: %s",
                    relative_path,
                    issue.line,
                    reason,
                )
                continue
            candidate_content = new_content
            applied = True
        if applied and candidate_content != content:
            prepared[file_path] = candidate_content

    written: list[Path] = []
    try:
        for file_path, content in prepared.items():
            _atomic_write_text(file_path, content)
            written.append(file_path)
    except OSError as exc:
        logger.error("Patch transaction failed; restoring original files: %s", exc)
        for file_path in reversed(written):
            try:
                _atomic_write_text(file_path, originals[file_path])
            except OSError as rollback_exc:
                logger.critical("Could not restore %s: %s", file_path, rollback_exc)
        return []

    return [relative_paths[file_path] for file_path in written]


def _validate_patched_content(file_path: Path, content: str) -> tuple[bool, str]:
    """Run non-executing syntax validation for formats supported locally."""
    try:
        suffix = file_path.suffix.casefold()
        if suffix == ".py":
            ast.parse(content, filename=str(file_path))
        elif suffix == ".json":
            json.loads(content)
    except (SyntaxError, json.JSONDecodeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, ""


def _atomic_write_text(file_path: Path, content: str) -> None:
    """Replace a UTF-8 source file atomically while retaining its mode."""
    mode = file_path.stat().st_mode
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=file_path.parent,
            prefix=f".{file_path.name}.aegisscan-",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = temporary.name
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, file_path)
        temporary_path = None
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def apply_auto_fixes(issues: List[ReviewIssue], repo_path: str = ".") -> bool:
    """Compatibility wrapper returning whether any safety-cleansed fix applied."""
    return bool(apply_auto_fixes_with_paths(issues, repo_path))


def push_auto_fixes(
    github_token: str,
    repository: str,
    repo_path: str,
    changed_files: list[str],
    issues: List[ReviewIssue],
    base_branch: str = "",
) -> AuditPushResult:
    """Commit only AegisScan changes on a new audit branch and open a new PR."""
    root = str(Path(repo_path).expanduser().resolve())
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    branch = f"aegis-audit-{timestamp}"

    def git(
        *args: str,
        redact: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
    ) -> tuple[bool, str]:
        return run_cmd(
            ["git", "-c", f"safe.directory={root}", "-C", root, *args],
            redact=redact,
            env=env,
        )

    if not changed_files:
        raise ValueError("No AegisScan changes were supplied for the audit branch.")

    original_branch = validate_publishable_worktree(root, changed_files)
    remote_success, remote_url = git("remote", "get-url", "origin")
    if not remote_success:
        raise RuntimeError("Pull-request publishing requires a configured origin remote.")
    normalized_remote = remote_url.strip().removesuffix(".git").replace(":", "/")
    expected_suffix = f"github.com/{repository}".casefold()
    if not normalized_remote.casefold().endswith(expected_suffix):
        raise RuntimeError(
            "The configured GitHub repository does not match this worktree's origin remote."
        )

    gh = Github(auth=Auth.Token(github_token))
    repo = gh.get_repo(repository)
    target_branch = base_branch or repo.default_branch
    if original_branch != target_branch:
        raise RuntimeError(
            f"Check out the PR base branch '{target_branch}' before publishing; "
            f"the current branch is '{original_branch}'."
        )

    logger.info("Creating dedicated audit branch %s...", branch)
    success, error = git("switch", "-c", branch)
    if not success:
        raise RuntimeError(f"Failed to create audit branch: {error.strip()}")

    try:
        add_success, error = git("add", "--", *changed_files)
        if not add_success:
            raise RuntimeError(f"Failed to stage audit fixes: {error.strip()}")

        _, status = git("status", "--porcelain", "--", *changed_files)
        if not status.strip():
            raise RuntimeError("No auto-fix changes remained after staging.")

        commit_environment = os.environ.copy()
        commit_environment.update(
            {
                "GIT_AUTHOR_NAME": "AegisScan",
                "GIT_AUTHOR_EMAIL": "aegisscan@users.noreply.github.com",
                "GIT_COMMITTER_NAME": "AegisScan",
                "GIT_COMMITTER_EMAIL": "aegisscan@users.noreply.github.com",
            }
        )
        commit_success, error = git(
            "commit",
            "-m",
            "AegisScan: apply repository-wide security mitigations",
            env=commit_environment,
        )
        if not commit_success:
            raise RuntimeError(f"Failed to commit audit fixes: {error.strip()}")

        push_url = f"https://github.com/{repository}.git"
        credential = base64.b64encode(
            f"x-access-token:{github_token}".encode("utf-8")
        ).decode("ascii")
        git_env = os.environ.copy()
        git_env.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {credential}",
            }
        )
        push_success, error = git(
            "push",
            push_url,
            f"HEAD:refs/heads/{branch}",
            redact=github_token,
            env=git_env,
        )
        if not push_success:
            raise RuntimeError(f"Failed to push audit branch: {error.strip()}")

        counts: dict[str, int] = {}
        for issue in issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
        summary = ", ".join(f"{count} {severity}" for severity, count in sorted(counts.items()))
        body = (
            "AegisScan performed a batched full-repository Semgrep and LLM audit, then "
            "applied only fixes that passed deterministic patch safety validation.\n\n"
            f"Confirmed findings: {len(issues)} ({summary or 'none'}).\n"
            f"Files changed: {len(changed_files)}."
        )
        pr = repo.create_pull(
            title="AegisScan full-repository security mitigations",
            body=body,
            head=branch,
            base=target_branch,
        )
        result = AuditPushResult(branch=branch, pull_request_url=pr.html_url)
    except Exception:
        restore_success, restore_error = git("switch", original_branch)
        if not restore_success:
            logger.error("Could not restore original branch %s: %s", original_branch, restore_error)
        raise

    restore_success, restore_error = git("switch", original_branch)
    if not restore_success:
        raise RuntimeError(
            f"Pull request was created, but the original branch could not be restored: "
            f"{restore_error.strip()}"
        )
    return result


def push_audit_fixes(
    github_token: str,
    repository: str,
    repo_path: str,
    changed_files: list[str],
    issues: List[ReviewIssue],
    base_branch: str = "",
) -> AuditPushResult:
    """Descriptive alias for the repository-wide ``push_auto_fixes`` flow."""
    return push_auto_fixes(
        github_token,
        repository,
        repo_path,
        changed_files,
        issues,
        base_branch,
    )


def post_inline_comments(pr, latest_commit, issues: List[ReviewIssue]) -> None:
    """
    Post inline review comments on the PR for each identified issue.

    Falls back to a general PR issue comment if the inline comment fails
    (e.g., the line is not part of the diff). Includes a small delay
    between comments to avoid hitting GitHub's secondary rate limits.
    """
    for i, issue in enumerate(issues):
        body = (
            f"### 🛡️ AegisScan [{issue.severity}]\n"
            f"**{issue.issue_name}**\n\n"
            f"{issue.description}"
        )
        if issue.suggested_fix:
            body += f"\n\n```suggestion\n{issue.suggested_fix}\n```"

        logger.info(f"Posting inline comment to {issue.file}:{issue.line}...")
        try:
            pr.create_review_comment(
                body=body,
                commit=latest_commit,
                path=issue.file,
                line=issue.line,
                side="RIGHT",
            )
            logger.info("Successfully posted inline comment.")
        except Exception as e:
            logger.warning(
                f"Failed to post inline comment on {issue.file}:{issue.line} "
                f"(possibly line not in diff): {e}"
            )
            # Fallback to general PR comment
            fallback_body = (
                f"### 🛡️ AegisScan [{issue.severity}] on `{issue.file}` line {issue.line}\n"
                f"**{issue.issue_name}**\n\n"
                f"{issue.description}"
            )
            if issue.suggested_fix:
                fallback_body += (
                    f"\n\n**Suggested Fix:**\n```\n{issue.suggested_fix}\n```"
                )
            try:
                pr.create_issue_comment(fallback_body)
                logger.info("Successfully posted fallback PR issue comment.")
            except Exception as fe:
                logger.error(f"Failed to post fallback PR comment: {fe}")

        # Small delay between comments to respect GitHub rate limits
        if i < len(issues) - 1:
            time.sleep(1)
