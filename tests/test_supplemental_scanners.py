import json
from subprocess import CompletedProcess
from unittest.mock import patch

from src.supplemental_scanners import scan_dependencies, scan_secrets


def test_osv_findings_are_normalized_and_alias_groups_are_deduplicated(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('{"name":"demo","dependencies":{"library":"1.0.0"}}\n')
    payload = {
        "results": [
            {
                "source": {"path": str(lockfile), "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "library",
                            "version": "1.0.0",
                            "ecosystem": "npm",
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-demo",
                                "aliases": ["CVE-2026-0001"],
                                "summary": "Unsafe parsing in affected releases.",
                                "database_specific": {"severity": "HIGH"},
                                "affected": [
                                    {
                                        "ranges": [
                                            {"events": [{"fixed": "1.0.1"}]}
                                        ]
                                    }
                                ],
                            },
                            {"id": "CVE-2026-0001", "aliases": ["GHSA-demo"]},
                        ],
                        "groups": [{"ids": ["GHSA-demo", "CVE-2026-0001"]}],
                    }
                ],
            }
        ]
    }
    completed = CompletedProcess(
        args=[], returncode=1, stdout=json.dumps(payload), stderr=""
    )

    with patch("src.supplemental_scanners._executable", return_value="/bin/osv"):
        with patch("src.supplemental_scanners.subprocess.run", return_value=completed) as run:
            result = scan_dependencies(str(tmp_path))

    assert result.finding_count == 1
    assert len(result.issues) == 1
    assert result.issues[0].severity == "HIGH"
    assert result.issues[0].remediation_type == "MANUAL_REQUIRED"
    assert "1.0.1" in result.issues[0].suggested_fix
    assert result.dispositions[0].status == "CONFIRMED"
    assert result.telemetry["status"] == "completed"
    assert result.telemetry["manifests_discovered"] == 1
    assert result.telemetry["manifests_scanned"] == 1
    assert result.telemetry["packages_queried"] == 1
    assert result.telemetry["osv_result_sources"] == 1
    assert run.call_args.args[0][-1] == str(tmp_path.resolve())


def test_osv_no_packages_is_not_reported_as_a_detector_failure(tmp_path):
    completed = CompletedProcess(args=[], returncode=128, stdout="", stderr="no packages")
    with patch("src.supplemental_scanners._executable", return_value="/bin/osv"):
        with patch("src.supplemental_scanners.subprocess.run", return_value=completed):
            result = scan_dependencies(str(tmp_path))

    assert result.finding_count == 0
    assert result.errors == []
    assert result.telemetry["status"] == "no_packages_found"
    assert result.telemetry["command_completed"] is True
    assert result.telemetry["skip_reasons"]


def test_betterleaks_redacts_values_scopes_tests_and_deduplicates_history(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("private_key = get_secret()\n", encoding="utf-8")
    test_source = tmp_path / "tests" / "test_auth.py"
    test_source.parent.mkdir()
    test_source.write_text("token = fixture_token()\n", encoding="utf-8")
    current = [
        {
            "RuleID": "private-key",
            "Description": "Private key",
            "File": "app.py",
            "StartLine": 1,
            "Secret": "must-not-escape",
            "Match": "private_key=must-not-escape",
        },
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "tests/test_auth.py",
            "StartLine": 1,
            "Secret": "test-secret",
        },
    ]
    history = current + [
        {
            "RuleID": "private-key",
            "Description": "Private key",
            "File": "removed.pem",
            "StartLine": 3,
            "Commit": "abcdef1234567890",
            "Secret": "historical-secret",
        }
    ]
    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        report_path = command[command.index("--report-path") + 1]
        findings = current if command[1] == "dir" else history
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump(findings, report)
        return CompletedProcess(args=command, returncode=1, stdout="", stderr="")

    with patch(
        "src.supplemental_scanners._executable",
        side_effect=lambda command, _environment: (
            "/bin/betterleaks" if command == "betterleaks" else None
        ),
    ):
        with patch("src.supplemental_scanners.subprocess.run", side_effect=fake_run):
            result = scan_secrets(str(tmp_path), max_target_bytes=2_500_000)

    assert result.detector == "betterleaks"
    assert result.finding_count == 3
    assert len(result.issues) == 1
    assert result.issues[0].severity == "HIGH"
    assert result.issues[0].original_code == "[REDACTED SECRET]"
    assert [item.status for item in result.dispositions] == [
        "CONFIRMED",
        "NON_RUNTIME",
        "NEEDS_REVIEW",
    ]
    assert result.dispositions[0].evidence_scope == "CURRENT_AND_HISTORY"
    assert result.dispositions[0].occurrence_count == 2
    assert result.dispositions[2].evidence_scope == "GIT_HISTORY"
    assert result.dispositions[2].commits == ["abcdef123456"]
    assert result.telemetry["deduplicated_occurrences"] == 2
    serialized = json.dumps(
        {
            "issues": [item.model_dump() for item in result.issues],
            "dispositions": [item.model_dump() for item in result.dispositions],
        }
    )
    assert "must-not-escape" not in serialized
    assert "test-secret" not in serialized
    assert "historical-secret" not in serialized
    assert all(command[0] == "/bin/betterleaks" for command in commands)
    assert all("--redact=100" in command for command in commands)
    assert all("--validation" not in command for command in commands)
    assert all(
        command[command.index("--max-target-megabytes") + 1] == "3"
        for command in commands
    )


def test_gitleaks_is_used_when_betterleaks_is_unavailable(tmp_path):
    commands: list[list[str]] = []

    def fake_executable(command, _environment):
        return "/bin/gitleaks" if command == "gitleaks" else None

    def fake_run(command, **_kwargs):
        commands.append(command)
        return CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    with patch("src.supplemental_scanners._executable", side_effect=fake_executable):
        with patch("src.supplemental_scanners.subprocess.run", side_effect=fake_run):
            result = scan_secrets(str(tmp_path))

    assert result.detector == "gitleaks"
    assert result.errors == []
    assert len(commands) == 2
    assert all(command[0] == "/bin/gitleaks" for command in commands)


def test_generic_runtime_secret_requires_review_instead_of_auto_confirmation(tmp_path):
    (tmp_path / "app.py").write_text("token = configured_value\n", encoding="utf-8")
    finding = {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "Attributes": {"path": "app.py"},
        "StartLine": 1,
        "Secret": "must-not-escape",
    }

    def fake_run(command, **_kwargs):
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump([finding] if command[1] == "dir" else [], report)
        return CompletedProcess(args=command, returncode=1, stdout="", stderr="")

    with patch(
        "src.supplemental_scanners._executable",
        side_effect=lambda command, _environment: (
            "/bin/betterleaks" if command == "betterleaks" else None
        ),
    ):
        with patch("src.supplemental_scanners.subprocess.run", side_effect=fake_run):
            result = scan_secrets(str(tmp_path))

    assert result.issues == []
    assert result.dispositions[0].status == "NEEDS_REVIEW"


def test_missing_supplemental_tools_return_explicit_errors(tmp_path):
    with patch("src.supplemental_scanners._executable", return_value=None):
        dependency_result = scan_dependencies(str(tmp_path))
        secret_result = scan_secrets(str(tmp_path))

    assert "Install" in dependency_result.errors[0]
    assert "Install" in secret_result.errors[0]
