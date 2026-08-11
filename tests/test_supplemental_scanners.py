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
    assert run.call_args.args[0][-1] == str(tmp_path.resolve())


def test_osv_no_packages_is_not_reported_as_a_detector_failure(tmp_path):
    completed = CompletedProcess(args=[], returncode=128, stdout="", stderr="no packages")
    with patch("src.supplemental_scanners._executable", return_value="/bin/osv"):
        with patch("src.supplemental_scanners.subprocess.run", return_value=completed):
            result = scan_dependencies(str(tmp_path))

    assert result.finding_count == 0
    assert result.errors == []


def test_gitleaks_redacts_values_and_deduplicates_current_from_history(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("token = get_secret()\n", encoding="utf-8")
    current = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "app.py",
            "StartLine": 1,
            "Secret": "must-not-escape",
            "Match": "token=must-not-escape",
        }
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

    with patch("src.supplemental_scanners._executable", return_value="/bin/gitleaks"):
        with patch("src.supplemental_scanners.subprocess.run", side_effect=fake_run):
            result = scan_secrets(str(tmp_path), max_target_bytes=2_500_000)

    assert result.finding_count == 2
    assert len(result.issues) == 1
    assert result.issues[0].severity == "HIGH"
    assert result.issues[0].original_code == "[REDACTED SECRET]"
    assert [item.status for item in result.dispositions] == [
        "CONFIRMED",
        "NEEDS_REVIEW",
    ]
    serialized = json.dumps(
        {
            "issues": [item.model_dump() for item in result.issues],
            "dispositions": [item.model_dump() for item in result.dispositions],
        }
    )
    assert "must-not-escape" not in serialized
    assert "historical-secret" not in serialized
    assert all("--redact=100" in command for command in commands)
    assert all(
        command[command.index("--max-target-megabytes") + 1] == "3"
        for command in commands
    )


def test_missing_supplemental_tools_return_explicit_errors(tmp_path):
    with patch("src.supplemental_scanners._executable", return_value=None):
        dependency_result = scan_dependencies(str(tmp_path))
        secret_result = scan_secrets(str(tmp_path))

    assert "Install" in dependency_result.errors[0]
    assert "Install" in secret_result.errors[0]
