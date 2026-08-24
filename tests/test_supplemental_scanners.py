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
                                "affected": [{"ranges": [{"events": [{"fixed": "1.0.1"}]}]}],
                            },
                            {"id": "CVE-2026-0001", "aliases": ["GHSA-demo"]},
                        ],
                        "groups": [{"ids": ["GHSA-demo", "CVE-2026-0001"]}],
                    }
                ],
            }
        ]
    }
    completed = CompletedProcess(args=[], returncode=1, stdout=json.dumps(payload), stderr="")

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


def test_osv_missing_lockfile_is_an_explicit_coverage_gap(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"library":"^1.0.0"}}\n', encoding="utf-8"
    )
    completed = CompletedProcess(args=[], returncode=128, stdout="", stderr="no packages")
    with patch("src.supplemental_scanners._executable", return_value="/bin/osv"):
        with patch("src.supplemental_scanners.subprocess.run", return_value=completed):
            result = scan_dependencies(str(tmp_path))

    assert result.finding_count == 0
    assert result.errors == []
    assert result.coverage_gaps
    assert result.telemetry["status"] == "coverage_unavailable"
    assert result.telemetry["coverage_complete"] is False
    assert result.telemetry["manifests_discovered"] == 1
    assert result.telemetry["supported_manifests_discovered"] == 0
    assert result.telemetry["uncovered_manifest_files"] == ["package.json"]


def test_osv_uses_ephemeral_npm_lock_without_modifying_repository(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name":"demo","dependencies":{"library":"1.0.0"}}\n',
        encoding="utf-8",
    )

    def fake_executable(command, _environment):
        return {"npm": "/bin/npm", "osv-scanner": "/bin/osv"}.get(command)

    def fake_run(command, **kwargs):
        if command[0] == "/bin/npm":
            lockfile = kwargs["cwd"] / "package-lock.json"
            lockfile.write_text(
                json.dumps(
                    {
                        "name": "demo",
                        "packages": {
                            "": {"name": "demo"},
                            "node_modules/library": {"version": "1.0.0"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            return CompletedProcess(command, 0, "", "")
        lockfile = command[command.index("--lockfile") + 1]
        payload = {
            "results": [
                {
                    "source": {"path": lockfile, "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "library", "version": "1.0.0"},
                            "vulnerabilities": [
                                {
                                    "id": "OSV-DEMO",
                                    "summary": "Affected demo package.",
                                    "database_specific": {"severity": "HIGH"},
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        return CompletedProcess(command, 1, json.dumps(payload), "")

    with patch("src.supplemental_scanners._executable", side_effect=fake_executable):
        with patch("src.supplemental_scanners.subprocess.run", side_effect=fake_run):
            result = scan_dependencies(str(tmp_path))

    assert result.finding_count == 1
    assert result.issues[0].file == "package.json"
    assert result.coverage_gaps == []
    assert result.telemetry["status"] == "completed"
    assert result.telemetry["coverage_complete"] is True
    assert result.telemetry["ephemeral_lockfiles_generated"] == 1
    assert result.telemetry["ephemeral_packages_resolved"] == 1
    assert result.telemetry["supported_manifests_discovered"] == 1
    assert result.telemetry["supported_manifest_files"] == ["package.json"]
    assert result.telemetry["uncovered_manifests"] == 0
    assert result.telemetry["uncovered_manifest_files"] == []
    assert result.telemetry["manifest_inventory_complete"] is True
    assert result.telemetry["dependency_finding_occurrences"] == 1
    assert result.telemetry["unique_advisories"] == 1
    assert result.telemetry["affected_package_versions"] == 1
    assert result.telemetry["affected_packages"] == [
        {
            "package": "library",
            "versions": ["1.0.0"],
            "unique_advisories": 1,
            "occurrences": 1,
        }
    ]
    assert result.telemetry["repository_modified_for_resolution"] is False
    assert not (tmp_path / "package-lock.json").exists()


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
            "Fingerprint": "/repo/app.py:private-key:1",
        },
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "tests/test_auth.py",
            "StartLine": 1,
            "Secret": "test-secret",
        },
    ]
    history = [
        {
            **current[0],
            "Commit": "1234567890abcdef",
            "Fingerprint": "1234567890abcdef:app.py:private-key:1",
        },
        current[1],
        {
            "RuleID": "private-key",
            "Description": "Private key",
            "File": "removed.pem",
            "StartLine": 3,
            "Commit": "abcdef1234567890",
            "Secret": "historical-secret",
        },
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
    assert result.dispositions[0].commits == ["1234567890ab"]
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
    assert all(command[command.index("--max-target-megabytes") + 1] == "3" for command in commands)


def test_betterleaks_suppresses_generic_password_localization_noise(tmp_path):
    translation = tmp_path / "app" / "i18n" / "en.json"
    translation.parent.mkdir(parents=True)
    translation.write_text('{"passwordLabel":"Password"}\n', encoding="utf-8")
    current = [
        {
            "RuleID": "generic-password",
            "Description": "Generic password",
            "File": str(translation),
            "StartLine": 1,
            "Secret": "REDACTED",
        }
    ]

    def fake_run(command, **_kwargs):
        report_path = command[command.index("--report-path") + 1]
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump(current, report)
        return CompletedProcess(args=command, returncode=1, stdout="", stderr="")

    with patch(
        "src.supplemental_scanners._executable",
        side_effect=lambda command, _environment: (
            "/bin/betterleaks" if command == "betterleaks" else None
        ),
    ):
        with patch("src.supplemental_scanners.subprocess.run", side_effect=fake_run):
            result = scan_secrets(str(tmp_path))

    assert result.finding_count == 0
    assert result.dispositions == []
    assert result.telemetry["suppressed_localization_findings"] == 2


def test_betterleaks_consolidates_structured_credential_collections(tmp_path):
    users = tmp_path / "data" / "static" / "users.yml"
    users.parent.mkdir(parents=True)
    users.write_text("users:\n  - password: one\n  - password: two\n", encoding="utf-8")
    current = [
        {
            "RuleID": "generic-password",
            "Description": "Generic password",
            "File": str(users),
            "StartLine": line,
            "StartColumn": 5,
            "Secret": "REDACTED",
        }
        for line in (2, 3)
    ]
    history = [{**finding, "Commit": "1234567890abcdef"} for finding in current]

    def fake_run(command, **_kwargs):
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
            result = scan_secrets(str(tmp_path))

    assert result.finding_count == 1
    assert len(result.dispositions) == 1
    assert result.dispositions[0].status == "NEEDS_REVIEW"
    assert result.dispositions[0].evidence_scope == "CURRENT_AND_HISTORY"
    assert result.dispositions[0].occurrence_count == 4
    assert result.telemetry["consolidated_credential_collection_findings"] == 3


def test_betterleaks_consolidates_identical_copied_secret_files(tmp_path):
    first = tmp_path / "terraform" / "networking.tf"
    second = tmp_path / "infrastructure" / "terraform" / "networking.tf"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    source = 'private_key = "[fixture secret]"\n'
    first.write_text(source, encoding="utf-8")
    second.write_text(source, encoding="utf-8")
    current = [
        {
            "RuleID": "private-key",
            "Description": "Private key",
            "File": str(path),
            "StartLine": 1,
            "Secret": "REDACTED",
        }
        for path in (first, second)
    ]

    def fake_run(command, **_kwargs):
        report_path = command[command.index("--report-path") + 1]
        findings = current if command[1] == "dir" else []
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
            result = scan_secrets(str(tmp_path))

    assert result.finding_count == 2
    assert len(result.issues) == 1
    assert [item.status for item in result.dispositions] == [
        "CONFIRMED",
        "DUPLICATE",
    ]
    assert result.dispositions[1].canonical_finding_id == (result.dispositions[0].finding_id)
    assert result.dispositions[0].occurrence_count == 2
    assert result.telemetry["duplicate_secret_locations"] == 1


def test_generic_api_key_public_blockchain_address_is_false_positive(tmp_path):
    source = tmp_path / "faucet.ts"
    source.write_text(
        "const tokenAddress = '0x1111111111111111111111111111111111111111'\n",
        encoding="utf-8",
    )
    finding = {
        "RuleID": "generic-api-key",
        "Description": "Generic API key",
        "File": str(source),
        "StartLine": 1,
        "Secret": "REDACTED",
    }

    def fake_run(command, **_kwargs):
        report_path = command[command.index("--report-path") + 1]
        findings = [finding] if command[1] == "dir" else []
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
            result = scan_secrets(str(tmp_path))

    assert result.dispositions[0].status == "FALSE_POSITIVE"
    assert "public blockchain address" in result.dispositions[0].reason


def test_secret_locations_on_same_line_keep_distinct_columns(tmp_path):
    source = tmp_path / "keys.py"
    source.write_text("first = get_secret(); second = get_secret()\n", encoding="utf-8")
    findings = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API key",
            "File": str(source),
            "StartLine": 1,
            "StartColumn": column,
            "Secret": "REDACTED",
        }
        for column in (1, 23)
    ]

    def fake_run(command, **_kwargs):
        report_path = command[command.index("--report-path") + 1]
        payload = findings if command[1] == "dir" else []
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump(payload, report)
        return CompletedProcess(args=command, returncode=1, stdout="", stderr="")

    with patch(
        "src.supplemental_scanners._executable",
        side_effect=lambda command, _environment: (
            "/bin/betterleaks" if command == "betterleaks" else None
        ),
    ):
        with patch("src.supplemental_scanners.subprocess.run", side_effect=fake_run):
            result = scan_secrets(str(tmp_path))

    assert result.finding_count == 2
    assert len({item.finding_id for item in result.dispositions}) == 2


def test_historical_public_address_match_stays_needs_review(tmp_path):
    source = tmp_path / "faucet.ts"
    source.write_text(
        "const tokenAddress = '0x1111111111111111111111111111111111111111'\n",
        encoding="utf-8",
    )
    finding = {
        "RuleID": "generic-api-key",
        "Description": "Generic API key",
        "File": str(source),
        "StartLine": 1,
        "Secret": "REDACTED",
    }

    def fake_run(command, **_kwargs):
        report_path = command[command.index("--report-path") + 1]
        payload = [finding] if command[1] == "dir" else [{**finding, "Commit": "abc"}]
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump(payload, report)
        return CompletedProcess(args=command, returncode=1, stdout="", stderr="")

    with patch(
        "src.supplemental_scanners._executable",
        side_effect=lambda command, _environment: (
            "/bin/betterleaks" if command == "betterleaks" else None
        ),
    ):
        with patch("src.supplemental_scanners.subprocess.run", side_effect=fake_run):
            result = scan_secrets(str(tmp_path))

    assert result.finding_count == 1
    assert result.dispositions[0].status == "NEEDS_REVIEW"
    assert result.dispositions[0].evidence_scope == "CURRENT_AND_HISTORY"


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
