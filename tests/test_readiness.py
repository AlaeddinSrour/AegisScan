from src.readiness import inspect_scanner_readiness, missing_required_scanners


def test_readiness_prefers_betterleaks_and_marks_enabled_scanners_required(
    monkeypatch,
):
    executables = {
        "semgrep": "/tools/semgrep",
        "osv-scanner": "/tools/osv-scanner",
        "betterleaks": "/tools/betterleaks",
        "gitleaks": "/tools/gitleaks",
    }
    monkeypatch.setattr(
        "src.readiness._resolve",
        lambda command, _environment: executables.get(command),
    )
    monkeypatch.setattr(
        "src.readiness._version_text", lambda command: f"version:{command[0]}"
    )

    statuses = inspect_scanner_readiness()

    assert [status.available for status in statuses] == [True, True, True]
    assert [status.required for status in statuses] == [True, True, True]
    assert statuses[2].name == "Betterleaks"
    assert statuses[2].executable == "/tools/betterleaks"
    assert statuses[2].version == "version:/tools/betterleaks"
    assert missing_required_scanners(statuses) == []


def test_readiness_uses_gitleaks_fallback_and_ignores_disabled_optional_tools(
    monkeypatch,
):
    executables = {
        "semgrep": "/tools/semgrep",
        "osv-scanner": None,
        "betterleaks": None,
        "gitleaks": "/tools/gitleaks",
    }
    monkeypatch.setattr(
        "src.readiness._resolve",
        lambda command, _environment: executables.get(command),
    )

    statuses = inspect_scanner_readiness(
        dependency_enabled=False,
        secret_enabled=True,
        include_versions=False,
    )

    assert statuses[1].required is False
    assert statuses[2].name == "Gitleaks fallback"
    assert statuses[2].executable == "/tools/gitleaks"
    assert missing_required_scanners(statuses) == []


def test_readiness_reports_missing_required_scanners(monkeypatch):
    monkeypatch.setattr(
        "src.readiness._resolve", lambda _command, _environment: None
    )

    statuses = inspect_scanner_readiness(include_versions=False)

    assert [status.key for status in missing_required_scanners(statuses)] == [
        "semgrep",
        "osv",
        "secrets",
    ]
