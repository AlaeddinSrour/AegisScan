import json
from copy import deepcopy

import pytest

from scripts.compare_audits import compare
from src.reporting import build_sarif_payload
from tests.test_reporting import _outcome


def test_comparison_detects_location_and_configuration_drift(tmp_path):
    first, second = tmp_path / "first.sarif", tmp_path / "second.sarif"
    payload = build_sarif_payload(_outcome())
    first.write_text(json.dumps(payload))
    second.write_text(json.dumps(payload))
    manifest = {"expected": [], "gates": {}}
    assert compare([first, second], manifest)["identical_exported_ledgers"]
    payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] += 1
    payload["runs"][0]["invocations"][0]["properties"]["repositoryCommit"] = "different"
    second.write_text(json.dumps(payload))
    result = compare([first, second], manifest)
    assert not result["identical_exported_ledgers"]
    assert not result["comparable_configuration"]
    assert len(result["differences"]) == 1


def test_comparison_reports_app_version_drift(tmp_path):
    first, second = tmp_path / "first.sarif", tmp_path / "second.sarif"
    payload = build_sarif_payload(_outcome())
    first.write_text(json.dumps(payload))
    payload["runs"][0]["tool"]["driver"]["semanticVersion"] = "0.0.0"
    second.write_text(json.dumps(payload))
    result = compare([first, second], {"expected": [], "gates": {}})
    assert not result["same_app_version"]


@pytest.mark.parametrize("change", ["level", "score", "duplicate", "duplicate_verdict"])
def test_comparison_preserves_severity_and_duplicate_fingerprints(tmp_path, change):
    first, second = tmp_path / "first.sarif", tmp_path / "second.sarif"
    payload = build_sarif_payload(_outcome())
    first.write_text(json.dumps(payload))
    run = payload["runs"][0]
    if change == "level":
        run["results"][0]["level"] = "warning"
    elif change == "score":
        run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = "9.5"
    else:
        duplicate = deepcopy(run["results"][0])
        if change == "duplicate_verdict":
            duplicate["properties"]["status"] = "NEEDS_REVIEW"
        run["results"].insert(0, duplicate)
    second.write_text(json.dumps(payload))
    assert not compare([first, second], {"expected": [], "gates": {}})["identical_exported_ledgers"]


def test_reordering_duplicate_entries_does_not_change_comparison(tmp_path):
    first, second = tmp_path / "first.sarif", tmp_path / "second.sarif"
    payload = build_sarif_payload(_outcome())
    results = payload["runs"][0]["results"]
    duplicate = deepcopy(results[0])
    duplicate["properties"]["status"] = "NEEDS_REVIEW"
    results.append(duplicate)
    first.write_text(json.dumps(payload))
    results.reverse()
    second.write_text(json.dumps(payload))
    assert compare([first, second], {"expected": [], "gates": {}})["identical_exported_ledgers"]
