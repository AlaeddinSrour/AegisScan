#!/usr/bin/env python3
"""Compare exported audit ledgers without running providers or changing reports."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.security_benchmark import evaluate, load_payload


def compare(paths, manifest):
    runs, ledgers, identities = [], [], []
    for path in paths:
        payload = json.loads(path.read_text())
        findings, telemetry = load_payload(path, payload)
        run = payload["runs"][0]
        properties = run["invocations"][0].get("properties", {})
        identities.append({key: properties.get(key) for key in (
            "repositoryCommit", "repositoryDirty", "semgrepRulesSha256", "semgrepRuleMode",
            "aiModels", "aiTriageEnabled", "scanExclusions", "maxTargetBytes",
        )})
        ledger = {}
        rules = {rule["id"]: rule for rule in run["tool"]["driver"].get("rules", [])}
        for finding, result in zip(findings, run.get("results", []), strict=True):
            key = finding.fingerprint or f"{finding.rule_id}:{finding.path}:{finding.line}"
            rule = rules.get(finding.rule_id, {})
            level = result.get("level", rule.get("defaultConfiguration", {}).get("level", "warning"))
            severity = result.get("properties", {}).get(
                "security-severity", rule.get("properties", {}).get("security-severity")
            )
            entry = (finding.rule_id, finding.status, finding.path, finding.line,
                     finding.suppressed, level, str(severity) if severity is not None else None)
            ledger.setdefault(key, []).append(entry)
        # Compare multisets: preserve repeated fingerprints and ignore result ordering.
        ledger = {key: tuple(sorted(entries, key=lambda entry: json.dumps(entry)))
                  for key, entries in ledger.items()}
        ledgers.append(ledger)
        score = evaluate(findings, manifest, telemetry)
        runs.append({"file": str(path), "version": run["tool"]["driver"].get("semanticVersion"),
                     "benchmark_passed": score["passed"], "metrics": score["metrics"]})
    keys = sorted(set().union(*(ledger.keys() for ledger in ledgers)))
    differences = [{"finding_id": key, "verdicts": [ledger.get(key) for ledger in ledgers]}
                   for key in keys if len({ledger.get(key) for ledger in ledgers}) > 1]
    comparable = all(identity == identities[0] for identity in identities)
    comparable = comparable and bool(identities[0]["repositoryCommit"])
    comparable = comparable and bool(identities[0]["semgrepRulesSha256"])
    comparable = comparable and identities[0]["repositoryDirty"] is False
    return {"runs": runs, "comparable_configuration": comparable,
            "same_app_version": len({run["version"] for run in runs}) == 1,
            "identical_exported_ledgers": not differences, "differences": differences,
            "scope": "Exported candidates only; omitted historical findings are not compared."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path, nargs="+")
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if len(args.reports) < 2:
        parser.error("Provide at least two SARIF reports")
    result = compare(args.reports, json.loads(args.manifest.read_text()))
    print(json.dumps(result, indent=2))
    return 0 if (result["comparable_configuration"] and result["same_app_version"]
                 and result["identical_exported_ledgers"]
                 and all(run["benchmark_passed"] for run in result["runs"])) else 1


if __name__ == "__main__":
    sys.exit(main())
