#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.security_benchmark import evaluate, load_payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate AegisScan benchmark quality gates")
    parser.add_argument("--results", required=True, type=Path, help="SARIF or Semgrep JSON")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="Optional metrics JSON output")
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    payload = json.loads(args.results.read_text(encoding="utf-8"))
    findings, telemetry = load_payload(args.results, payload)
    report = evaluate(findings, manifest, telemetry)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
