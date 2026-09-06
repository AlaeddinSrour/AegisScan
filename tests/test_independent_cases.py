import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from src.security_benchmark import evaluate, findings_from_semgrep


def test_independent_vulnerable_and_safe_cases(tmp_path):
    scanner = shutil.which("semgrep")
    if not scanner:
        pytest.skip("Semgrep is required for the independent detector benchmark")
    root = Path(__file__).resolve().parents[1]
    cases = shutil.copytree(root / "tests/fixtures/independent_cases", tmp_path / "independent_cases")
    env = os.environ.copy()
    env["SEMGREP_LOG_FILE"] = str(tmp_path / "semgrep.log")
    if Path("/etc/ssl/cert.pem").is_file():
        env.setdefault("SSL_CERT_FILE", "/etc/ssl/cert.pem")
    result = subprocess.run(
        [scanner, "scan", "--disable-version-check", "--metrics", "off", "--json", "--quiet",
         "--config", str(root / "src/aegisscan_rules.yml"),
         str(cases)],
        capture_output=True, text=True, timeout=60, env=env,
    )
    assert result.returncode == 0, result.stderr
    findings, telemetry = findings_from_semgrep(json.loads(result.stdout))
    manifest = json.loads((root / "benchmarks/independent-cases.json").read_text())
    metrics = evaluate(findings, manifest, telemetry)
    assert metrics["passed"], metrics
