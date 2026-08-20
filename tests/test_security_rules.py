import json
import os
from collections import Counter
from pathlib import Path
import shutil
import subprocess

import pytest

from src.semgrep_runner import _aegisscan_rules_path, normalize_rule_id


def test_bundled_ssrf_and_toctou_rules_detect_only_vulnerable_fixtures(tmp_path):
    semgrep = shutil.which("semgrep")
    if not semgrep:
        pytest.skip("Semgrep is not installed in this test environment")

    fixtures = Path(__file__).parent / "fixtures"
    targets = [
        fixtures / "ssrf_toctou_vulnerable.py",
        fixtures / "ssrf_toctou_safe.py",
        fixtures / "ssrf_toctou_vulnerable.js",
        fixtures / "ssrf_toctou_safe.js",
        fixtures / "ssrf_toctou_vulnerable.go",
        fixtures / "ssrf_toctou_safe.go",
        fixtures / "SsrfToctouVulnerable.java",
        fixtures / "SsrfToctouSafe.java",
        fixtures / "SsrfToctouVulnerable.cs",
        fixtures / "SsrfToctouSafe.cs",
    ]
    environment = os.environ.copy()
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["SEMGREP_LOG_FILE"] = str(tmp_path / "semgrep.log")
    certificate_store = Path("/etc/ssl/cert.pem")
    if certificate_store.is_file():
        environment.setdefault("SSL_CERT_FILE", str(certificate_store))

    result = subprocess.run(
        [
            semgrep,
            "scan",
            "--disable-version-check",
            "--metrics",
            "off",
            "--config",
            str(_aegisscan_rules_path()),
            "--json",
            "--quiet",
            *(str(target) for target in targets),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    findings = Counter(
        (Path(item["path"]).name, item["check_id"].split("src.")[-1])
        for item in payload["results"]
    )

    expected_findings = Counter({
        (
            "ssrf_toctou_vulnerable.py",
            "aegisscan.python.user-input-to-network-request",
        ): 1,
        (
            "ssrf_toctou_vulnerable.py",
            "aegisscan.python.filesystem-check-then-use",
        ): 2,
        (
            "ssrf_toctou_vulnerable.js",
            "aegisscan.javascript.user-input-to-network-request",
        ): 1,
        (
            "ssrf_toctou_vulnerable.js",
            "aegisscan.javascript.filesystem-check-then-use",
        ): 2,
        (
            "ssrf_toctou_vulnerable.go",
            "aegisscan.go.user-input-to-network-request",
        ): 1,
        (
            "ssrf_toctou_vulnerable.go",
            "aegisscan.go.filesystem-check-then-use",
        ): 2,
        (
            "SsrfToctouVulnerable.java",
            "aegisscan.java.user-input-to-network-request",
        ): 1,
        (
            "SsrfToctouVulnerable.java",
            "aegisscan.java.filesystem-check-then-use",
        ): 2,
        (
            "SsrfToctouVulnerable.cs",
            "aegisscan.csharp.user-input-to-network-request",
        ): 1,
        (
            "SsrfToctouVulnerable.cs",
            "aegisscan.csharp.filesystem-check-then-use",
        ): 2,
    })
    assert findings == expected_findings
    assert len(payload["results"]) == sum(expected_findings.values())
    assert payload["errors"] == []


def test_juice_shop_regression_floor_covers_high_value_javascript_categories(
    tmp_path,
):
    semgrep = shutil.which("semgrep")
    if not semgrep:
        pytest.skip("Semgrep is not installed in this test environment")

    fixtures = Path(__file__).parent / "fixtures"
    targets = [
        fixtures / "juice_shop_regression_vulnerable.ts",
        fixtures / "juice_shop_regression_safe.ts",
    ]
    environment = os.environ.copy()
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["SEMGREP_LOG_FILE"] = str(tmp_path / "semgrep.log")
    certificate_store = Path("/etc/ssl/cert.pem")
    if certificate_store.is_file():
        environment.setdefault("SSL_CERT_FILE", str(certificate_store))
    result = subprocess.run(
        [
            semgrep,
            "scan",
            "--disable-version-check",
            "--metrics",
            "off",
            "--config",
            str(_aegisscan_rules_path()),
            "--json",
            "--quiet",
            *(str(target) for target in targets),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    findings = Counter(
        (Path(item["path"]).name, normalize_rule_id(item["check_id"]))
        for item in payload["results"]
    )
    expected = Counter(
        {
            (
                "juice_shop_regression_vulnerable.ts",
                "aegisscan.javascript.express-command-injection",
            ): 1,
            (
                "juice_shop_regression_vulnerable.ts",
                "aegisscan.javascript.express-path-traversal",
            ): 1,
            (
                "juice_shop_regression_vulnerable.ts",
                "aegisscan.javascript.express-code-injection",
            ): 1,
            (
                "juice_shop_regression_vulnerable.ts",
                "aegisscan.javascript.express-unsafe-deserialization",
            ): 1,
            (
                "juice_shop_regression_vulnerable.ts",
                "aegisscan.javascript.express-id-to-data-access",
            ): 1,
            (
                "juice_shop_regression_vulnerable.ts",
                "aegisscan.javascript.express-response-xss",
            ): 1,
        }
    )
    assert findings == expected
    assert payload["errors"] == []
