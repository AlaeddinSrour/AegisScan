from src.models import FindingDisposition, ReviewIssue, ReviewReport
from src.prompt import build_full_scan_prompt
from src.redaction import REDACTED_SECRET, redact_review_report, redact_text


PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\\r\\n"
    "MIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8"
    "\\r\\n-----END RSA PRIVATE KEY-----"
)


def test_redact_text_removes_pem_hmac_named_and_known_tokens():
    source = (
        f"const privateKey = '{PRIVATE_KEY}'\n"
        "crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj')\n"
        "api_key = 'AIzaSyExampleTokenThatMustNeverLeave'\n"
        "url = 'https://user:password@example.test/path'\n"
    )

    redacted = redact_text(source)

    assert PRIVATE_KEY not in redacted
    assert "pa4qacea4VK9t9nGv7yZtwmj" not in redacted
    assert "AIzaSyExampleTokenThatMustNeverLeave" not in redacted
    assert "user:password@" not in redacted
    assert redacted.count(REDACTED_SECRET) >= 4


def test_redact_text_removes_a_truncated_pem_header_from_evidence():
    redacted = redact_text("'-----BEGIN RSA PRIVATE KEY-----\\r\\n...'")

    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert REDACTED_SECRET in redacted


def test_full_scan_prompt_scrubs_repository_context_before_provider_call():
    prompt = build_full_scan_prompt(
        f"Code Snippet: const privateKey = '{PRIVATE_KEY}'",
        "function configure() { password: 'super-secret-password' }",
        1,
        1,
    )

    assert PRIVATE_KEY not in prompt
    assert "super-secret-password" not in prompt
    assert REDACTED_SECRET in prompt


def test_review_report_redaction_covers_retained_and_exported_fields():
    issue = ReviewIssue(
        file="security.ts",
        line=1,
        severity="HIGH",
        issue_name="Hardcoded private key",
        description=f"Embedded key {PRIVATE_KEY}",
        original_code=f"const privateKey = '{PRIVATE_KEY}'",
        suggested_fix="const privateKey = process.env.JWT_PRIVATE_KEY",
        source_evidence=PRIVATE_KEY,
        sink_evidence="Used to sign tokens.",
        reachability_evidence="Authorization uses the key.",
    )
    report = ReviewReport(
        analysis_scratchpad=f"Found {PRIVATE_KEY}",
        issues=[issue],
        dispositions=[
            FindingDisposition(
                finding_id="SG-key",
                status="CONFIRMED",
                reason=f"Source contains {PRIVATE_KEY}",
                message=f"Hardcoded key {PRIVATE_KEY}",
            )
        ],
    )

    redacted = redact_review_report(report)
    serialized = redacted.model_dump_json()

    assert PRIVATE_KEY not in serialized
    assert REDACTED_SECRET in serialized
    assert PRIVATE_KEY in report.issues[0].original_code
