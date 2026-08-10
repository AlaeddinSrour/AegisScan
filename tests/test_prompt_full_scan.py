from src.prompt import build_full_scan_prompt


def test_full_scan_prompt_does_not_require_a_diff():
    prompt = build_full_scan_prompt("Finding #1", "FILE app.py", 2, 4)
    assert "batch 2 of 4" in prompt
    assert "not a pull-request diff" in prompt
    assert "FILE app.py" in prompt
    assert "Finding #1" in prompt
    assert "exactly one `dispositions` entry" in prompt
    assert "Candidates must never disappear" in prompt
