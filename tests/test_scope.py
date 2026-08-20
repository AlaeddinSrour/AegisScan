from src.scope import classify_code_role, load_ignore_patterns


def test_runtime_and_fixture_paths_are_distinguished():
    assert classify_code_role("routes/search.ts") == "RUNTIME"
    assert classify_code_role("data/static/codefixes/search_1.ts") == "FIXTURE"
    assert classify_code_role("tests/search.spec.ts") == "TEST"
    assert classify_code_role("dist/server.js") == "GENERATED"
    assert classify_code_role("frontend/src/assets/private/three.js") == "DEPENDENCY"
    assert classify_code_role("public/app.bundle.js") == "GENERATED"


def test_aegisscanignore_patterns_override_runtime_role():
    assert classify_code_role("custom/training.ts", ["custom/**"]) == "IGNORED"


def test_ignore_file_supports_comments_and_repo_relative_patterns(tmp_path):
    (tmp_path / ".aegisscanignore").write_text(
        "# training data\ndata/static/codefixes/**\n\n",
        encoding="utf-8",
    )
    assert load_ignore_patterns(tmp_path) == ["data/static/codefixes/**"]


def test_negated_scope_pattern_can_force_runtime_role():
    patterns = ["generated/**", "!generated/runtime/**"]
    assert classify_code_role("generated/cache/file.py", patterns) == "IGNORED"
    assert classify_code_role("generated/runtime/server.py", patterns) == "RUNTIME"
