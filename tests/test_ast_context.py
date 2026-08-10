from src.ast_context import build_ast_context


def test_build_ast_context_maps_definitions_imports_and_calls(tmp_path):
    source = tmp_path / "service.py"
    source.write_text(
        "import os\n\ndef load():\n    return os.getenv('TOKEN')\n",
        encoding="utf-8",
    )
    context = build_ast_context(tmp_path, ["service.py"])
    assert "Imports: os" in context
    assert "function load@3" in context
    assert "load -> os.getenv@4" in context


def test_build_ast_context_ignores_traversal(tmp_path):
    assert build_ast_context(tmp_path, ["../outside.py"]) == ""
