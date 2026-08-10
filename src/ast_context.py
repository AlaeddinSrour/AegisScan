"""Lightweight Python AST summaries used to enrich full-scan batches."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable


class _StructureVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: list[str] = []
        self.imports: list[str] = []
        self.definitions: list[str] = []
        self.calls: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        self.imports.extend(alias.name for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(f"{module}.{alias.name}".strip("."))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified = ".".join([*self.scope, node.name])
        self.definitions.append(f"class {qualified}@{node.lineno}")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = ".".join([*self.scope, node.name])
        self.definitions.append(f"function {qualified}@{node.lineno}")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Call(self, node: ast.Call) -> None:
        called = _call_name(node.func)
        if called:
            caller = ".".join(self.scope) or "<module>"
            self.calls.append(f"{caller} -> {called}@{node.lineno}")
        self.generic_visit(node)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def build_ast_context(repo_path: str | Path, relative_paths: Iterable[str]) -> str:
    """Return concise import/definition/call summaries for Python files in a batch."""
    root = Path(repo_path).resolve()
    sections: list[str] = []

    for relative_path in sorted(set(relative_paths)):
        if not relative_path.endswith(".py"):
            continue
        candidate = (root / relative_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if not candidate.is_file() or candidate.stat().st_size > 2_000_000:
            continue

        try:
            tree = ast.parse(candidate.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError, ValueError) as exc:
            sections.append(f"FILE {relative_path}\nAST unavailable: {type(exc).__name__}")
            continue

        visitor = _StructureVisitor()
        visitor.visit(tree)
        imports = ", ".join(list(dict.fromkeys(visitor.imports))[:40]) or "none"
        definitions = "; ".join(visitor.definitions[:80]) or "none"
        calls = "; ".join(visitor.calls[:120]) or "none"
        sections.append(
            f"FILE {relative_path}\n"
            f"Imports: {imports}\n"
            f"Definitions: {definitions}\n"
            f"Call edges: {calls}"
        )

    return "\n\n".join(sections)
