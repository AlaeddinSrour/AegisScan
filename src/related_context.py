"""Bounded cross-file context for JavaScript and TypeScript audit findings."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .redaction import redact_text


_SOURCE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_IMPORT_RE = re.compile(
    r"\bimport\s+(?P<clause>[^;\n]+?)\s+from\s+['\"](?P<module>\.{1,2}/[^'\"]+)['\"]"
)
_REQUIRE_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<clause>[^=\n]+?)\s*=\s*require\(\s*['\"]"
    r"(?P<module>\.{1,2}/[^'\"]+)['\"]\s*\)"
)


def _contained_file(root: Path, source: Path, module: str) -> Path | None:
    base = (source.parent / module).resolve()
    candidates = [base]
    if not base.suffix:
        candidates.extend(base.with_suffix(suffix) for suffix in _SOURCE_SUFFIXES)
        candidates.extend(base / f"index{suffix}" for suffix in _SOURCE_SUFFIXES)
    for candidate in candidates:
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.is_file() and candidate.suffix.casefold() in _SOURCE_SUFFIXES:
            return candidate
    return None


def _imported_symbols(clause: str, source_text: str) -> list[str]:
    symbols: list[str] = []
    namespace = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", clause)
    if namespace:
        alias = namespace.group(1)
        symbols.extend(
            match.group(1)
            for match in re.finditer(
                rf"\b{re.escape(alias)}\.([A-Za-z_$][\w$]*)\s*\(", source_text
            )
        )
    named = re.search(r"\{([^}]+)\}", clause)
    if named:
        for item in named.group(1).split(","):
            imported = item.strip().split()[0] if item.strip() else ""
            if imported:
                symbols.append(imported)
    destructured = re.search(r"\{([^}]+)\}", clause)
    if destructured and "require(" in source_text:
        symbols.extend(
            item.strip().split(":", 1)[0].strip()
            for item in destructured.group(1).split(",")
            if item.strip()
        )
    return list(dict.fromkeys(symbols))


def _definition_excerpt(text: str, symbol: str) -> tuple[int, str] | None:
    lines = text.splitlines()
    definition = re.compile(
        rf"\b(?:export\s+)?(?:async\s+)?(?:const|let|var|function|class)\s+"
        rf"{re.escape(symbol)}\b"
    )
    for index, line in enumerate(lines):
        if not definition.search(line):
            continue
        start = max(0, index - 18)
        end = min(len(lines), index + 24)
        numbered = "\n".join(
            f"{line_number:>5} | {lines[line_number - 1]}"
            for line_number in range(start + 1, end + 1)
        )
        return index + 1, numbered
    return None


def build_related_context(
    repo_path: str | Path,
    relative_paths: Iterable[str],
    *,
    max_characters: int = 30_000,
) -> str:
    """Return imported helper definitions used by JS/TS files in a finding batch."""
    root = Path(repo_path).resolve()
    sections: list[str] = []
    used = 0

    for relative_path in sorted(set(relative_paths)):
        if Path(relative_path).suffix.casefold() not in _SOURCE_SUFFIXES:
            continue
        source = (root / relative_path).resolve()
        try:
            source.relative_to(root)
        except ValueError:
            continue
        if not source.is_file() or source.stat().st_size > 2_000_000:
            continue
        try:
            source_text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        imports = [*_IMPORT_RE.finditer(source_text), *_REQUIRE_RE.finditer(source_text)]
        for imported in imports:
            target = _contained_file(root, source, imported.group("module"))
            if target is None or target == source or target.stat().st_size > 2_000_000:
                continue
            try:
                target_text = target.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for symbol in _imported_symbols(imported.group("clause"), source_text):
                excerpt = _definition_excerpt(target_text, symbol)
                if excerpt is None:
                    continue
                definition_line, body = excerpt
                target_relative = target.relative_to(root).as_posix()
                section = redact_text(
                    f"RELATED MODULE {relative_path} -> {target_relative}\n"
                    f"Imported helper: {symbol} (definition near line {definition_line})\n"
                    f"{body}"
                )
                if used + len(section) > max_characters:
                    return "\n\n".join(sections)
                sections.append(section)
                used += len(section)

    return "\n\n".join(dict.fromkeys(sections))
