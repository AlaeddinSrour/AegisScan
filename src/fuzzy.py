"""Conservative code replacement for reviewed, AI-suggested patches."""

from __future__ import annotations

import re
import textwrap


def _lines(value: str) -> list[str]:
    """Return logical lines without discarding relative indentation."""
    return value.strip("\r\n").splitlines()


def _normalized_block(lines: list[str]) -> list[str]:
    """Normalize a block's common margin while retaining nested indentation."""
    if not lines:
        return []
    dedented = textwrap.dedent("\n".join(line.rstrip() for line in lines)).splitlines()
    return [line.rstrip() for line in dedented]


def fuzzy_replace(
    content: str,
    original: str,
    replacement: str,
    *,
    target_line: int | None = None,
) -> tuple[str, bool]:
    """Replace one unambiguous block while preserving relative indentation.

    ``target_line`` is one-indexed and anchors duplicate snippets to the reviewed
    finding. If no anchored match exists, a replacement is allowed only when the
    snippet occurs exactly once in the file.
    """
    orig_lines = _lines(original)
    repl_lines = _lines(replacement)
    if not orig_lines or not repl_lines:
        return content, False

    content_lines = content.split("\n")
    window_size = len(orig_lines)
    normalized_original = _normalized_block(orig_lines)
    matches: list[int] = []

    for index in range(len(content_lines) - window_size + 1):
        window = content_lines[index : index + window_size]
        if _normalized_block(window) == normalized_original:
            matches.append(index)

    if target_line is not None and target_line > 0:
        target_index = target_line - 1
        anchored = [
            index
            for index in matches
            if index <= target_index < index + window_size
        ]
        if len(anchored) == 1:
            match_index = anchored[0]
        elif anchored:
            return content, False
        elif len(matches) == 1:
            match_index = matches[0]
        else:
            return content, False
    elif len(matches) == 1:
        match_index = matches[0]
    else:
        return content, False

    first_line = content_lines[match_index]
    leading_whitespace = re.match(r"^[ \t]*", first_line).group(0)
    normalized_replacement = _normalized_block(repl_lines)
    replacement_with_margin = [
        leading_whitespace + line if line else ""
        for line in normalized_replacement
    ]
    content_lines[match_index : match_index + window_size] = replacement_with_margin
    return "\n".join(content_lines), True
