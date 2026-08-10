"""
Unified diff parser for extracting modified line numbers.

Parses GitHub-style unified diff patches to identify exactly which
lines were added or modified in the new version of a file.
"""

import re


from typing import Optional

def get_modified_lines(patch: Optional[str]) -> set[int]:
    """
    Parse a unified diff patch and return the set of line numbers
    (1-indexed, in the new file) that were added or modified.

    Handles:
        - @@ chunk headers to reset the line counter
        - '+' lines as additions (tracked and counted)
        - '-' lines as deletions (skipped, don't advance new-file counter)
        - ' ' context lines (advance the counter)
        - '---'/'+++' file headers (ignored)
        - Empty or unrecognized lines (advance the counter as context)
    """
    modified_lines: set[int] = set()
    if not patch:
        return modified_lines

    current_line = 0
    for line in patch.split('\n'):
        if line.startswith('@@'):
            m = re.search(r'\+([0-9]+)', line)
            if m:
                current_line = int(m.group(1))
        elif line.startswith('+++') or line.startswith('---'):
            # File header lines — skip
            continue
        elif line.startswith('+'):
            modified_lines.add(current_line)
            current_line += 1
        elif line.startswith('-'):
            # Deleted lines don't advance the new-file line counter
            continue
        else:
            # Context lines (starting with ' ') and any unrecognized lines
            # advance the counter to stay in sync with the new file
            current_line += 1

    return modified_lines
