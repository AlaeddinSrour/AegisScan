import pytest
from src.diff import get_modified_lines


def test_simple_addition():
    """Single hunk with one added line."""
    patch = "@@ -1,3 +1,4 @@\n line1\n line2\n+new_line\n line3"
    result = get_modified_lines(patch)
    assert result == {3}


def test_multiple_additions():
    """Multiple added lines in a single hunk."""
    patch = "@@ -1,2 +1,4 @@\n line1\n+added1\n+added2\n line2"
    result = get_modified_lines(patch)
    assert result == {2, 3}


def test_deletion_does_not_count():
    """Deleted lines should not appear in the result."""
    patch = "@@ -1,3 +1,2 @@\n line1\n-deleted_line\n line2"
    result = get_modified_lines(patch)
    assert result == set()


def test_mixed_additions_and_deletions():
    """Mix of additions and deletions — only additions should be tracked."""
    patch = "@@ -1,4 +1,4 @@\n line1\n-old_line\n+new_line\n line2\n line3"
    result = get_modified_lines(patch)
    assert result == {2}


def test_multiple_hunks():
    """Two separate hunks in one patch."""
    patch = (
        "@@ -1,3 +1,4 @@\n line1\n+added_at_2\n line2\n line3\n"
        "@@ -10,3 +11,4 @@\n line10\n line11\n+added_at_13\n line12"
    )
    result = get_modified_lines(patch)
    assert result == {2, 13}


def test_empty_patch():
    """Empty patch string returns an empty set."""
    assert get_modified_lines("") == set()
    assert get_modified_lines(None) == set()


def test_file_headers_ignored():
    """--- and +++ file header lines should not affect line counting."""
    patch = "--- a/file.py\n+++ b/file.py\n@@ -1,2 +1,3 @@\n line1\n+added\n line2"
    result = get_modified_lines(patch)
    assert result == {2}


def test_trailing_empty_lines():
    """Trailing empty lines from split should not cause drift."""
    patch = "@@ -1,2 +1,3 @@\n line1\n+added\n line2\n"
    result = get_modified_lines(patch)
    assert result == {2}
