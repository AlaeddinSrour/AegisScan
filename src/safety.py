"""
Safety validator for AI-synthesized auto-fix patches.

Enforces deterministic patch cleansing by blocking dangerous patterns
that an LLM might introduce: dynamic evaluation, unvetted sub-processes,
loose permissions, unsafe deserialization, and obfuscated imports.
"""

import ast
import re


def is_suggested_fix_safe(suggested_fix: str) -> tuple[bool, str]:
    """
    Validate that an AI-synthesized fix does not introduce dangerous patterns.

    Returns:
        (True, "") if the fix is safe.
        (False, reason) if the fix contains a blocked pattern.
    """
    if not suggested_fix.strip():
        return False, "Suggested fix is empty."
    if len(suggested_fix) > 20_000 or len(suggested_fix.splitlines()) > 12:
        return False, "Suggested fix exceeds the bounded automatic-patch size."

    # 1. Dynamic evaluations
    dynamic_eval_patterns = [
        (r'\b(eval|exec)\s*\(', "raw dynamic evaluation block ('eval' or 'exec')"),
        (r'\b__import__\s*\(', "obfuscated dynamic import via __import__()"),
    ]
    for pattern, description in dynamic_eval_patterns:
        if re.search(pattern, suggested_fix, re.IGNORECASE):
            return False, f"Suggested fix contains {description}."

    # 2. Unvetted sub-processes or command execution
    subprocess_patterns = [
        (
            r'\b(os\.system|os\.popen|os\.spawn|pty\.spawn)\b',
            "unvetted sub-process or command execution",
        ),
        (
            r'\bshell\s*=\s*True\b',
            "shell=True subprocess execution (command injection risk)",
        ),
    ]
    for pattern, description in subprocess_patterns:
        if re.search(pattern, suggested_fix, re.IGNORECASE):
            return False, f"Suggested fix contains {description}."

    destructive_patterns = [
        (
            r"\b(?:shutil\.)?rmtree\s*\(|\b(?:os\.)?(?:remove|unlink|rmdir|removedirs)\s*\(",
            "destructive filesystem deletion",
        ),
        (r"\b(?:requests|httpx|urllib3|aiohttp)\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(",
         "a network request that requires manual destination validation"),
        (r"\b(?:fetch|axios\s*\.\s*(?:get|post|put|patch|delete))\s*\(",
         "a network request that requires manual destination validation"),
        (
            r"\b(?:child_process\s*\.\s*(?:exec|execFile|spawn|fork)|Deno\.Command|Bun\.spawn)\s*\(",
            "process execution that requires manual argument validation",
        ),
        (
            r"\b(?:fs\s*\.\s*(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)|Deno\.remove)\s*\(",
            "destructive filesystem deletion",
        ),
    ]
    for pattern, description in destructive_patterns:
        if re.search(pattern, suggested_fix, re.IGNORECASE):
            return False, f"Suggested fix contains {description}."

    # 3. Unsafe deserialization
    deserialization_patterns = [
        (r'\bpickle\.(loads?|Unpickler)\s*\(', "unsafe pickle deserialization"),
        (r'\bmarshal\.loads?\s*\(', "unsafe marshal deserialization"),
        (
            r'\byaml\.load\s*\([^)]*\)',
            "yaml.load() without SafeLoader (use yaml.safe_load())",
        ),
    ]
    for pattern, description in deserialization_patterns:
        match = re.search(pattern, suggested_fix)
        if match:
            # Allow yaml.load if SafeLoader/CSafeLoader is explicitly specified
            if 'yaml.load' in (match.group(0) if match else ''):
                if re.search(r'Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader', suggested_fix):
                    continue
            return False, f"Suggested fix contains {description}."

    # 4. Loose system/file permissions
    permission_patterns = [
        (r'\b0[oO]?[0-7]*[7]{2,}[0-7]*\b', "highly permissive octal permissions (e.g. 777)"),
        (r'\b777\b', "highly permissive numeric permissions (777)"),
        (
            r'\b(stat\.S_IRWXO|stat\.S_IRWXG)\b',
            "loose group/other read-write-execute permissions",
        ),
    ]
    for pattern, description in permission_patterns:
        if re.search(pattern, suggested_fix):
            return False, f"Suggested fix contains {description}."

    # Python snippets get an additional structural subprocess check. Syntax is
    # validated after insertion because a one-line fragment may not parse alone.
    try:
        tree = ast.parse(suggested_fix)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _python_call_name(node.func)
            if name not in {
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.check_call",
                "subprocess.check_output",
            }:
                continue
            if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
                return False, "Suggested subprocess call does not use a literal argument list."
            elements = node.args[0].elts
            if not elements or not isinstance(elements[0], ast.Constant) or not isinstance(elements[0].value, str):
                return False, "Suggested subprocess executable is not a fixed literal."
            for keyword in node.keywords:
                if keyword.arg == "shell" and not (
                    isinstance(keyword.value, ast.Constant) and keyword.value.value is False
                ):
                    return False, "Suggested subprocess call does not enforce shell=False."

    return True, ""


def _python_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""
