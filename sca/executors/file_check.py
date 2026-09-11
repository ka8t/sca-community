"""
file_contains executor — checks for presence/absence of patterns in a file.

Two uses:
  - `matches()`: checks the conditions (returns bool) — used as a pre-filter
  - `execute()`: creates a file-level finding (line 1) if the conditions are met
"""
import re
import logging

logger = logging.getLogger("sca.executors.file_check")


def matches(file_contains: dict, content: str, filepath: str = "",
            line_count: int = 0) -> bool:
    """Check whether a file's content satisfies the file_contains conditions.

    Supported conditions:
    - has: ALL patterns must match in the content
    - not_has: NONE of the patterns must match
    - min_lines: the file must have at least N lines
    - path_contains: the relative path must contain the segment
    """
    has_patterns = file_contains.get("_compiled_has")
    not_has_patterns = file_contains.get("_compiled_not_has")

    # Fallback: compile on the fly if needed
    if has_patterns is None:
        try:
            has_patterns = [re.compile(p) for p in file_contains.get("has", [])]
        except re.error:
            return False
        file_contains["_compiled_has"] = has_patterns

    if not_has_patterns is None:
        try:
            not_has_patterns = [re.compile(p) for p in file_contains.get("not_has", [])]
        except re.error:
            return False
        file_contains["_compiled_not_has"] = not_has_patterns

    # All `has` conditions must match
    for pat in has_patterns:
        if not pat.search(content):
            return False

    # No `not_has` condition may match
    for pat in not_has_patterns:
        if pat.search(content):
            return False

    # min_lines: the file must have at least N lines
    min_lines = file_contains.get("min_lines", 0)
    if min_lines > 0 and line_count < min_lines:
        return False

    # path_contains: the relative path must contain the segment
    path_segments = file_contains.get("path_contains", [])
    if path_segments and filepath:
        fp_lower = filepath.lower().replace("\\", "/")
        if not any(seg.lower() in fp_lower for seg in path_segments):
            return False

    # not_path_has_file: the file's directory must NOT contain these files
    not_path_files = file_contains.get("not_path_has_file", [])
    if not_path_files and filepath:
        import os
        dir_path = os.path.dirname(filepath)
        for check_file in not_path_files:
            # Safety: reject names with path traversal
            if ".." in check_file or os.sep in check_file or "/" in check_file:
                continue
            found = False
            check_dir = dir_path
            for _ in range(5):  # max 5 levels up
                if os.path.exists(os.path.join(check_dir, check_file)):
                    found = True
                    break
                parent = os.path.dirname(check_dir)
                if parent == check_dir:
                    break
                check_dir = parent
            if found:
                return False  # Governance file exists → no finding

    return True


def execute(runner, rule: dict, filepath: str, content: str, all_lines: list):
    """Create a file-level finding (line 1) if the rule's file_contains conditions are met."""
    fc = rule.get("file_contains", {})

    if not matches(fc, content, filepath=filepath, line_count=len(all_lines)):
        return

    # file_contains convention: finding at line 1, code = first non-empty line
    first_match_line = 1
    code = ""
    if all_lines:
        for ln, txt in all_lines:
            if txt.strip():
                code = txt
                break

    rule_id = rule["id"]
    if runner._finding_exists(filepath, first_match_line, rule_id):
        return

    msg = runner._resolve_i18n(rule.get("message", {}))
    risk = runner._resolve_i18n(rule.get("risk", {}))
    solution = runner._resolve_i18n(rule.get("solution", {}))
    benefit = runner._resolve_i18n(rule.get("benefit", {}))

    runner._add_finding(
        rule["category"].upper(), msg, filepath, first_match_line, code,
        rule["severity"], risk, solution, benefit,
        confidence=rule.get("confidence", 80), rule_key=rule_id,
    )

    cat_key = rule["category"].upper()
    if cat_key in runner.categories:
        for f in runner.categories[cat_key].findings:
            if f.file == runner._rel(filepath) and f.line == first_match_line and f.rule_key == rule_id:
                f.rule_source = rule.get("_source", "json_builtin")
                break
