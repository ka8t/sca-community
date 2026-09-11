"""
regex executor — line-by-line or multi-line (context-N) pattern matching.

Extracted from rule_engine.py. Called by the orchestrator for every rule
containing `patterns`.
"""
import logging
import re

logger = logging.getLogger("sca.executors.regex")

# Comment syntax per language, used only to blank out comment content before
# checking pattern-not/with (never before the primary `pattern` match -- see
# _strip_comments_from_lines).
_LINE_COMMENT = {
    "python": "#", "yaml": "#", "dockerfile": "#",
    "javascript": "//", "java": "//", "csharp": "//", "php": "//",
}
_BLOCK_COMMENT = {
    "javascript": (r"/\*", r"\*/"),
    "java": (r"/\*", r"\*/"),
    "csharp": (r"/\*", r"\*/"),
    "php": (r"/\*", r"\*/"),
    "html": (r"<!--", r"-->"),
}

# Rules whose pattern-not/with legitimately depends on comment syntax itself
# (the safe case *is* a comment, not code) -- found by running the full
# fixture suite after adding comment-stripping above: gha_version_comment_missing's
# safe case is precisely a version-pinned action *with* a "# v4.1.1"-style
# comment next to the pinned SHA. A hardcoded, explicit set rather than a new
# DSL flag: one rule needs this today, easy to extend if another ever does.
_COMMENT_STRIP_EXEMPT_RULES = {"gha_version_comment_missing"}


def _strip_comments_from_lines(all_lines: list, language: str) -> list:
    """Return `all_lines` with comment content blanked out, for pattern-not/
    with checks only.

    A comment merely *describing* the code (a docstring, a fixture header
    naming the rule it tests) can otherwise coincidentally contain a
    pattern-not's trigger word and wrongly suppress a real finding -- found
    twice this way on real builtin fixtures once pattern-not started looking
    backward too (see sca/executors/dataflow_adapter.py's neighbor commit
    history for the backward-context fix this exposed). The primary
    `pattern` search and the finding's reported code snippet both keep using
    the original, unstripped `all_lines` -- some rules (e.g. todo_unresolved)
    intentionally match *inside* comments.

    Regex-based, no string-literal awareness -- consistent with the rest of
    this line/block matcher, and safe to over-strip: worst case, pattern-not
    sees slightly less text, which can only make it stricter, never looser
    (a real, code-level safety token immediately next to a comment could in
    principle get nicked at the boundary, but that's the same class of
    approximation this whole matcher already accepts elsewhere).
    """
    block = _BLOCK_COMMENT.get(language)
    if block:
        # Block comments can span multiple lines: strip across the whole
        # file text first (replacing the match with the same number of
        # newlines, to keep every line's number aligned), then re-split.
        # Each line already carries its own trailing "\n" (source: readlines()
        # in sca/utils.py::read_file) -- joining with "" reconstructs the
        # original text exactly; joining with an extra "\n" would insert a
        # blank line between every pair and silently desync line numbers.
        full_text = "".join(text for _, text in all_lines)
        full_text = re.sub(
            f"{block[0]}.*?{block[1]}",
            lambda m: "\n" * m.group(0).count("\n"),
            full_text, flags=re.DOTALL,
        )
        stripped = full_text.split("\n")
    else:
        stripped = [text for _, text in all_lines]

    marker = _LINE_COMMENT.get(language)
    if marker:
        prefix = re.escape(marker)
        stripped = [re.sub(f"{prefix}.*$", "", text) for text in stripped]

    return list(zip((ln for ln, _ in all_lines), stripped))


def execute(runner, rule: dict, filepath: str, all_lines: list):
    """Run a regex rule against a file. Creates one finding per occurrence."""
    patterns = rule.get("patterns", [])
    if not patterns:
        return

    if rule.get("id") in _COMMENT_STRIP_EXEMPT_RULES:
        clean_lines = all_lines
    else:
        clean_lines = _strip_comments_from_lines(all_lines, rule.get("language", ""))

    negative_patterns = [
        p["_compiled_pattern-not"]
        for p in patterns
        if p.get("_compiled_pattern-not") is not None
    ]

    # candidates: dict line_num → context_text (text used to check pattern-not)
    candidates = {}

    for p in patterns:
        compiled = p.get("_compiled")
        if compiled is None:
            continue

        match_scope = p.get("match", "line")
        compiled_with = p.get("_compiled_with")
        compiled_not = p.get("_compiled_pattern-not")

        if match_scope == "file":
            # File scope: pattern-not checked against the entire file
            full_content = "\n".join(line for _, line in all_lines)
            clean_content = "\n".join(line for _, line in clean_lines)
            if compiled_not and compiled_not.search(clean_content):
                continue
            if compiled_with and not compiled_with.search(clean_content):
                continue
            for line_num, line in all_lines:
                if compiled.search(line):
                    candidates[line_num] = clean_content

        elif match_scope == "line":
            for (line_num, line), (_, clean_line) in zip(all_lines, clean_lines):
                if compiled.search(line):
                    if compiled_with and not compiled_with.search(clean_line):
                        continue
                    candidates[line_num] = clean_line

        elif match_scope.startswith("context-"):
            try:
                window = int(match_scope.split("-")[1])
            except (IndexError, ValueError):
                window = 6

            n_lines = len(all_lines)
            for start_idx in range(n_lines):
                block_end = min(start_idx + window, n_lines)
                block_text = "".join(
                    line for _, line in all_lines[start_idx:block_end]
                )
                if not block_text:
                    continue

                m = compiled.search(block_text)
                if not m:
                    continue

                clean_block_text = "".join(
                    line for _, line in clean_lines[start_idx:block_end]
                )
                if compiled_with and not compiled_with.search(clean_block_text):
                    continue

                local_start = m.start()
                start_line = all_lines[start_idx][0] + block_text.count(
                    "\n", 0, local_start
                )
                # block_text is forward-biased (it only ever extends from
                # start_idx towards later lines), so pattern-not could never
                # see a guard/sanitizer declared on an earlier line -- widening
                # `window` does not help, since the winning (last-overwritten)
                # start_idx is always the one closest to the match itself.
                # Fold in up to `window` lines BEFORE the match line as well,
                # purely additive: forward reach (and thus every other rule's
                # already-calibrated behavior) is unchanged, backward reach is
                # newly available to pattern-not.
                match_idx = start_line - all_lines[0][0]
                back_start = max(0, match_idx - window)
                clean_backward_text = "".join(
                    line for _, line in clean_lines[back_start:match_idx]
                )
                candidates[start_line] = clean_backward_text + clean_block_text

    if not candidates:
        return

    rule_id = rule["id"]
    msg = runner._resolve_i18n(rule.get("message", {}))
    risk = runner._resolve_i18n(rule.get("risk", {}))
    solution = runner._resolve_i18n(rule.get("solution", {}))
    benefit = runner._resolve_i18n(rule.get("benefit", {}))

    for line_num in sorted(candidates):
        if line_num - 1 >= len(all_lines) or line_num < 1:
            continue
        line_text = all_lines[line_num - 1][1]
        context_text = candidates[line_num]

        # Check pattern-not against the context (block or line depending on scope)
        if any(neg.search(context_text) for neg in negative_patterns):
            continue

        if runner._finding_exists(filepath, line_num, rule_id):
            continue

        runner._add_finding(
            rule["category"].upper(), msg, filepath, line_num, line_text,
            rule["severity"], risk, solution, benefit,
            confidence=rule.get("confidence", 80), rule_key=rule_id,
        )

        cat_key = rule["category"].upper()
        if cat_key in runner.categories:
            for f in runner.categories[cat_key].findings:
                if f.file == runner._rel(filepath) and f.line == line_num and f.rule_key == rule_id:
                    f.rule_source = rule.get("_source", "json_builtin")
                    break
