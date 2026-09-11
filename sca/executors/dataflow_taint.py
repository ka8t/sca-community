"""Bridge between the SCA `.sca` DSL and the dataflow engine.

Clean-room implementation based on sca/docs/dataflow-spec.md §10
and CONTRACT-SCA-AUDITAI.md §3.1.

No semgrep OCaml source was read to write this module.

Overview:
    Exposes the stable public API `run_taint_rule(rule_json, content, filename,
    language)`, conforming to contract §3.1. The compiled SCA rule (internal
    JSON format with regex patterns) is converted into `RuleSpecs` in dataflow
    format (dotted glob patterns), then run over the content's CFG + IR.

Known limitations:
    - The regex → dotted conversion is *best-effort*. Overly complex patterns
      (lookahead, backreferences, etc.) fall back to a `**` pattern
      (over-approximation) or produce 0 findings.
    - The Python stdlib AST is used. For other languages, see Phase 8.
"""
from __future__ import annotations

import ast
import logging
import os
import re
from dataclasses import replace
from typing import Iterable, List, Optional, Tuple

from sca.dataflow.cfg import build_cfg
from sca.dataflow.lattice import SourceInfo, Tainted, empty_state, state_set
from sca.dataflow.summary import (
    collect_functions,
    compute_file_summaries,
    function_to_sub_module,
    route_source_params,
)
from sca.dataflow.transfer import (
    Finding,
    PassthroughSpec,
    RuleSpecs,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
)
from sca.dataflow.worklist import analyze


logger = logging.getLogger("sca.dataflow.executor")


# ============================================================================
# Contract §3.4 exceptions
# ============================================================================

class UnsupportedLanguage(Exception):
    """Raised when `language` is not supported by the dataflow engine."""

    def __init__(self, language: str) -> None:
        super().__init__(f"language not supported by dataflow engine: {language!r}")
        self.language = language


# ============================================================================
# Java dataflow engine — merged with the lexical engine by default
#
# The Java dataflow engine (sca/dataflow/java_*.py) reached its quality
# gate on OWASP BenchmarkJava (F1 99.9%, recall 100%, round 8, 2026-07-27)
# then was validated against 4 real-world corpora (WebGoat 94.4%,
# spring-petclinic, spring-boot-realworld-example-app, JeecgBoot ~495
# files — 0 new false positive). Explicit decision (2026-07-28): do NOT
# choose between the two Java engines, run BOTH of them and merge their
# results — `sca/rule_engine.py::_integrate_taint_flow` already natively
# deduplicates by (file, line, rule_key), no merge code to write. This
# variable remains a FALLBACK switch (name unchanged, polarity flipped) to
# revert to the lexical engine alone if an issue emerged on real code not
# yet encountered — never observed so far. Detail: docs/ROADMAP.md § v2.0.0.
# ============================================================================

def java_dataflow_engine_enabled() -> bool:
    """Return whether the Java dataflow engine should run alongside the lexical engine."""
    return os.environ.get("SCA_JAVA_DATAFLOW_ENGINE", "1") not in ("0", "false", "False")


# ============================================================================
# C# dataflow engine — validation-only, NOT merged with the lexical engine
# by default (opposite polarity from Java's switch, deliberately: the C#
# engine has not yet passed the same quality gate Java's did — see
# `sca/dataflow/csharp_cfg.py`/`csharp_summary.py`/
# `sca/executors/dataflow_taint_csharp.py` module docstrings and
# `docs/ROADMAP.md`). Opt-in, so `scripts/eval_juliet_csharp.py` can
# exercise it (`SCA_CSHARP_DATAFLOW_ENGINE=1 python3 scripts/eval_juliet_csharp.py`)
# without touching what every other caller of `run_taint_rule` sees.
# ============================================================================

def csharp_dataflow_engine_enabled() -> bool:
    """Return whether the C# dataflow engine should run alongside the lexical engine."""
    return os.environ.get("SCA_CSHARP_DATAFLOW_ENGINE", "0") not in ("0", "false", "False")


# ============================================================================
# Public API
# ============================================================================

def run_taint_rule(
    rule_json: dict,
    content: str,
    filename: str = "",
    language: str = "python",
    precomputed_summaries: Optional[dict] = None,
    extra_summaries: Optional[dict] = None,
) -> Iterable[Finding]:
    """Run a single SCA taint rule against source content.

    Conforms to CONTRACT-SCA-AUDITAI.md §3.1.

    Args:
        rule_json: compiled SCA rule (internal format with `mode`,
            `sources`, `sinks`, etc. as produced by sca.rule_loader).
        content: source to analyze.
        filename: file name (for reporting only, not used for parsing).
        language: language of the content ("python" as of Phase 4).
        precomputed_summaries: intra-file summary sheets already computed
            (Volet 3 — pre-pass). If given, avoids recomputing them here.
        extra_summaries: **cross-file** summary sheets (Volet 3), indexed by
            the local call name (e.g. `helper` for `from b import helper`).
            Merged into the specs; local functions take priority over
            imports on name collision (a local def shadows an import).

    Yields:
        A Finding for each detected vulnerability.

    Raises:
        UnsupportedLanguage: if language is not one of the supported values.
    """
    # Error case — see contract §3.4
    if language != "python":
        # SCA Community Edition: Python-only taint engine. The full
        # multi-language engine (Java/C#/PHP/JavaScript) is part of
        # the commercial offering — see codefixture.com.
        raise UnsupportedLanguage(language)

    mode = rule_json.get("mode", "")
    if mode not in ("taint", "regex+taint"):
        # This module only handles taint rules
        return

    sources = rule_json.get("sources", [])
    sinks = rule_json.get("sinks", [])
    if not sources or not sinks:
        # Incomplete rule → empty list (contract §3.4)
        return

    # file_contains pre-check: if the rule declares `has`/`not_has`,
    # filter BEFORE the costly analysis. Lets us gate taint_xxe on the
    # presence of `setFeature(external_ges, True)`, etc.
    fc = rule_json.get("file_contains") or {}
    for pat in fc.get("has", []):
        try:
            if not re.search(pat, content):
                return
        except re.error:
            pass
    for pat in fc.get("not_has", []):
        try:
            if re.search(pat, content):
                return
        except re.error:
            pass

    # DSL → RuleSpecs conversion
    specs = rule_json_to_specs(rule_json)
    if specs is None:
        return

    # For Python: full pipeline (Phase 1-7)
    # Parse the content. On syntax error → empty list (contract §3.4).
    try:
        tree = ast.parse(content, filename=filename or "<dataflow>")
    except SyntaxError:
        logger.debug("dataflow_taint: syntax error in %s", filename)
        return

    # Phase 7 — precompute the source lines for hybrid regex matching
    source_lines = content.splitlines()

    # Part 2 — intra-file function summaries: for each function, how taint
    # flows through its calls (tainted return, params reaching a sink).
    # eval_call consults them to connect source-in-function-A →
    # sink-in-function-B. Part 3 — the cross-file pre-pass can supply these
    # already computed (precomputed_summaries) and add the summaries of
    # imported functions (extra_summaries). Local functions take priority
    # over imported ones.
    functions = collect_functions(tree)
    if precomputed_summaries is not None:
        summaries = dict(precomputed_summaries)
    else:
        summaries = compute_file_summaries(
            tree, specs, language=language, source_lines=source_lines,
        )
    if extra_summaries:
        merged = dict(extra_summaries)
        merged.update(summaries)  # local takes precedence over cross-file
        summaries = merged
    if summaries:
        specs = replace(specs, summaries=summaries)

    # Module-level analysis (Phase 1-5)
    cfg = build_cfg(tree)
    result = analyze(cfg, specs, language=language, source_lines=source_lines)
    all_findings: List[Finding] = list(result.findings)

    # Phase 6 — intra-file interprocedural: analyze each FunctionDef as a
    # sub-module (FunctionDef is no longer opaque as of Phase 6).
    # Spec §8 — function summaries via sub-analysis.
    for fn in functions:
        try:
            sub_module = function_to_sub_module(fn)
            sub_cfg = build_cfg(sub_module)
            # Web route handlers: path/query parameters (annotated scalars)
            # are user-controlled. Seed them as Tainted(http) in the
            # sub-analysis's entry state so their use as a sink is detected
            # (FastAPI/Flask/Starlette).
            init_state = None
            route_params = route_source_params(fn)
            if route_params:
                fn_line = getattr(fn.ast_def, "lineno", 0)
                init_state = empty_state()
                for pname in route_params:
                    init_state = state_set(init_state, pname, Tainted(
                        kinds=frozenset({"http"}),
                        source=SourceInfo(
                            line=fn_line,
                            expr=f"{fn.name}({pname})",
                            kind="http",
                        ),
                    ))
            sub_result = analyze(
                sub_cfg, specs, initial_state=init_state,
                language=language, source_lines=source_lines,
            )
        except Exception as exc:
            # Robustness: if a function breaks the analysis (bug), continue
            # with the others. Contract §3.4: internal bug → propagates the
            # original exception in strict mode, but here we just drop the
            # findings for this one function so as not to lose the others.
            logger.debug(
                "dataflow_taint: analyse de %s a échoué : %s", fn.name, exc
            )
            continue
        all_findings.extend(sub_result.findings)

    # Global dedup. Key: (rule_id, line, source_line).
    # `sink_text` is deliberately excluded because it varies between dotted
    # matching (callee name) and hybrid regex matching (full line).
    seen = set()
    lines = content.splitlines()
    for f in all_findings:
        key = (f.rule_id, f.line, f.source_line)
        if key in seen:
            continue
        seen.add(key)
        sink_line_text = ""
        if 0 < f.line <= len(lines):
            sink_line_text = lines[f.line - 1].strip()
        yield Finding(
            rule_id=f.rule_id,
            severity=f.severity,
            line=f.line,
            column=f.column,
            sink_text=sink_line_text or f.sink_text,
            source_line=f.source_line,
            message=f.message,
            cwe=f.cwe,
            flow=f.flow,
            source_kind=f.source_kind,
        )


# ============================================================================
# rule_json → RuleSpecs conversion
# ============================================================================

def _safe_compile_regex(pattern: str):
    """Compile a regex, returning None if it is invalid."""
    try:
        return re.compile(pattern)
    except (re.error, TypeError):
        return None


def rule_json_to_specs(rule_json: dict) -> Optional[RuleSpecs]:
    """Convert a compiled SCA rule into dataflow `RuleSpecs`.

    Best-effort conversion: for each regex pattern, generates 1..N dotted
    patterns interpretable by the dataflow engine.

    Returns:
        RuleSpecs, or None if the rule has no convertible pattern.
    """
    sources: List[SourceSpec] = []
    sinks: List[SinkSpec] = []
    sanitizers: List[SanitizerSpec] = []
    passthroughs: List[PassthroughSpec] = []

    # Pre-compile each `dotted` glob once (hot-path perf, see
    # transfer.compile_glob_pattern). Avoids ~144M `re.escape` calls measured
    # via cProfile on a customer-project audit (171s → estimated ~25s).
    from sca.dataflow.transfer import compile_glob_pattern

    for s in rule_json.get("sources", []):
        regex = s.get("pattern", "")
        kind = s.get("kind", "unknown")
        compiled = _safe_compile_regex(regex)
        for dotted in regex_to_dotted_patterns(regex):
            sources.append(SourceSpec(
                pattern=dotted, kind=kind,
                raw_regex=compiled,
                compiled=compile_glob_pattern(dotted),
            ))

    for s in rule_json.get("sinks", []):
        regex = s.get("pattern", "")
        # The .sca DSL produces `arg_index: 0` (int) by default on each sink.
        # `args: [...]` (list of indices) is also accepted for backward
        # compatibility. When `arg_index=0` is explicit, the sink check is
        # restricted to the 1st arg: e.g. `cur.execute("SELECT ?", (bar,))`
        # stays safe because `bar` is in arg 1.
        args_idx = s.get("args")
        if args_idx is not None:
            args = tuple(args_idx)
        else:
            single = s.get("arg_index")
            args = (single,) if single is not None else ()
        kinds_filter = tuple(s.get("kinds", ())) if s.get("kinds") else ()
        compiled = _safe_compile_regex(regex)
        for dotted in regex_to_dotted_patterns(regex):
            sinks.append(SinkSpec(
                pattern=dotted, args=args, kinds=kinds_filter,
                raw_regex=compiled,
                compiled=compile_glob_pattern(dotted),
            ))

    for s in rule_json.get("sanitizers", []):
        regex = s.get("pattern", "")
        compiled = _safe_compile_regex(regex)
        for dotted in regex_to_dotted_patterns(regex):
            sanitizers.append(SanitizerSpec(
                pattern=dotted,
                raw_regex=compiled,
                compiled=compile_glob_pattern(dotted),
            ))

    for s in rule_json.get("passthroughs", []):
        regex = s.get("pattern", "")
        compiled = _safe_compile_regex(regex)
        for dotted in regex_to_dotted_patterns(regex):
            passthroughs.append(PassthroughSpec(
                pattern=dotted,
                raw_regex=compiled,
                compiled=compile_glob_pattern(dotted),
            ))

    if not sources or not sinks:
        return None

    # Extract message + metadata
    message_block = rule_json.get("message", {})
    if isinstance(message_block, dict):
        # i18n format: EN is used as the default
        message = message_block.get("en") or next(iter(message_block.values()), "")
    else:
        message = str(message_block) if message_block else ""

    metadata = rule_json.get("metadata", {}) or {}
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None

    return RuleSpecs(
        # SCA compiles the rule with the `id` key. `rule_id` is kept as a
        # fallback for compatibility with any external formats.
        rule_id=rule_json.get("id") or rule_json.get("rule_id", ""),
        severity=rule_json.get("severity", "MEDIUM"),
        cwe=cwe,
        message=message,
        sources=tuple(sources),
        sinks=tuple(sinks),
        sanitizers=tuple(sanitizers),
        passthroughs=tuple(passthroughs),
    )


# ============================================================================
# regex → dotted patterns converter (heuristic)
# ============================================================================

# Regex noise characters to strip to get a readable dotted name
_REGEX_NOISE_RE = re.compile(
    r"\\s\*"                # \s*
    r"|\\b"                 # \b (anchor)
    r"|\\s\+"               # \s+
    r"|\\\("                # \(
    r"|\\\)"                # \)
    r"|\\\["                # \[
    r"|\\\]"                # \]
    r"|\(\?\:"              # (?: non-capturing group opening
)

# Opening markers of lookaround assertions (?=, (?!, (?<=, (?<!.
# Unlike (?: (non-capturing group, stripped by _REGEX_NOISE_RE while
# keeping the content), a lookaround carries a constraint that has no
# equivalent in the dotted model (no negation/context) -- the ENTIRE group
# must be removed (balanced parentheses included), not just the opening
# marker. Otherwise the orphaned closing parenthesis and the content (often
# an alternation `a|b`) are misinterpreted downstream by
# `_expand_alternations`, which treats them as a normal group and produces
# corrupted patterns (bug found in taint_xss.sca: sinks
# `(?<!System\.(?:out|err))\.print\s*\(` converted into gibberish such as
# `<!System.out).print`, `err).print` -- zero XSS sink recognized by the
# interprocedural dataflow engine).
_LOOKAROUND_OPEN_RE = re.compile(r"\(\?<?[=!]")


def _strip_lookaround_groups(pattern: str) -> str:
    """Strip lookaround groups (?=...), (?!...), (?<=...), (?<!...) in full
    (balanced parentheses), keeping the rest of the pattern intact.

    Best-effort: removing a context constraint over-approximates the pattern
    (it now also matches cases the lookaround excluded) -- consistent with
    this converter's documented approach to overly complex regexes (see
    module docstring).
    """
    out = []
    i = 0
    n = len(pattern)
    while i < n:
        m = _LOOKAROUND_OPEN_RE.match(pattern, i)
        if not m:
            out.append(pattern[i])
            i += 1
            continue
        depth = 1
        j = m.end()
        while j < n and depth > 0:
            if pattern[j] == "(":
                depth += 1
            elif pattern[j] == ")":
                depth -= 1
            j += 1
        i = j  # skip the whole group, including the closing parenthesis
    return "".join(out)


def regex_to_dotted_patterns(regex_str: str) -> List[str]:
    r"""Best-effort conversion of an SCA DSL regex into a list of dotted patterns.

    Heuristics:
        (?=...), (?!...), (?<=...), (?<!...) are stripped entirely (no dotted
                                    equivalent, over-approximation)
        \s*, \s+, \b, \(, \), \[, \] are removed (regex noise)
        \.                          → .
        \w+, \w*, .*                → *
        (a|b|c)                     → multiple patterns, one per alternative
        ^pattern                    → pattern (leading anchor ignored)
        .method (suffix)            → **.method (matches any prefix)

    If the result still contains unhandled regex characters, it is returned
    as-is (the dataflow matcher does its best with it).

    Returns:
        List of dotted patterns (can be empty if the regex is too opaque).
    """
    if not regex_str:
        return []

    # Step 0: strip lookaround groups in full (before the rest, so no
    # orphaned parentheses are left for _expand_alternations)
    regex_str = _strip_lookaround_groups(regex_str)
    # Step 1: strip the noise
    clean = _REGEX_NOISE_RE.sub("", regex_str)
    # Step 2: `\.` → `.`
    clean = clean.replace(r"\.", ".")
    # Step 3: anchors
    clean = clean.lstrip("^").rstrip("$")
    # Step 4: ` = ` has no meaning as a pattern, strip it
    clean = clean.split("=")[0].strip()
    # Step 5: expand the alternations (a|b|c)
    patterns = _expand_alternations(clean)

    # Step 6: finalize each pattern
    out: List[str] = []
    for p in patterns:
        p = _finalize_dotted(p)
        if p:
            out.append(p)

    return out


def _expand_alternations(pattern: str) -> List[str]:
    """Expand alternation groups `(a|b|c)` into multiple patterns.

    Limited to the simplest groups (no deep nesting).
    """
    # Find the FIRST `(...)` group with a `|` inside it and expand over its
    # alternatives. Recursive on the result.
    open_paren = pattern.find("(")
    if open_paren < 0:
        return [pattern]
    # Find the matching closing parenthesis
    depth = 0
    close_paren = -1
    for i in range(open_paren, len(pattern)):
        if pattern[i] == "(":
            depth += 1
        elif pattern[i] == ")":
            depth -= 1
            if depth == 0:
                close_paren = i
                break
    if close_paren < 0:
        # Unbalanced parenthesis: leave as-is
        return [pattern]

    inside = pattern[open_paren + 1 : close_paren]
    if "|" not in inside:
        # No alternation in this group → keep it fixed and move to the next one
        # Strategy: treat "()" as "" and recurse on the remainder.
        before = pattern[:open_paren]
        after = pattern[close_paren + 1 :]
        # Replace `(x)` with `x` (simple capturing group)
        return _expand_alternations(before + inside + after)

    before = pattern[:open_paren]
    after = pattern[close_paren + 1 :]
    alternatives = inside.split("|")
    out: List[str] = []
    for alt in alternatives:
        out.extend(_expand_alternations(before + alt + after))
    return out


def _finalize_dotted(pattern: str) -> str:
    r"""Final cleanup pass on a dotted pattern.

    - Removes `?` (optional — ignored, over-approximated)
    - `\w+`, `\w*`, `.*`, `.+` → `*`
    - Trims whitespace
    - If it starts with `.`, prefixes `**` to match any prefix
    """
    # Replace regex wildcards with `*`
    pattern = re.sub(r"\\w[\+\*]?", "*", pattern)
    pattern = re.sub(r"\.[\+\*]", "*", pattern)
    pattern = pattern.replace("?", "")
    # Several consecutive `*` → `*`
    pattern = re.sub(r"\*+", "*", pattern)
    pattern = pattern.strip()
    # If nothing is left, or only `.`, ignore
    if not pattern or set(pattern) <= {".", "*"}:
        return ""
    # ".method"-style pattern (suffix) → prefix with **
    if pattern.startswith("."):
        pattern = "**" + pattern
    return pattern
