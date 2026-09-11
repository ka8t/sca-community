"""Transfer functions for the SCA dataflow engine.

Clean-room implementation based on sca/docs/dataflow-spec.md §5 and §7.
Algorithms inspired by:
  - Nielson, Nielson, Hankin — Principles of Program Analysis (Springer 2005, ch. 2.4)
  - Schwartz, Avgerinos, Brumley — All You Ever Wanted to Know About Dynamic
    Taint Analysis (IEEE S&P 2010)

No reading of semgrep's OCaml code was done to write this module.

Overview:
    For each IR instruction (Assign, Call, Return, Raise, Branch, Noop),
    we define `tf(stmt, state) → (state', findings)` which computes the
    next state and emits 0..N findings.

    Rule specs (sources/sinks/sanitizers/passthroughs) are looked up via
    `resolve_spec(callee_name, specs)`, which returns a `SpecKind`
    (SOURCE/SINK/SANITIZER/PASSTHROUGH/UNKNOWN).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Pattern, Tuple

from sca.dataflow.ir import (
    Assign,
    AttrLhs,
    AttrRef,
    BinOp,
    Bool,
    Branch,
    Call,
    CallRef,
    Cmp,
    Const,
    DictRef,
    IfExp,
    IRStmt,
    LHS,
    LambdaRef,
    ListRef,
    Noop,
    RHS,
    Raise,
    Return,
    SetRef,
    Star,
    StarLhs,
    SubscriptLhs,
    SubscriptRef,
    TupleLhs,
    TupleRef,
    UnaryOp,
    VarLhs,
    VarRef,
    canon_callee,
    canon_lhs,
    canon_rhs,
    pretty_rhs,
)
from sca.dataflow.lattice import (
    CLEAN,
    State,
    Tainted,
    Taint,
    SourceInfo,
    is_clean,
    is_tainted,
    is_top,
    join,
    state_get,
    state_set,
)


# Terminator of a guard sanitizer: the line following `if not <san>(x): ...`
# must contain one of these calls for the block to be considered a guard
# (the downstream sink is no longer reached if the predicate fails).
_GUARD_TERMINATOR_RE = re.compile(
    r"\b(?:abort|raise|return|exit|sys\.exit|os\._exit)\b"
)

# `!` negation (Java/C#/JS style, e.g. `if (!isValid(x))`) as an alternative
# to Python's `not`/`in`. Excludes `!=` (not a negation of the sanitizer call).
_NEGATION_BANG_RE = re.compile(r"!(?!=)")

# Reassignment to a literal in a guard `if (!check(x)) x = "literal";`
# (same physical line as the if-condition). Mirrors the terminator idiom:
# the guard fails open to a safe hardcoded value instead of aborting.
_GUARD_REASSIGN_SAMELINE_RE = re.compile(
    r"\)\s*\{?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:[\"'][^\"']*[\"']|[+-]?[0-9]+|null|None|undefined|true|false)"
)

# Same idiom, but as the whole next line (multi-line guard body:
# `if (!check(x)) {` / `x = "literal";`). Anchored at line start since
# it's a standalone statement, not a continuation of `)`.
_GUARD_REASSIGN_NEXTLINE_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:[\"'][^\"']*[\"']|[+-]?[0-9]+|null|None|undefined|true|false)\s*;"
)

# Strip string literals before searching for a tainted variable name as a
# raw substring (`_aux_match_line`, Phase 7/10bis hybrid regex matching) —
# without this, a literal that coincidentally contains the name of a
# tainted variable (e.g. `"select ip from ..."` when the tainted variable
# is called `ip`) triggers a false-positive sink match/false guard cleanup,
# unrelated to the real data flow. Same pattern and same rationale as
# `lexical_taint.py::_STRING_LIT_STRIP_RE` — not imported from this module
# to avoid making `transfer.py` (the engine core, shared by Python/Java)
# depend on the Java/JS/PHP/C# lexical front-end.
_STRING_LIT_STRIP_RE = re.compile(
    r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\''
)  # sca-ignore:redos_nested_quantifier,redos_vulnerable — each repetition of (?:\\.[^"\\]*)* starts on a literal backslash excluded from the previous group: unambiguous partitioning, no exponential backtracking (standard escaped-string pattern)


def _strip_plain_string_literals(text: str) -> str:
    """Strip plain string literals from `text`, but keep interpolated ones intact.

    Like `_STRING_LIT_STRIP_RE.sub`, but leaves any literal containing
    `{`/`}` untouched — a Python f-string (`f'Hello {bar}'`) or a JS
    template (`` `Hello ${bar}` ``) carries a REAL variable reference inside
    the quotes (interpolation), not a coincidental text match: stripping it
    would break legitimate XSS detection on `return f'...{bar}...'`
    (regression caught by `test_fstring_return_still_flags`). A "flat"
    literal without `{`/`}` (e.g. SQL text) is still stripped normally."""
    return _STRING_LIT_STRIP_RE.sub(
        lambda m: m.group(0) if ("{" in m.group(0) or "}" in m.group(0)) else " ",
        text,
    )


def _backward_aliased_var(var_name: str, guard_ids, lineno: int, source_lines) -> bool:
    """Check the preceding 10 lines for `<id> = ...<var_name>...` where `<id>` is a guard identifier.

    Returns True if such an aliasing assignment is found.
    """
    for back in range(1, 11):
        idx_back = lineno - 1 - back
        if idx_back < 0:
            return False
        prev = source_lines[idx_back]
        for gid in guard_ids:
            assign_re = re.compile(
                r"^\s*" + re.escape(gid) + r"\s*=.*\b" + re.escape(var_name) + r"\b"
            )
            if assign_re.search(prev):
                return True
    return False


def _apply_guard_cleanup(state, line_text: str, lineno: int, source_lines):
    """Clean tainted variables implicated by a guard `if EXPR: …return`.

    Step 1: directly clean tainted vars mentioned in the guard line.
    Step 2: backward aliasing — for each identifier in the guard, scan the
    preceding 10 lines for an assignment `<id> = ...<var>...`; if found,
    clean `<var>` too. Covers the pattern
    `url = urlparse(bar); if url.netloc in [...]: return; redirect(bar)`.
    """
    for var_name in list(state.keys()):
        if var_name in line_text and is_tainted(state[var_name]):
            state = state_set(state, var_name, CLEAN)
    guard_ids = set(re.findall(r"\b([a-zA-Z_]\w*)\b", line_text))
    for var_name in list(state.keys()):
        if not is_tainted(state[var_name]):
            continue
        if _backward_aliased_var(var_name, guard_ids, lineno, source_lines):
            state = state_set(state, var_name, CLEAN)
    return state


# Mutation methods: a call-statement `obj.<method>(..., tainted, ...)`
# propagates taint onto `obj` (models list.append, dict[]=, set.add,
# configparser.set, etc.). Limited to statements to avoid noise on
# normal expressions.
# Key-indexed write methods (dict, configparser…). The targeted state slot
# is `obj['k']` if the key is constant, otherwise `obj[*]` (wildcard).
_INDEXED_WRITE_METHODS = frozenset({
    "set", "setdefault", "__setitem__",
    "put",  # Round 7 (Java) — java.util.Map.put(k, v), no equivalently
            # named method on the Python side, so no collision risk.
})

# Bulk-update methods via dict or kwargs. Each (k, v) pair is indexed
# individually; if the argument is an unknown object, it falls back to
# `obj[*]`.
_BULK_UPDATE_METHODS = frozenset({"update"})

# Write methods that add an element with no identifiable key
# (`list.append`, `set.add`…). The taint lands in `obj[*]`.
_ELEMENT_WRITE_METHODS = frozenset({
    "append", "extend", "insert", "add",
})

# Methods where the receiver IS the container (IO stream). The taint
# stays on the direct receiver `obj`.
_RECEIVER_WRITE_METHODS = frozenset({
    "write", "writelines",
})

# Union used to identify that a call must trigger a mutation propagation
# (the precise dispatch then depends on the category above).
_MUTATION_METHODS = (
    _INDEXED_WRITE_METHODS | _BULK_UPDATE_METHODS
    | _ELEMENT_WRITE_METHODS | _RECEIVER_WRITE_METHODS
)


# Key-indexed read methods. A Const key gives `obj['k']`; a dynamic key
# gives `obj[*]`. The read always includes the wildcard to pick up prior
# dynamic writes.
_INDEXED_READ_METHODS = frozenset({
    "get", "__getitem__", "setdefault", "pop",
})


def _key_repr(rhs: RHS) -> str:
    """Canonical representation of an access key, for use in state keys.

    Const(value) → `repr(value)` (literal). Any other expression → `'*'`
    (wildcard). Aligned with `ir._canon_subscript_key` to stay consistent
    with the keys generated by SubscriptLhs / SubscriptRef.
    """
    if isinstance(rhs, Const):
        return repr(rhs.value)
    return "*"


# ============================================================================
# Spec format
# ============================================================================

class SpecKind(Enum):
    """Category a callee resolves to when matched against a rule's specs."""

    SOURCE = "source"
    SINK = "sink"
    SANITIZER = "sanitizer"
    PASSTHROUGH = "passthrough"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SourceSpec:
    """A taint-source pattern: any callee/attribute matching it produces tainted data."""

    pattern: str
    kind: str = "unknown"
    raw_regex: Optional[Pattern[str]] = None    # Phase 7 — regex on source line
    compiled: Optional[Pattern[str]] = None     # Pre-compiled glob (`compile_glob_pattern`)


@dataclass(frozen=True)
class SinkSpec:
    """A taint-sink pattern: reaching it with tainted args emits a finding."""

    pattern: str
    args: Tuple[int, ...] = ()                  # () = all args
    kinds: Tuple[str, ...] = ()                 # () = all kinds
    raw_regex: Optional[Pattern[str]] = None    # Phase 7 — regex on source line
    compiled: Optional[Pattern[str]] = None     # Pre-compiled glob


@dataclass(frozen=True)
class SanitizerSpec:
    """A sanitizer pattern: matching it clears the taint of its return value (and optionally args)."""

    pattern: str
    args: Tuple[int, ...] = ()                  # rarely used: args whose state is also cleaned
    raw_regex: Optional[Pattern[str]] = None    # Phase 7 — regex on source line
    compiled: Optional[Pattern[str]] = None     # Pre-compiled glob


@dataclass(frozen=True)
class PassthroughSpec:
    """A passthrough pattern: propagates the taint of selected args to the return (or a mutated arg)."""

    pattern: str
    args_in: Tuple[int, ...] = ()               # () = all
    arg_out: Any = "return"                     # "return" or index of the mutated arg
    raw_regex: Optional[Pattern[str]] = None    # Phase 7 — regex on source line
    compiled: Optional[Pattern[str]] = None     # Pre-compiled glob


@dataclass(frozen=True)
class RuleSpecs:
    """The full set of specs for a taint rule."""
    rule_id: str = ""
    severity: str = "MEDIUM"
    cwe: Optional[str] = None
    message: str = ""
    sources: Tuple[SourceSpec, ...] = ()
    sinks: Tuple[SinkSpec, ...] = ()
    sanitizers: Tuple[SanitizerSpec, ...] = ()
    passthroughs: Tuple[PassthroughSpec, ...] = ()
    # Part 2 — interprocedural function summaries, indexed by function name.
    # Populated by `run_taint_rule` before the main analysis pass;
    # consulted in `eval_call` to propagate taint across calls.
    summaries: Dict[str, Any] = field(default_factory=dict)
    # Java only (round 5 calibration) — local variable → simple name of its
    # declared class (e.g. "scr" -> "SeparateClassRequest"), to resolve
    # `scr.method()` to the `SeparateClassRequest.method` summary when the
    # direct lookup by variable name fails. Always empty for Python (no
    # behavior change) — Python has no static per-local-variable type
    # declaration to exploit this way.
    type_map: Dict[str, str] = field(default_factory=dict)


# ============================================================================
# Finding
# ============================================================================

@dataclass(frozen=True)
class FlowStep:
    """A single step (source, propagation, or sink) in a finding's reported taint flow."""

    line: int
    kind: str           # "source" | "propagation" | "sink"
    text: str = ""


@dataclass(frozen=True)
class Finding:
    """A reported taint finding, conforming to the internal rule-generation contract doc §3.2."""
    rule_id: str
    severity: str
    line: int
    column: int = 0
    sink_text: str = ""
    source_line: Optional[int] = None
    message: str = ""
    cwe: Optional[str] = None
    flow: Tuple[FlowStep, ...] = ()
    source_kind: str = "unknown"


# ============================================================================
# Pattern matching (spec §7.1)
# ============================================================================

def compile_glob_pattern(pattern: str) -> Pattern[str]:
    """Compile an SCA glob pattern into a regex for fast `fullmatch`.

    Supported glob syntax:
        - `foo`           : exact match
        - `foo.bar`       : exact dotted
        - `foo.*`         : any direct child of foo (1 segment)
        - `*.execute`     : any execute method (1 segment before)
        - `**.execute`    : any execute method at any depth (≥1 segment)

    Note: `*` does NOT cross dots. Use `**` to cross them.

    Call this **once** per pattern (at DSL rule → RuleSpecs conversion
    time). `Spec` objects then carry the compiled regex and
    `match_pattern` uses it directly — avoids the 144M `re.escape` /
    10.7M recompilations measured via cProfile.
    """
    if "*" not in pattern:
        # Pure literal pattern — always `re.escape` at compile time.
        return re.compile(re.escape(pattern))
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*" and i + 1 < len(pattern) and pattern[i + 1] == "*":
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^.]*")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out))


def match_pattern(callee_name: str, compiled: Pattern[str]) -> bool:
    """Match a dotted name against a pre-compiled glob regex (spec §7.1).

    The pattern must be pre-compiled via `compile_glob_pattern`. This
    function is on the hot path (10M+ calls per audit on customer-project) — any regex
    construction at call time was moved to compilation time.
    """
    return compiled.fullmatch(callee_name) is not None


# ============================================================================
# Spec resolution
# ============================================================================

def _spec_compiled(spec) -> Pattern[str]:
    """Return a spec's pre-compiled regex, compiling it on the fly if absent.

    Covers the case of a `Spec` created outside `rule_json_to_specs`.
    """
    return spec.compiled if spec.compiled is not None else compile_glob_pattern(spec.pattern)


def _check_source_match(name: str, specs: RuleSpecs, lineno: int) -> Optional[Taint]:
    """Return a Tainted value if `name` matches a source spec, else None.

    Lets pure AttrRefs (e.g. `request.GET`) be treated as sources without
    requiring a call.
    """
    for s in specs.sources:
        if match_pattern(name, _spec_compiled(s)):
            return Tainted(
                kinds=frozenset({s.kind}),
                source=SourceInfo(line=lineno, expr=name, kind=s.kind),
            )
    return None


def resolve_spec(
    callee_name: str, specs: RuleSpecs
) -> Tuple[SpecKind, Optional[object]]:
    """Resolve a callee name to its (kind, spec) against a rule's specs.

    Priority (spec §5.2):
        SOURCE > SINK > SANITIZER > PASSTHROUGH > UNKNOWN

    Note: a function can be both a source and a sink across different
    rules, but standard semantics apply the priority above within a single
    rule. Multi-role cases generally require several rules.
    """
    for s in specs.sources:
        if match_pattern(callee_name, _spec_compiled(s)):
            return (SpecKind.SOURCE, s)
    for s in specs.sinks:
        if match_pattern(callee_name, _spec_compiled(s)):
            return (SpecKind.SINK, s)
    for s in specs.sanitizers:
        if match_pattern(callee_name, _spec_compiled(s)):
            return (SpecKind.SANITIZER, s)
    for s in specs.passthroughs:
        if match_pattern(callee_name, _spec_compiled(s)):
            return (SpecKind.PASSTHROUGH, s)
    return (SpecKind.UNKNOWN, None)


# ============================================================================
# RHS evaluation (spec §5.1)
# ============================================================================

def eval_rhs(rhs: RHS, state: State, specs: RuleSpecs,
             findings: List[Finding], lineno: int = 0) -> Taint:
    """Compute the taint of an RHS expression in the current abstract state.

    Spec §5.1 (transfer function table by RHS type).

    Args:
        rhs: expression to evaluate.
        state: current dataflow state.
        specs: rule specs (used to resolve calls).
        findings: list accumulating emitted findings (mutated in place).
        lineno: line of the parent statement (for SourceInfo, if applicable).

    Returns:
        The taint of the expression.
    """
    if isinstance(rhs, Const):
        return CLEAN

    if isinstance(rhs, VarRef):
        # Source by direct name (e.g. `request` in `request.GET` is read via
        # AttrRef, but a source could be a plain VarRef — rare but possible).
        src_taint = _check_source_match(rhs.name, specs, lineno)
        if src_taint is not None:
            return src_taint
        # Phase 9.bis — Aggregate indexed sub-entries: if `obj['k']` is
        # tainted in state, reading `obj` as a whole (e.g. `sink(obj)`,
        # `'{}'.format(obj)`) must pick up that taint.
        base = state_get(state, rhs.name)
        prefix = rhs.name + "["
        for key, t in state.items():
            if key.startswith(prefix):
                base = join(base, t)
        return base

    if isinstance(rhs, AttrRef):
        # Source via attribute access (e.g. `request.GET`).
        attr_name = canon_callee(rhs)
        src_taint = _check_source_match(attr_name, specs, lineno)
        if src_taint is not None:
            return src_taint
        # Spec §5.1: σ(canon(AttrRef)) ⊔ σ(canon(base)) ⊔ eval_rhs(base)
        # Recursing on `base` lets a sub-AttrRef (e.g. `request.args` in
        # `request.args.get`) be detected as a source even if the full
        # name doesn't match any spec.
        attr_key = canon_rhs(rhs)
        return join(
            state_get(state, attr_key),
            eval_rhs(rhs.base, state, specs, findings, lineno),
        )

    if isinstance(rhs, SubscriptRef):
        sub_key = canon_rhs(rhs)
        base_key = canon_rhs(rhs.base)
        sub_taint = state_get(state, sub_key)
        # Constant key: Phase 9.bis precision. We only read:
        #   - the exact slot `obj['k']`,
        #   - the wildcard `obj[*]` (other prior dynamic writes),
        #   - the direct receiver `obj` (no recursive aggregation).
        # No call to `eval_rhs(rhs.base)`, which would aggregate all
        # sub-entries and reintroduce the over-taint we're trying to avoid.
        if isinstance(rhs.key, Const):
            if sub_key in state:
                return sub_taint
            wildcard_taint = state.get(f"{base_key}[*]", CLEAN)
            base_direct = state.get(base_key, CLEAN)
            return join(wildcard_taint, base_direct)
        # Dynamic key: no precision possible — we join base (state) + key +
        # base (recursive) to handle `request.args.get('p')[0:5]`
        # (base = tainted CallRef).
        return join(
            join(sub_taint, state_get(state, base_key)),
            join(
                eval_rhs(rhs.base, state, specs, findings, lineno),
                eval_rhs(rhs.key, state, specs, findings, lineno),
            ),
        )

    if isinstance(rhs, BinOp):
        return join(
            eval_rhs(rhs.left, state, specs, findings, lineno),
            eval_rhs(rhs.right, state, specs, findings, lineno),
        )

    if isinstance(rhs, UnaryOp):
        return eval_rhs(rhs.operand, state, specs, findings, lineno)

    if isinstance(rhs, Cmp):
        # Spec §5.1: Cmp produces a bool, considered clean.
        # We still evaluate the operands for their effects (taint side effects).
        eval_rhs(rhs.left, state, specs, findings, lineno)
        eval_rhs(rhs.right, state, specs, findings, lineno)
        return CLEAN

    if isinstance(rhs, Bool):
        result: Taint = CLEAN
        for op in rhs.operands:
            result = join(result, eval_rhs(op, state, specs, findings, lineno))
        return result

    if isinstance(rhs, (TupleRef, ListRef, SetRef)):
        # Container: taint aggregated over elements (choice SCA-8)
        result = CLEAN
        for elt in rhs.elements:
            result = join(result, eval_rhs(elt, state, specs, findings, lineno))
        return result

    if isinstance(rhs, DictRef):
        result = CLEAN
        for k, v in rhs.items:
            result = join(result, eval_rhs(k, state, specs, findings, lineno))
            result = join(result, eval_rhs(v, state, specs, findings, lineno))
        return result

    if isinstance(rhs, Star):
        return eval_rhs(rhs.inner, state, specs, findings, lineno)

    if isinstance(rhs, IfExp):
        # Phase 9 — conservative semantics: we evaluate the condition for
        # its effects (potential sinks in the condition), then join the
        # taints of both branches. Simplifying the IfExp when the condition
        # is Const-evaluable is done in a pre-pass in `_compute_dead_edges`,
        # which rewrites `node_ir`.
        eval_rhs(rhs.cond, state, specs, findings, lineno)
        return join(
            eval_rhs(rhs.then, state, specs, findings, lineno),
            eval_rhs(rhs.orelse, state, specs, findings, lineno),
        )

    if isinstance(rhs, LambdaRef):
        # Choice SCA-3: opaque in phase 1-5
        return CLEAN

    if isinstance(rhs, CallRef):
        return eval_call(rhs, state, specs, findings, lineno)

    return CLEAN


# ============================================================================
# Call evaluation (spec §5.2)
# ============================================================================

def _arg_regex_source(arg: RHS, specs: RuleSpecs, lineno: int) -> Optional[Taint]:
    """Detect a source via regex on the TEXT of a single call argument, or return None.

    Volet 4 — lets a source passed directly as an argument
    (`run_query(request.GET["q"])`) be tainted without an intermediate
    variable. The pattern is tested against the reconstructed text of THIS
    argument (`pretty_rhs`), not the whole line, so neighboring arguments
    (`db` in `run_query(src, db)`) aren't tainted. Additive: only consulted
    when `eval_rhs` has already returned CLEAN for the argument (no double
    counting with dotted patterns).
    """
    expr: Optional[str] = None
    for src in specs.sources:
        rx = getattr(src, "raw_regex", None)
        if rx is None:
            continue
        if expr is None:
            expr = pretty_rhs(arg)
        if rx.search(expr):
            return Tainted(
                kinds=frozenset({src.kind}),
                source=SourceInfo(line=lineno, expr=expr, kind=src.kind),
            )
    return None


def eval_call(call: CallRef, state: State, specs: RuleSpecs,
              findings: List[Finding], lineno: int = 0) -> Taint:
    """Evaluate a CallRef, applying its spec (source/sink/sanitizer/passthrough).

    Spec §5.2. Emits findings into `findings` if a sink is reached with a
    compatible taint.

    Returns:
        The taint of the call's return value.
    """
    # Evaluate all arguments first (for effects and their taint). Part 4 —
    # a source written directly as an argument (`run_query(request.GET["q"])`)
    # is tainted via regex on the text of THIS argument (see _arg_regex_source).
    arg_taints: List[Taint] = []
    for arg in call.args:
        t = eval_rhs(arg, state, specs, findings, lineno)
        if is_clean(t):
            t = _arg_regex_source(arg, specs, lineno) or t
        arg_taints.append(t)
    kw_taints: Dict[str, Taint] = {}
    for name, val in call.kwargs:
        t = eval_rhs(val, state, specs, findings, lineno)
        if is_clean(t):
            t = _arg_regex_source(val, specs, lineno) or t
        kw_taints[name] = t

    callee_name = canon_callee(call.callee)
    # Evaluate the callee itself for effects AND to get its taint.
    # Spec §5.2 — the taint of a method's receiver (e.g. `request.args` in
    # `request.args.get(...)`) must propagate to the call's result.
    callee_taint = eval_rhs(call.callee, state, specs, findings, lineno)

    spec_kind, spec = resolve_spec(callee_name, specs)

    if spec_kind == SpecKind.SOURCE:
        assert isinstance(spec, SourceSpec)
        return Tainted(
            kinds=frozenset({spec.kind}),
            source=SourceInfo(line=lineno, expr=callee_name, kind=spec.kind),
        )

    if spec_kind == SpecKind.SINK:
        assert isinstance(spec, SinkSpec)
        _check_sink(spec, callee_name, arg_taints, kw_taints, specs, findings, lineno)
        # A sink's return value stays clean by default.
        # Phase 7 may introduce a "sink also propagates" mode.
        return CLEAN

    if spec_kind == SpecKind.SANITIZER:
        # Kills the taint of the return value. Spec §5.2.
        return CLEAN

    if spec_kind == SpecKind.PASSTHROUGH:
        assert isinstance(spec, PassthroughSpec)
        passthrough_result = _eval_passthrough(spec, arg_taints, kw_taints)
        # Spec §5.2 — a tainted receiver also contributes to the result
        return join(passthrough_result, callee_taint)

    # Part 2 — call to a user function with a summary (interprocedural).
    # Additive: we emit sinks reached through the call, and taint the
    # return value if the function has an unconditional internal source.
    # The over-approximation by joining args is kept as a fallback (no
    # regression).
    summary = specs.summaries.get(callee_name) if specs.summaries else None
    if summary is None and specs.type_map and isinstance(call.callee, AttrRef) and isinstance(call.callee.base, VarRef):
        # Round 5 (Java) — `scr.method()` where `scr` is a typed local
        # variable: the direct lookup by variable name always fails (no
        # summary is ever indexed under a variable name); we retry via the
        # declared class name. Always empty for Python (`specs.type_map`
        # always `{}`) — see RuleSpecs.
        declared_type = specs.type_map.get(call.callee.base.name)
        if declared_type:
            callee_name = f"{declared_type}.{call.callee.attr}"
            summary = specs.summaries.get(callee_name)
    if (summary is None and isinstance(call.callee, AttrRef)
            and isinstance(call.callee.base, CallRef)
            and isinstance(call.callee.base.callee, VarRef)):
        # Round 6 (Java) — chained call `new ClassName(...).method(...)`:
        # `java_to_ir.py` inlines the constructor's CallRef as the AttrRef's
        # base precisely to enable this resolution here. No `language`
        # guard: this shape is only produced by the Java lowering, so it
        # has no effect on Python (never built by `python_to_ir.py`).
        ctor_type_name = call.callee.base.callee.name
        callee_name = f"{ctor_type_name}.{call.callee.attr}"
        summary = specs.summaries.get(callee_name)
    if summary is not None:
        findings.extend(
            _apply_summary_at_call(summary, callee_name, arg_taints, specs, lineno)
        )

    # Phase 9.bis — Key-indexed read: short-circuits the UNKNOWN case that
    # over-approximates via callee_taint (including the receiver's VarRef
    # aggregation).
    applicable, indexed_result = _try_indexed_read(call, state, arg_taints)
    if applicable:
        return indexed_result

    # SpecKind.UNKNOWN: over-approximation (choice SCA-9) — reserved for
    # truly opaque calls (no summary). Round 6 (Java calibration): when a
    # summary IS resolved, `return_taint_params` (per-parameter probing,
    # `compute_summary_from_cfg`) precisely tells which positional
    # arguments actually reach the return — computed until now but never
    # consulted here, which cancelled out all the precision gained from a
    # "return not tainted" summary (e.g. a function that always returns a
    # constant despite a tainted parameter). The receiver (`callee_taint`)
    # and kwargs remain unconditionally over-approximated: neither is
    # modeled by the probing (instance state not simulated, kwargs not
    # indexed by parameter) — only the positional narrowing is safe.
    result: Taint = callee_taint
    if summary is not None:
        for i, t in enumerate(arg_taints):
            if i in summary.return_taint_params:
                result = join(result, t)
    else:
        for t in arg_taints:
            result = join(result, t)
    for t in kw_taints.values():
        result = join(result, t)
    # Part 2 — unconditional internal source: the return is tainted even
    # with no tainted argument (e.g. `def f(): return request.GET[...]`).
    # Filtering by kind (web only) happens when the summary is built
    # (`compute_summary`), not here.
    if summary is not None and summary.return_tainted_uncond:
        kind = summary.return_kind or "http"
        result = join(result, Tainted(
            kinds=frozenset({kind}),
            source=SourceInfo(line=lineno, expr=f"{callee_name}()", kind=kind),
        ))
    return result


def _apply_summary_at_call(summary, callee_name, arg_taints, specs, lineno):
    """Build "sink reached through a call" findings from a callee's summary.

    A tainted argument passed to a parameter that the summary marks as
    reaching a sink triggers a finding at the call site, with a flow that
    crosses the call boundary (the `caller → callee` step)."""
    out: List[Finding] = []
    for param_idx, template in summary.sink_param_findings.items():
        if param_idx >= len(arg_taints):
            continue
        arg_t = arg_taints[param_idx]
        if not is_tainted(arg_t):
            continue
        src_line = None
        src_kind = "unknown"
        flow: List[FlowStep] = []
        if isinstance(arg_t, Tainted):
            src_line = arg_t.source.line
            src_kind = arg_t.source.kind or "unknown"
            flow.append(FlowStep(line=arg_t.source.line, kind="source", text=arg_t.source.expr))
        # Explicit interprocedural step (contains `→`, verified by tests).
        flow.append(FlowStep(
            line=lineno, kind="propagation",
            text=f"{callee_name}(...) → {getattr(template, 'sink_text', 'sink')}",
        ))
        flow.append(FlowStep(line=getattr(template, "line", lineno), kind="sink",
                             text=getattr(template, "sink_text", "")))
        out.append(Finding(
            rule_id=specs.rule_id,
            severity=specs.severity,
            line=lineno,
            column=0,
            sink_text=f"{callee_name}(...)",
            source_line=src_line,
            message=specs.message,
            cwe=specs.cwe,
            flow=tuple(flow),
            source_kind=src_kind,
        ))
    return out


def _check_sink(
    spec: SinkSpec,
    callee_name: str,
    arg_taints: List[Taint],
    kw_taints: Dict[str, Taint],
    rule_specs: RuleSpecs,
    findings: List[Finding],
    lineno: int,
) -> None:
    """Check whether a sink is reached with a compatible taint.

    Spec §5.2 + §7.3. Appends a Finding to `findings` if so.
    """
    # Which args to inspect? If spec.args is empty → all of them.
    if spec.args:
        indices = spec.args
    else:
        indices = tuple(range(len(arg_taints)))

    # For each relevant arg, check its taint
    for idx in indices:
        if idx >= len(arg_taints):
            continue
        t = arg_taints[idx]
        if is_clean(t):
            continue
        # Check kind compatibility (spec §7.3)
        if not _kinds_compatible(t, spec.kinds):
            continue
        # Build the finding
        source_line = None
        source_kind = "unknown"
        flow: List[FlowStep] = []
        if isinstance(t, Tainted):
            source_line = t.source.line
            source_kind = t.source.kind or "unknown"
            flow.append(FlowStep(line=t.source.line, kind="source", text=t.source.expr))
        flow.append(FlowStep(line=lineno, kind="sink", text=callee_name))
        findings.append(Finding(
            rule_id=rule_specs.rule_id,
            severity=rule_specs.severity,
            line=lineno,
            column=0,
            sink_text=callee_name,
            source_line=source_line,
            message=rule_specs.message,
            cwe=rule_specs.cwe,
            flow=tuple(flow),
            source_kind=source_kind,
        ))
        # We emit one finding per tainted arg; we don't return early so
        # every distinct vector is spotted.


def _kinds_compatible(t: Taint, sink_kinds: Tuple[str, ...]) -> bool:
    """Check that at least one taint kind matches the sink's kind filter (§7.3).

    If sink_kinds is empty, all kinds match.
    """
    if not sink_kinds:
        return True
    if is_top(t):
        return True  # over-approximation
    if isinstance(t, Tainted):
        return bool(t.kinds & set(sink_kinds))
    return False


def _eval_passthrough(
    spec: PassthroughSpec,
    arg_taints: List[Taint],
    kw_taints: Dict[str, Taint],
) -> Taint:
    """Compute the return taint of a passthrough call (spec §7.2).

    If spec.args_in is empty, joins all args. If spec.arg_out is "return"
    (default), the result is that computed join. Otherwise the indicated
    arg is mutated — not handled here (eval_rhs has no state access; the
    mutation effect must go through transfer_stmt). In that case CLEAN is
    returned for the call's own result, and the caller must handle the
    mutation effect.
    """
    if spec.args_in:
        indices = spec.args_in
    else:
        indices = tuple(range(len(arg_taints)))

    result: Taint = CLEAN
    for idx in indices:
        if idx < len(arg_taints):
            result = join(result, arg_taints[idx])

    # Note: for spec.arg_out != "return", the arg's mutation is not
    # handled here (eval_call has no access to the lvalue). Limited to
    # the return value in Phase 3; Phase 7 will introduce finer-grained
    # handling for the `list.append(x)` pattern that mutates the receiver.
    return result


# ============================================================================
# Transfer functions for statements (spec §5)
# ============================================================================

def _discard_sinks_failing_raw_regex(
    findings: List[Finding],
    before: int,
    specs: RuleSpecs,
    source_lines: List[str],
) -> None:
    r"""Revalidate in place the findings appended since index `before` against
    their SinkSpec's `raw_regex` (the original DSL regex).

    `eval_call` -> `_check_sink` resolves a sink purely by call name against
    the dotted glob (`**.println` matches ANY receiver), without
    revalidation -- unlike `_aux_match_line` (§10bis), which does check
    `raw_regex` but for a different purpose (additional matching on
    assign/branch statements, not a filter on this path). A sink DSL
    pattern written with a negative lookbehind to exclude a specific
    receiver (e.g. `(?<!System\.(?:out|err))\.println\s*\(`, cf.
    taint_xss.sca) must therefore be revalidated here, otherwise the
    exclusion has no effect on this path -- a bug found via the
    `taint_xss_console_clean.java` regression (System.out.println falsely
    flagged as an XSS sink via the **.println glob, even though raw_regex
    explicitly excluded it).

    Only drops a finding if at least one spec whose glob matches its
    `sink_text` exists AND none of those specs validate `raw_regex` against
    the relevant text -- a spec without `raw_regex` (None, an uncompilable
    DSL regex) is never filtered (unchanged, best-effort behavior like the
    rest of the converter).

    Relevant text: tries `sink_text` (the resolved name/path, e.g. a
    CallRef's callee_name, or the full canonical path of an AttrLhs sink
    like `user.is_admin`) AND the source line text, in that order -- both
    existing sink DSL shapes depend on this: a sink anchored at the end of
    a string (`\.(is_admin|...)$`, AttrLhs, cf.
    taint_sensitive_attr_write.sca) can only match `sink_text` (`$` would
    fall mid-line in the full source line, before `= value`); a call sink
    (`\.println\s*\(`, cf. taint_xss.sca) can only match the line text
    (`sink_text` is just the bare method name, no dot or parens). Trying
    both risks no false keep: a call pattern never matches a bare path (it
    requires a literal `(` absent from `sink_text`), and an anchored `$`
    pattern only matches the full line when the sink genuinely sits at the
    end of the line -- already the legitimate case for a plain `x.attr`
    with nothing after it.
    """
    if before >= len(findings):
        return
    kept: List[Finding] = findings[:before]
    for f in findings[before:]:
        candidates = [
            s for s in specs.sinks if match_pattern(f.sink_text, _spec_compiled(s))
        ]
        if not candidates:
            kept.append(f)
            continue
        line_text = source_lines[f.line - 1] if 0 < f.line <= len(source_lines) else ""
        if any(
            c.raw_regex is None
            or c.raw_regex.search(f.sink_text)
            or c.raw_regex.search(line_text)
            for c in candidates
        ):
            kept.append(f)
        # otherwise: every candidate spec has a raw_regex that excludes
        # both sink_text and the line -- finding dropped (not added to `kept`)
    findings[:] = kept


def transfer_stmt(
    stmt: IRStmt,
    state: State,
    specs: RuleSpecs,
    findings: List[Finding],
    source_lines: Optional[List[str]] = None,
) -> State:
    """Apply the transfer function for a single IR statement.

    Returns the new state. Findings are appended to the given list.

    Args:
        source_lines: if provided, enables hybrid regex matching on the
            source line (spec §10bis). Lets sinks/sanitizers/sources be
            detected via the original DSL regexes, in addition to dotted
            matching. Also enables raw_regex revalidation of sinks resolved
            by glob (cf. `_discard_sinks_failing_raw_regex`).
    """
    if isinstance(stmt, Assign):
        before = len(findings)
        new_state = _transfer_assign(stmt, state, specs, findings)
        if source_lines is not None:
            _discard_sinks_failing_raw_regex(findings, before, specs, source_lines)
            new_state = _aux_match_line(stmt, new_state, specs, findings, source_lines)
        return new_state
    if isinstance(stmt, Call):
        before = len(findings)
        new_state = _transfer_call_stmt(stmt, state, specs, findings)
        if source_lines is not None:
            _discard_sinks_failing_raw_regex(findings, before, specs, source_lines)
            new_state = _aux_match_line(stmt, new_state, specs, findings, source_lines)
        return new_state
    if isinstance(stmt, Return):
        before = len(findings)
        new_state = _transfer_return(stmt, state, specs, findings)
        if source_lines is not None:
            _discard_sinks_failing_raw_regex(findings, before, specs, source_lines)
            new_state = _aux_match_line(stmt, new_state, specs, findings, source_lines)
        return new_state
    if isinstance(stmt, Raise):
        before = len(findings)
        new_state = _transfer_raise(stmt, state, specs, findings)
        if source_lines is not None:
            _discard_sinks_failing_raw_regex(findings, before, specs, source_lines)
            new_state = _aux_match_line(stmt, new_state, specs, findings, source_lines)
        return new_state
    if isinstance(stmt, Branch):
        # Evaluate the condition for its effects (sinks in the condition would be spotted)
        before = len(findings)
        eval_rhs(stmt.condition, state, specs, findings, stmt.lineno)
        if source_lines is not None:
            _discard_sinks_failing_raw_regex(findings, before, specs, source_lines)
            state = _aux_match_line(stmt, state, specs, findings, source_lines)
        return state
    if isinstance(stmt, Noop):
        return state
    return state


def _aux_match_line(
    stmt: IRStmt,
    state: State,
    specs: RuleSpecs,
    findings: List[Finding],
    source_lines: List[str],
) -> State:
    """Auxiliary regex matching against the raw source line (spec §10bis).

    For each sink/sanitizer/source spec with a `raw_regex`, tests it
    against the statement's raw source line. On a match, triggers the
    corresponding behavior.
    """
    lineno = getattr(stmt, "lineno", 0)
    if lineno <= 0 or lineno > len(source_lines):
        return state
    line_text = source_lines[lineno - 1]

    # Fetch the canonical LHS if the statement is an Assign
    lhs_key: Optional[str] = None
    if isinstance(stmt, Assign):
        lhs_key = canon_lhs(stmt.lhs)

    # Generic guard sanitizer (before the sanitizer loop) — `if EXPR: body`
    # with a terminator (return/raise/abort) in the body and `not` or `in`
    # in the condition. Cleans every tainted variable mentioned on the
    # line. Covers the OWASP patterns `if '\'' in bar: return` and
    # `if not bar.startswith(...): return` without depending on a
    # specific sanitizer.
    stripped_full = line_text.lstrip()
    if (stripped_full.startswith("if ") or stripped_full.startswith("elif ")) and \
       (" not " in line_text or " in " in line_text):
        if_indent = len(line_text) - len(stripped_full)
        for off in range(0, 8):
            idx = lineno + off
            if idx >= len(source_lines):
                break
            nxt = source_lines[idx]
            if not nxt.strip():
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip())
            if nxt_indent <= if_indent:
                break
            if _GUARD_TERMINATOR_RE.search(nxt):
                return _apply_guard_cleanup(state, line_text, lineno, source_lines)

    # Sanitizers — kill the taint on the LHS if the line matches
    for san in specs.sanitizers:
        if san.raw_regex is None:
            continue
        if not san.raw_regex.search(line_text):
            continue
        # "Guard sanitizer" case (predicate-based, spec §10bis):
        # `if not <sanitizer>(x): abort/raise/return/break/sys.exit`.
        # If the source line is a negative `if`/`elif` condition AND a
        # terminator follows immediately, we clean *all* tainted
        # variables mentioned on the line. The IR compiles this statement
        # into an `Assign` of a temporary, so lhs_key can't be relied on.
        stripped = line_text.lstrip()
        # Scan the if-block body for a terminator (OWASP uses multi-line
        # bodies before the return). We accept any line strictly more indented
        # than the if-line as part of the body; stop at the first line with
        # indent ≤ if-indent. Also looks for a "fail open to a literal"
        # reassignment guard (`if (!check(x)) x = "literal";`), same-line or
        # as the first body line — the non-Python idiom equivalent of the
        # terminator guard (Java/C#/JS don't early-return as idiomatically).
        if_indent = len(line_text) - len(stripped)
        terminator_nearby = False
        reassign_var: Optional[str] = None
        _same_line_reassign = _GUARD_REASSIGN_SAMELINE_RE.search(line_text)
        if _same_line_reassign:
            reassign_var = _same_line_reassign.group(1)
        for off in range(0, 8):
            idx = lineno + off
            if idx >= len(source_lines):
                break
            nxt = source_lines[idx]
            if not nxt.strip():
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip())
            if nxt_indent <= if_indent:
                break  # exited the if-block
            if _GUARD_TERMINATOR_RE.search(nxt):
                terminator_nearby = True
                break
            if reassign_var is None:
                _next_reassign = _GUARD_REASSIGN_NEXTLINE_RE.search(nxt)
                if _next_reassign:
                    reassign_var = _next_reassign.group(1)
        has_negation = (
            " not " in line_text or " in " in line_text
            or _NEGATION_BANG_RE.search(line_text) is not None
        )
        is_guard = (
            (stripped.startswith("if ") or stripped.startswith("elif "))
            and has_negation
            and (terminator_nearby or reassign_var is not None)
        )
        if is_guard:
            if terminator_nearby:
                line_text_no_lit = _strip_plain_string_literals(line_text)
                for var_name in list(state.keys()):
                    if var_name in line_text_no_lit and is_tainted(state[var_name]):
                        state = state_set(state, var_name, CLEAN)
            elif reassign_var is not None:
                state = state_set(state, reassign_var, CLEAN)
            return state
        if lhs_key is not None:
            state = state_set(state, lhs_key, CLEAN)
        return state  # first match is enough for a sanitizer

    # Does a USER ASSIGNMENT line ALSO contain a sink? Case
    # `result = eval(request.args.get(...))` or `session[...] = request.form[...]`
    # where the source and sink are on the same line: the source loop's
    # short-circuit (which only taints the LHS) must not prevent detection
    # of the inline sink.
    #
    # Exclusion of lowering temporaries `__t{N}` (cf. _fresh_temp in
    # python_to_ir): a `return f"... request.args ..."` is lowered into
    # `__t0 = f"..."`, whose source line contains both the `request.args`
    # literal AND the `return f` sink pattern. Unblocking it would reopen
    # detection on a **literal** (false positive on OWASP
    # BenchmarkTest00905/00926). Detection of a real inline flow is still
    # ensured by the enclosing statement (Call/Return) that shares the
    # same source line.
    assign_line_has_sink = (
        lhs_key is not None
        and not lhs_key.startswith("__t")
        and any(
            s.raw_regex is not None and s.raw_regex.search(line_text)
            for s in specs.sinks
        )
    )

    # Sources — mark the LHS as tainted
    for src in specs.sources:
        if src.raw_regex is None:
            continue
        if src.raw_regex.search(line_text):
            if lhs_key is not None:
                state = state_set(state, lhs_key, Tainted(
                    kinds=frozenset({src.kind}),
                    source=SourceInfo(line=lineno, expr=line_text.strip(), kind=src.kind),
                ))
                # Source AND sink on the same assignment line
                # (`result = eval(request.args.get(...))`): let the sink
                # loop detect the inline flow instead of short-circuiting.
                if assign_line_has_sink:
                    break
                return state
            # Part 4 — only for a `Call` statement (direct call): a source
            # passed as an argument can feed a sink on the same line
            # (`sink(...)` receiving `request.GET[...]`) → let the sink
            # loop run. For a `Return`/`Branch`, a **literal** source in
            # the text (e.g. an error message `"... request.query_string ..."`)
            # must NOT open sink detection — anti-FP short-circuit.
            if isinstance(stmt, Call):
                break
            return state

    # Sinks — emit a finding if a taint is visible on the line
    for sink in specs.sinks:
        if sink.raw_regex is None:
            continue
        if not sink.raw_regex.search(line_text):
            continue
        # Multi-line call: if the sink line opens unbalanced parentheses,
        # extend the taint's SEARCH TEXT to the continuation lines (until
        # balanced, capped at 25 lines). Lets a sink `foo(` be linked to a
        # tainted argument located a few lines below (e.g.
        # `openai.ChatCompletion.create(... messages=[{... user_prompt}])`).
        # For a single-line call (balanced parentheses), scan_text ==
        # line_text: behavior strictly unchanged.
        scan_text = line_text
        paren_depth = line_text.count("(") - line_text.count(")")
        if paren_depth > 0:
            span = [line_text]
            j = lineno  # source_lines[lineno-1] == line_text ; next = index lineno
            j_end = min(len(source_lines), lineno + 25)
            while j < j_end and paren_depth > 0:
                cont = source_lines[j]
                span.append(cont)
                paren_depth += cont.count("(") - cont.count(")")
                j += 1
            scan_text = "\n".join(span)
        # Find a compatible taint: collect every taint in the state that
        # is mentioned in the sink's text (extended if multi-line).
        # String literals stripped before the search: a variable name that
        # coincides with a word present in a literal (e.g. variable `ip`
        # and SQL text `"select ip from ..."`) must not count as a real
        # mention of the variable — cf. `_STRING_LIT_STRIP_RE`.
        scan_text_no_lit = _strip_plain_string_literals(scan_text)
        hit = False
        for var_name, var_taint in state.items():
            # If the variable appears in the text (multi-line), its taint counts
            if var_name in scan_text_no_lit and is_tainted(var_taint):
                if not _kinds_compatible(var_taint, sink.kinds):
                    continue
                # Finding emission (dedup happens at the worklist level)
                src_line = None
                src_kind = "unknown"
                flow: List[FlowStep] = []
                if isinstance(var_taint, Tainted):
                    src_line = var_taint.source.line
                    src_kind = var_taint.source.kind or "unknown"
                    flow.append(FlowStep(line=var_taint.source.line, kind="source", text=var_taint.source.expr))
                flow.append(FlowStep(line=lineno, kind="sink", text=line_text.strip()))
                findings.append(Finding(
                    rule_id=specs.rule_id,
                    severity=specs.severity,
                    line=lineno,
                    column=0,
                    sink_text=line_text.strip(),
                    source_line=src_line,
                    message=specs.message,
                    cwe=specs.cwe,
                    flow=tuple(flow),
                    source_kind=src_kind,
                ))
                hit = True
                break  # one finding per sink-line is enough

        # Part 4 — source written DIRECTLY on the sink's line, with no
        # intermediate variable (e.g. an `.execute(...)` call receiving
        # `request.GET[...]`). Sanitized lines already short-circuited
        # above (sanitizers loop).
        if not hit:
            for src in specs.sources:
                if src.raw_regex is None or not src.raw_regex.search(line_text):
                    continue
                if not _kinds_compatible(
                    Tainted(kinds=frozenset({src.kind}), source=None), sink.kinds
                ):
                    continue
                findings.append(Finding(
                    rule_id=specs.rule_id,
                    severity=specs.severity,
                    line=lineno,
                    column=0,
                    sink_text=line_text.strip(),
                    source_line=lineno,
                    message=specs.message,
                    cwe=specs.cwe,
                    flow=(
                        FlowStep(line=lineno, kind="source", text=line_text.strip()),
                        FlowStep(line=lineno, kind="sink", text=line_text.strip()),
                    ),
                    source_kind=src.kind,
                ))
                break  # one source is enough

    return state


def _lhs_sink_target(lhs: LHS) -> Optional[str]:
    """Return the canonical name to match against sink patterns for an assignable lhs.

    Two lhs families can constitute an injection sink:

      - `SubscriptLhs` (`obj[key] = value`): the key varies, so match the
        **base** `canon_rhs(base)` (e.g. `response.headers`). Covers HTTP
        Response Splitting, Session Fixation, etc.
      - `AttrLhs` (`obj.attr = value`): it's the **attribute name** that
        carries meaning (no variable key), so match the **full path**
        `canon_lhs(lhs)` (e.g. `user.is_admin`). Covers privilege
        escalation via a sensitive attribute write (direct mass assignment).

    Returns `None` for other lhs kinds (VarLhs, TupleLhs, StarLhs), which
    are never sinks.

    Anti-FP selectivity relies on the sink patterns themselves: those
    targeting a Call/Subscript include `\\(` or `\\[`, so a bare attribute
    assignment `obj.attr = x` only matches if a sink explicitly targets
    that attribute (e.g. `\\.(is_admin|role)$`).
    """
    if isinstance(lhs, SubscriptLhs):
        return canon_rhs(lhs.base)
    if isinstance(lhs, AttrLhs):
        return canon_lhs(lhs)
    return None


def _transfer_assign(
    stmt: Assign, state: State, specs: RuleSpecs, findings: List[Finding]
) -> State:
    """`lhs := rhs` (spec §5.1).

    Sink detection via assignable lhs: if the lhs is `obj[key] = value`
    (SubscriptLhs) or `obj.attr = value` (AttrLhs), the canonical target
    (`_lhs_sink_target`) matches a sink pattern, and rhs is tainted, a
    finding is emitted. Covers injection patterns not caught by the
    standard sink check (which only looks at Call):
      - `response.headers["X"] = source`, `session[k] = source` (SubscriptLhs);
      - `user.is_admin = source` (AttrLhs — sensitive attribute write).
    """
    rhs_taint = eval_rhs(stmt.rhs, state, specs, findings, stmt.lineno)
    if is_tainted(rhs_taint):
        target_name = _lhs_sink_target(stmt.lhs)
        if target_name is not None:
            for sink in specs.sinks:
                compiled = sink.compiled if sink.compiled is not None else _spec_compiled(sink)
                if not match_pattern(target_name, compiled):
                    continue
                if not _kinds_compatible(rhs_taint, sink.kinds):
                    continue
                src_line = None
                src_kind = "unknown"
                flow: List[FlowStep] = []
                if isinstance(rhs_taint, Tainted):
                    src_line = rhs_taint.source.line
                    src_kind = rhs_taint.source.kind or "unknown"
                    flow.append(FlowStep(line=rhs_taint.source.line, kind="source", text=rhs_taint.source.expr))
                flow.append(FlowStep(line=stmt.lineno, kind="sink", text=target_name))
                findings.append(Finding(
                    rule_id=specs.rule_id,
                    severity=specs.severity,
                    line=stmt.lineno,
                    column=0,
                    sink_text=target_name,
                    source_line=src_line,
                    message=specs.message,
                    cwe=specs.cwe,
                    flow=tuple(flow),
                    source_kind=src_kind,
                ))
                break  # one finding per assignment is enough
    return _assign_lhs(stmt.lhs, rhs_taint, state)


def _assign_lhs(lhs: LHS, taint: Taint, state: State) -> State:
    """Update the state for an assignment to `lhs`.

    Handles:
        - VarLhs / AttrLhs / SubscriptLhs: simple assignment
        - TupleLhs: destructuring (every element receives the same taint —
          Phase 3 over-approximation)
        - StarLhs: same as above
    """
    if isinstance(lhs, VarLhs):
        return state_set(state, lhs.name, taint)
    if isinstance(lhs, (AttrLhs, SubscriptLhs)):
        return state_set(state, canon_lhs(lhs), taint)
    if isinstance(lhs, TupleLhs):
        # Over-approximation: every element receives the full taint.
        # In practice, python_to_ir's lowering has already desugared
        # tuples via SubscriptRef; this code covers the case where the
        # IR grammar would be extended.
        new_state = state
        for elt in lhs.elements:
            new_state = _assign_lhs(elt, taint, new_state)
        return new_state
    if isinstance(lhs, StarLhs):
        return _assign_lhs(lhs.inner, taint, state)
    return state


def _compute_indexed_write_key(
    stmt: Call, base_key: str, state: State,
    specs: RuleSpecs, findings: List[Finding],
) -> Optional[Tuple[str, Taint]]:
    """Compute the state slot where taint should be written for `obj.set/
    setdefault/__setitem__`. The access key is either Const (→ literal) or
    dynamic (→ `'*'`). Applicable whenever the signature is `(k, v)` or
    (for `set`) `(s, k, v)`. Returns `None` if the arg count doesn't match.
    """
    assert isinstance(stmt.callee, AttrRef)
    method = stmt.callee.attr
    if method not in _INDEXED_WRITE_METHODS:
        return None
    args = stmt.args
    if len(args) == 2:
        kstr = _key_repr(args[0])
        val_taint = eval_rhs(args[1], state, specs, findings, stmt.lineno)
        return f"{base_key}[{kstr}]", val_taint
    if len(args) == 3 and method == "set":
        k0 = _key_repr(args[0])
        k1 = _key_repr(args[1])
        val_taint = eval_rhs(args[2], state, specs, findings, stmt.lineno)
        return f"{base_key}[{k0}][{k1}]", val_taint
    return None


def _try_indexed_read(
    call: CallRef, state: State, arg_taints: List[Taint],
) -> Tuple[bool, Taint]:
    """Indexed read for dict/configparser-like methods.

    Returns `(applicable, taint)`. `applicable=False` signals that the
    signature does not support indexed reads (callee not AttrRef, method
    outside `_INDEXED_READ_METHODS`, invalid base, no arg) — the caller
    then falls back to UNKNOWN by default. `applicable=True` allows a
    CLEAN `taint` as a valid result (the precise read is CLEAN).

    Construction of the returned taint when applicable:
      taint = state[obj[<key0>]]                  (direct slot, exact or wildcard)
            ∪ state[obj[*]]                       (other dynamic writes)
            ∪ state[obj]                          (direct taint of the receiver)
            ∪ taint(default_arg)                  (for `get/pop/setdefault`)

    For `obj.get(s, k)` (`get`/`__getitem__` method): the 2-level slot
    `obj[s][k]` (configparser) is tried first; if present (or its wildcard
    `obj[s][*]`), that is what gets read. Otherwise falls back to the
    1-level slot (`k` treated as default).
    """
    if not isinstance(call.callee, AttrRef):
        return False, CLEAN
    method = call.callee.attr
    if method not in _INDEXED_READ_METHODS:
        return False, CLEAN
    base_key = canon_rhs(call.callee.base)
    if not base_key or base_key in ("<unknown>", "<call>") or base_key.startswith("<"):
        return False, CLEAN
    args = call.args
    if not args:
        return False, CLEAN

    k0 = _key_repr(args[0])
    one_level = f"{base_key}[{k0}]"
    wildcard = f"{base_key}[*]"
    base_direct = state.get(base_key, CLEAN)
    wildcard_taint = state.get(wildcard, CLEAN)

    # Configparser-style 2 args (section, option) on `get`/`__getitem__`.
    if len(args) >= 2 and method in ("get", "__getitem__"):
        k1 = _key_repr(args[1])
        two_level = f"{base_key}[{k0}][{k1}]"
        two_level_wild = f"{base_key}[{k0}][*]"
        if two_level in state or two_level_wild in state:
            t = join(state.get(two_level, CLEAN), state.get(two_level_wild, CLEAN))
            return True, join(join(t, base_direct), wildcard_taint)

    result = state_get(state, one_level)
    result = join(result, wildcard_taint)
    result = join(result, base_direct)
    if len(args) >= 2 and method in ("get", "pop", "setdefault"):
        result = join(result, arg_taints[1])
    return True, result


def _transfer_call_stmt(
    stmt: Call, state: State, specs: RuleSpecs, findings: List[Finding]
) -> State:
    """Call used as a statement: evaluated for its effects (notably sinks).

    The return value is ignored (no assignment). Mutation pattern:
    `obj.<method>(...tainted...)` updates the state according to the
    method's category (see _INDEXED_/_BULK_UPDATE_/_ELEMENT_WRITE_/
    _RECEIVER_WRITE_). No branch taints the whole receiver when a key-based
    index (Const or wildcard) is applicable — the Phase 9.bis precision
    aims to isolate constant slots from dynamic writes.
    """
    call_ref = CallRef(callee=stmt.callee, args=stmt.args, kwargs=stmt.kwargs)
    eval_rhs(call_ref, state, specs, findings, stmt.lineno)

    if not (isinstance(stmt.callee, AttrRef) and stmt.callee.attr in _MUTATION_METHODS):
        return state
    base_key = canon_rhs(stmt.callee.base)
    if not base_key or base_key in ("<unknown>", "<call>") or base_key.startswith("<"):
        return state

    method = stmt.callee.attr

    # Indexed write — `set/setdefault/__setitem__`. The access key is
    # canonicalized via `_key_repr`; a dynamic one falls onto `obj[*]`.
    if method in _INDEXED_WRITE_METHODS:
        result = _compute_indexed_write_key(stmt, base_key, state, specs, findings)
        if result is None:
            return state
        slot, val_taint = result
        if is_tainted(val_taint):
            existing = state_get(state, slot)
            state = state_set(state, slot, join(existing, val_taint))
        return state

    # Bulk-update — `obj.update({…}|k=v|other)`. Each (k, v) pair is
    # indexed; an unknown argument falls back to the wildcard `obj[*]`.
    if method in _BULK_UPDATE_METHODS:
        return _apply_bulk_update(stmt, base_key, state, specs, findings)

    # Element write — `append/extend/insert/add`. With no identifiable
    # key, the taint lands in the wildcard `obj[*]`.
    if method in _ELEMENT_WRITE_METHODS:
        return _apply_element_write(stmt, base_key, state, specs, findings)

    # Write on direct receiver — `write/writelines`. The container IS the
    # receiver (IO stream), not an index: `obj` is tainted directly.
    if method in _RECEIVER_WRITE_METHODS:
        return _apply_receiver_write(stmt, base_key, state, specs, findings)

    return state


def _apply_bulk_update(
    stmt: Call, base_key: str, state: State,
    specs: RuleSpecs, findings: List[Finding],
) -> State:
    """`obj.update(...)`. For each known (key, value) pair, indexes on the
    canonicalized key (`obj['k']` or `obj[*]`). For a variable argument
    (e.g. `obj.update(other)`), falls back to the global wildcard `obj[*]`.
    """
    new_state = state
    items: List[Tuple[str, RHS]] = []
    if stmt.args:
        first = stmt.args[0]
        if isinstance(first, DictRef):
            for k_node, v_node in first.items:
                items.append((_key_repr(k_node), v_node))
        else:
            # `obj.update(other)`: the keys can't be enumerated. Wildcard.
            arg_taint = eval_rhs(first, new_state, specs, findings, stmt.lineno)
            if is_tainted(arg_taint):
                wkey = f"{base_key}[*]"
                existing = state_get(new_state, wkey)
                new_state = state_set(new_state, wkey, join(existing, arg_taint))
    for kname, val_node in stmt.kwargs:
        items.append((repr(kname), val_node))
    for kstr, v_node in items:
        slot = f"{base_key}[{kstr}]"
        vtaint = eval_rhs(v_node, new_state, specs, findings, stmt.lineno)
        if is_tainted(vtaint):
            existing = state_get(new_state, slot)
            new_state = state_set(new_state, slot, join(existing, vtaint))
    return new_state


def _apply_element_write(
    stmt: Call, base_key: str, state: State,
    specs: RuleSpecs, findings: List[Finding],
) -> State:
    """`obj.append/extend/insert/add`. Some element becomes tainted; with no
    identifiable key, the targeted slot is `obj[*]`. Prior writes to
    constant slots (`obj['k']`) are not overwritten.
    """
    arg_taint: Taint = CLEAN
    for arg in stmt.args:
        arg_taint = join(arg_taint, eval_rhs(arg, state, specs, findings, stmt.lineno))
    for _, val in stmt.kwargs:
        arg_taint = join(arg_taint, eval_rhs(val, state, specs, findings, stmt.lineno))
    if is_tainted(arg_taint):
        wkey = f"{base_key}[*]"
        existing = state_get(state, wkey)
        state = state_set(state, wkey, join(existing, arg_taint))
    return state


def _apply_receiver_write(
    stmt: Call, base_key: str, state: State,
    specs: RuleSpecs, findings: List[Finding],
) -> State:
    """`obj.write/writelines`. The receiver is the content (IO stream); the
    taint is applied directly to `obj`, as before Phase 9.bis.
    """
    arg_taint: Taint = CLEAN
    for arg in stmt.args:
        arg_taint = join(arg_taint, eval_rhs(arg, state, specs, findings, stmt.lineno))
    for _, val in stmt.kwargs:
        arg_taint = join(arg_taint, eval_rhs(val, state, specs, findings, stmt.lineno))
    if is_tainted(arg_taint):
        existing = state_get(state, base_key)
        state = state_set(state, base_key, join(existing, arg_taint))
    return state


def _transfer_return(
    stmt: Return, state: State, specs: RuleSpecs, findings: List[Finding]
) -> State:
    """Return: evaluates the value (side effects captured). The return
    value will be captured for the summary on the Phase 6 side."""
    if stmt.value is not None:
        eval_rhs(stmt.value, state, specs, findings, stmt.lineno)
    return state


def _transfer_raise(
    stmt: Raise, state: State, specs: RuleSpecs, findings: List[Finding]
) -> State:
    """Raise: evaluates the exception (choice SCA-12: no taint on exceptions
    in phase 1-5, but still evaluated for its side effects)."""
    if stmt.value is not None:
        eval_rhs(stmt.value, state, specs, findings, stmt.lineno)
    return state


def transfer_stmts(
    stmts: List[IRStmt],
    state: State,
    specs: RuleSpecs,
    findings: List[Finding],
    source_lines: Optional[List[str]] = None,
) -> State:
    """Sequentially apply the transfer functions for a list of statements.

    Used by the worklist to process a full basic block. If `source_lines`
    is provided, hybrid regex matching is enabled.
    """
    for stmt in stmts:
        state = transfer_stmt(stmt, state, specs, findings, source_lines)
    return state
