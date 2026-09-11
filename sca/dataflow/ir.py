"""Intermediate Representation (IR) of the SCA dataflow engine.

Clean-room implementation based on sca/docs/dataflow-spec.md §3.
Algorithms inspired by:
  - Nielson, Nielson, Hankin — Principles of Program Analysis (Springer 2005, ch. 2.1)
  - Aho-Sethi-Ullman — Compilers: Principles, Techniques and Tools (3-address code)

No OCaml semgrep code was read to write this module.

Overview:
    The IR is a normalized 3-address form of the Python AST. Each
    instruction has the form `lhs := op(rhs1, ..., rhsK)`.
    The IR is LANGUAGE-NEUTRAL: the same structure serves Python, JS, Java,
    C#, PHP in Phase 8.

See the full grammar in sca/docs/dataflow-spec.md §3.2.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union


# ============================================================================
# RHS (Right-Hand Side) — expressions whose value is read
# ============================================================================

@dataclass(frozen=True)
class Const:
    """Literal constant (int, str, bool, None, etc.)."""
    value: object


@dataclass(frozen=True)
class VarRef:
    """Reference to a variable."""
    name: str


@dataclass(frozen=True)
class AttrRef:
    """Attribute read: a.b."""
    base: "RHS"
    attr: str


@dataclass(frozen=True)
class SubscriptRef:
    """Index/key read: a[k]."""
    base: "RHS"
    key: "RHS"


@dataclass(frozen=True)
class CallRef:
    """Call used as an rvalue.

    Args:
        callee: expression being called (typically VarRef or AttrRef).
        args: positional args (list of RHS).
        kwargs: keyword args (list of (name, RHS)).
    """
    callee: "RHS"
    args: Tuple["RHS", ...] = field(default_factory=tuple)
    kwargs: Tuple[Tuple[str, "RHS"], ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class BinOp:
    """Binary operation: a op b. Op is a string (`+`, `-`, `==`, etc.)."""
    op: str
    left: "RHS"
    right: "RHS"


@dataclass(frozen=True)
class UnaryOp:
    """Unary operation: op a."""
    op: str
    operand: "RHS"


@dataclass(frozen=True)
class Cmp:
    """Comparison: a op b. Op is a string (`<`, `==`, `in`, etc.)."""
    op: str
    left: "RHS"
    right: "RHS"


@dataclass(frozen=True)
class Bool:
    """Short-circuit boolean operation: and/or."""
    op: str  # 'and' or 'or'
    operands: Tuple["RHS", ...]


@dataclass(frozen=True)
class TupleRef:
    """Tuple construction."""
    elements: Tuple["RHS", ...]


@dataclass(frozen=True)
class ListRef:
    """List construction."""
    elements: Tuple["RHS", ...]


@dataclass(frozen=True)
class DictRef:
    """Dict construction: [(key, val), ...]."""
    items: Tuple[Tuple["RHS", "RHS"], ...]


@dataclass(frozen=True)
class SetRef:
    """Set construction."""
    elements: Tuple["RHS", ...]


@dataclass(frozen=True)
class LambdaRef:
    """Lambda — opaque in Phase 1-5. The body is lowered separately in Phase 6."""
    arg_names: Tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Star:
    """Starred argument: *args or **kwargs (call side)."""
    inner: "RHS"
    double: bool = False  # True for **kwargs


@dataclass(frozen=True)
class IfExp:
    """Ternary expression: `then if cond else orelse`.

    Phase 9 — kept as a distinct IR node (instead of being desugared into
    `Bool('or', [then, orelse])`) so that constant propagation can mark one
    of the two branches as dead when `cond` is evaluable at compile time.
    `eval_rhs(IfExp)` defaults to returning `join(eval_rhs(then),
    eval_rhs(orelse))`; the simplification is done in a pre-pass in
    `_compute_dead_edges` when `cond` is known.
    """
    cond: "RHS"
    then: "RHS"
    orelse: "RHS"


# Union type for annotation
RHS = Union[
    Const, VarRef, AttrRef, SubscriptRef, CallRef,
    BinOp, UnaryOp, Cmp, Bool,
    TupleRef, ListRef, DictRef, SetRef,
    LambdaRef, Star,
    IfExp,
]


# ============================================================================
# LHS (Left-Hand Side) — assignable locations
# ============================================================================

@dataclass(frozen=True)
class VarLhs:
    """Variable target: `x = ...`."""
    name: str


@dataclass(frozen=True)
class AttrLhs:
    """Attribute target: `a.b = ...`."""
    base: "RHS"
    attr: str


@dataclass(frozen=True)
class SubscriptLhs:
    """Indexed target: `a[k] = ...`."""
    base: "RHS"
    key: "RHS"


@dataclass(frozen=True)
class TupleLhs:
    """Tuple target: `a, b = ...` (destructuring)."""
    elements: Tuple["LHS", ...]


@dataclass(frozen=True)
class StarLhs:
    """Starred target in destructuring: `*rest = ...`."""
    inner: "LHS"


LHS = Union[VarLhs, AttrLhs, SubscriptLhs, TupleLhs, StarLhs]


# ============================================================================
# Statements IR
# ============================================================================

@dataclass(frozen=True)
class Assign:
    """`lhs := rhs`. The fundamental dataflow statement.

    Attributes:
        lhs: target (Var, Attr, Subscript, Tuple, Star).
        rhs: value being assigned.
        lineno: source line for reports.
    """
    lhs: LHS
    rhs: RHS
    lineno: int = 0


@dataclass(frozen=True)
class Call:
    """Call used as a statement (return value not captured).

    Used for sinks whose return value is unused.
    Attributes:
        callee: called expression.
        args, kwargs: arguments.
        lineno: source line.
    """
    callee: RHS
    args: Tuple[RHS, ...] = field(default_factory=tuple)
    kwargs: Tuple[Tuple[str, RHS], ...] = field(default_factory=tuple)
    lineno: int = 0


@dataclass(frozen=True)
class Return:
    """`return [rhs]`."""
    value: Optional[RHS] = None
    lineno: int = 0


@dataclass(frozen=True)
class Raise:
    """`raise [rhs]`."""
    value: Optional[RHS] = None
    lineno: int = 0


@dataclass(frozen=True)
class Branch:
    """Condition of a branch (if, while, etc.).

    Only present in `Branch`/`Loop` CFG nodes, not in the linear flow of a
    BasicBlock.
    """
    condition: RHS
    lineno: int = 0


@dataclass(frozen=True)
class Noop:
    """No-op statement (for `pass` and ignored statements)."""
    lineno: int = 0


IRStmt = Union[Assign, Call, Return, Raise, Branch, Noop]


# ============================================================================
# Canonicalization helpers
# ============================================================================

def canon_lhs(lhs: LHS) -> str:
    """Convert an LHS node into its canonical string key for the dataflow state.

    Spec §4.4 — the state is `LValue → T`; the key must be unique per
    syntactically distinct lvalue. Sub-attribute / subscript access with a
    non-constant key is aggregated under `[*]` (spec §4.4).

    Examples:
        VarLhs("a")                                  → "a"
        AttrLhs(VarRef("a"), "b")                    → "a.b"
        AttrLhs(AttrRef(VarRef("a"), "b"), "c")      → "a.b.c"
        SubscriptLhs(VarRef("a"), Const(0))          → "a[0]"
        SubscriptLhs(VarRef("a"), VarRef("k"))       → "a[*]"
    """
    if isinstance(lhs, VarLhs):
        return lhs.name
    if isinstance(lhs, AttrLhs):
        return f"{canon_rhs(lhs.base)}.{lhs.attr}"
    if isinstance(lhs, SubscriptLhs):
        key_str = _canon_subscript_key(lhs.key)
        return f"{canon_rhs(lhs.base)}[{key_str}]"
    if isinstance(lhs, TupleLhs):
        return "(" + ", ".join(canon_lhs(e) for e in lhs.elements) + ")"
    if isinstance(lhs, StarLhs):
        return "*" + canon_lhs(lhs.inner)
    raise TypeError(f"unknown LHS: {type(lhs).__name__}")


def canon_rhs(rhs: RHS) -> str:
    """Convert an RHS node into a canonical string, used to build state keys."""
    if isinstance(rhs, VarRef):
        return rhs.name
    if isinstance(rhs, AttrRef):
        return f"{canon_rhs(rhs.base)}.{rhs.attr}"
    if isinstance(rhs, SubscriptRef):
        return f"{canon_rhs(rhs.base)}[{_canon_subscript_key(rhs.key)}]"
    if isinstance(rhs, Const):
        # Constants: simple representation. Mostly used for numeric keys.
        return repr(rhs.value)
    # For other RHS types (BinOp, CallRef, etc.), there is no canonical key
    # since they aren't lvalues. A readable representation is returned instead.
    return f"<{type(rhs).__name__}>"


def _canon_subscript_key(key: RHS) -> str:
    """Return the literal representation of a constant key, or `*` for any other key."""
    if isinstance(key, Const):
        return repr(key.value)
    return "*"


def canon_callee(rhs: RHS) -> str:
    """Convert a callee expression into a dotted name for spec resolution (§7.1).

    Examples:
        VarRef("foo")                                → "foo"
        AttrRef(VarRef("subprocess"), "run")         → "subprocess.run"
        AttrRef(AttrRef(VarRef("a"), "b"), "c")      → "a.b.c"
        AttrRef(CallRef(...), "method")              → "<unknown>.method"
        CallRef(...) directly                        → "<call>"
    """
    if isinstance(rhs, VarRef):
        return rhs.name
    if isinstance(rhs, AttrRef):
        return f"{canon_callee(rhs.base)}.{rhs.attr}"
    if isinstance(rhs, CallRef):
        return "<call>"
    if isinstance(rhs, SubscriptRef):
        return f"{canon_callee(rhs.base)}[{_canon_subscript_key(rhs.key)}]"
    # For everything else: opaque
    if isinstance(rhs, (BinOp, UnaryOp, Cmp, Bool, Const, TupleRef, ListRef, DictRef, SetRef, LambdaRef, Star, IfExp)):
        return "<unknown>"
    return "<unknown>"


# ============================================================================
# Pretty-printing for debugging
# ============================================================================

def pretty_rhs(rhs: RHS) -> str:
    """Render an RHS node as a human-readable expression string, for debugging and display."""
    if isinstance(rhs, Const):
        return repr(rhs.value)
    if isinstance(rhs, VarRef):
        return rhs.name
    if isinstance(rhs, AttrRef):
        return f"{pretty_rhs(rhs.base)}.{rhs.attr}"
    if isinstance(rhs, SubscriptRef):
        return f"{pretty_rhs(rhs.base)}[{pretty_rhs(rhs.key)}]"
    if isinstance(rhs, CallRef):
        args = [pretty_rhs(a) for a in rhs.args]
        kwargs = [f"{n}={pretty_rhs(v)}" for n, v in rhs.kwargs]
        return f"{pretty_rhs(rhs.callee)}({', '.join(args + kwargs)})"
    if isinstance(rhs, BinOp):
        return f"({pretty_rhs(rhs.left)} {rhs.op} {pretty_rhs(rhs.right)})"
    if isinstance(rhs, UnaryOp):
        return f"({rhs.op}{pretty_rhs(rhs.operand)})"
    if isinstance(rhs, Cmp):
        return f"({pretty_rhs(rhs.left)} {rhs.op} {pretty_rhs(rhs.right)})"
    if isinstance(rhs, Bool):
        return f"({f' {rhs.op} '.join(pretty_rhs(o) for o in rhs.operands)})"
    if isinstance(rhs, TupleRef):
        return f"({', '.join(pretty_rhs(e) for e in rhs.elements)},)"
    if isinstance(rhs, ListRef):
        return f"[{', '.join(pretty_rhs(e) for e in rhs.elements)}]"
    if isinstance(rhs, DictRef):
        items = [f"{pretty_rhs(k)}: {pretty_rhs(v)}" for k, v in rhs.items]
        return "{" + ", ".join(items) + "}"
    if isinstance(rhs, SetRef):
        return "{" + ", ".join(pretty_rhs(e) for e in rhs.elements) + "}"
    if isinstance(rhs, LambdaRef):
        return f"lambda {', '.join(rhs.arg_names)}: ..."
    if isinstance(rhs, Star):
        return ("**" if rhs.double else "*") + pretty_rhs(rhs.inner)
    if isinstance(rhs, IfExp):
        return f"({pretty_rhs(rhs.then)} if {pretty_rhs(rhs.cond)} else {pretty_rhs(rhs.orelse)})"
    return f"<{type(rhs).__name__}>"


def pretty_lhs(lhs: LHS) -> str:
    """Render an LHS node as a human-readable expression string."""
    if isinstance(lhs, VarLhs):
        return lhs.name
    if isinstance(lhs, AttrLhs):
        return f"{pretty_rhs(lhs.base)}.{lhs.attr}"
    if isinstance(lhs, SubscriptLhs):
        return f"{pretty_rhs(lhs.base)}[{pretty_rhs(lhs.key)}]"
    if isinstance(lhs, TupleLhs):
        return "(" + ", ".join(pretty_lhs(e) for e in lhs.elements) + ")"
    if isinstance(lhs, StarLhs):
        return "*" + pretty_lhs(lhs.inner)
    raise TypeError(f"unknown LHS: {type(lhs).__name__}")


def pretty_stmt(stmt: IRStmt) -> str:
    """Render a single IR statement as a human-readable string."""
    if isinstance(stmt, Assign):
        return f"{pretty_lhs(stmt.lhs)} := {pretty_rhs(stmt.rhs)}"
    if isinstance(stmt, Call):
        args = [pretty_rhs(a) for a in stmt.args]
        kwargs = [f"{n}={pretty_rhs(v)}" for n, v in stmt.kwargs]
        return f"{pretty_rhs(stmt.callee)}({', '.join(args + kwargs)})"
    if isinstance(stmt, Return):
        return f"return {pretty_rhs(stmt.value)}" if stmt.value else "return"
    if isinstance(stmt, Raise):
        return f"raise {pretty_rhs(stmt.value)}" if stmt.value else "raise"
    if isinstance(stmt, Branch):
        return f"branch {pretty_rhs(stmt.condition)}"
    if isinstance(stmt, Noop):
        return "noop"
    return f"<{type(stmt).__name__}>"


def pretty_stmts(stmts: List[IRStmt]) -> str:
    """Render a list of IR statements as a multi-line human-readable string."""
    return "\n".join(pretty_stmt(s) for s in stmts)
