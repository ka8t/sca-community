"""Constant evaluation for the dataflow engine (Phase 9).

Module separate from the taint lattice: tracks, in parallel, what certain
variables are made of when they can be deduced from source-code literals.
Lets branches be marked dead (`if 7*42 > 200` always true) without
touching the main taint lattice.

No call to Python's built-in dynamic-code-execution functions: the
evaluation is purely structural over the IR nodes. Any unsupported type
or risky operation (division by zero, type mismatch) returns `None`
(= "unknown value").

Reference: sca/docs/dataflow-spec.md §11 (Phase 9 — abstract value domain).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

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
    ListRef,
    Raise,
    Return,
    RHS,
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
    canon_lhs,
)


# ============================================================================
# Representation and state
# ============================================================================

# A "deduced concrete value" is represented by a `Const(value)` node from
# the IR module. `None` (in the Python sense) signals "unknown value" and
# is distinct from `Const(None)`, which represents the literal constant
# `None`.
ConstState = Dict[str, Const]
"""`var_canon → Const(value)` state propagated alongside the taint lattice."""


def empty_const_state() -> ConstState:
    """Return an empty constant-propagation state."""
    return {}


# Types accepted as a `Const`-carried value. Mutable containers (list,
# dict, set) are represented in immutable form (tuple, frozenset) to
# stay hashable.
_VAL_TYPES = (int, float, str, bool, type(None), tuple, frozenset, bytes)


# ============================================================================
# _OPAQUE sentinel — non-Const element inside a Const(tuple)
# ============================================================================
# Phase 9.quater — to model the OWASP "list-shuffle" pattern:
#
#   lst = []
#   lst.append('safe')        # tuple = ('safe',)
#   lst.append(param)         # param tainted, indeterminate → tuple = ('safe', _OPAQUE)
#   lst.append('moresafe')    # tuple = ('safe', _OPAQUE, 'moresafe')
#   lst.pop(0)                # tuple = (_OPAQUE, 'moresafe')
#   bar = lst[1]              # = 'moresafe' → bar CLEAN
#   bar = lst[0]              # = _OPAQUE → SubscriptRef not simplified → bar tainted
#
# The `_OPAQUE` sentinel is unique (singleton). It appears ONLY as an
# element of a Const(tuple) — never as the top-level value of a Const.
# When reading `lst[i]`, if element i is `_OPAQUE`, `_eval_subscript`
# returns None (no simplification), letting the taint engine evaluate
# the read normally.


class _OpaqueElement:
    """Marker for a non-Const element inside a Const(tuple).

    Singleton (`_OPAQUE`). Reflects the semantics "this container slot
    holds an unknown dynamic value — probably tainted". Not hashable as
    a standalone value, but a tuple containing `_OPAQUE` elements stays
    hashable (object identity serves as the hash).
    """
    _instance: "Optional[_OpaqueElement]" = None

    def __new__(cls) -> "_OpaqueElement":
        """Return the shared _OPAQUE instance, creating it on first use."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        """Render as `<opaque>`."""
        return "<opaque>"


_OPAQUE = _OpaqueElement()


def _is_const_tuple_with_opaque(value: Any) -> bool:
    """Return True if `value` is a tuple containing at least one `_OPAQUE` element."""
    return isinstance(value, tuple) and any(e is _OPAQUE for e in value)


def _wrap(value: Any) -> Optional[Const]:
    """Wrap a Python value into a `Const` if its type is supported.
    Return `None` if the type is not in `_VAL_TYPES`.

    Special case (Phase 9.quater): a tuple containing `_OPAQUE` is also
    accepted (the tuple represents a partially-simulated list).
    """
    if isinstance(value, _VAL_TYPES):
        return Const(value=value)
    if _is_const_tuple_with_opaque(value):
        return Const(value=value)
    if isinstance(value, list):
        try:
            return Const(value=tuple(value))
        except TypeError:
            return None
    if isinstance(value, set):
        try:
            return Const(value=frozenset(value))
        except TypeError:
            return None
    return None


# ============================================================================
# Evaluation
# ============================================================================

def eval_const(rhs: RHS, const_state: ConstState) -> Optional[Const]:
    """Attempt to evaluate `rhs` to a concrete value under `const_state`.

    Return `Const(value)` if all operands are known and the operation is
    deterministic and safe. Return `None` (= unknown value) otherwise —
    including on any runtime exception (TypeError, ZeroDivisionError,
    IndexError, etc.).

    Covers:
      - literals (`Const`).
      - reads (`VarRef`) via `const_state`.
      - arithmetic (`BinOp`), comparisons (`Cmp`), unary ops (`UnaryOp`),
        boolean ops (`Bool` and/or, short-circuit).
      - subscript on Const(str), Const(tuple), Const(bytes).
      - tuple/set/dict literals whose elements are all Const.
      - attributes (`AttrRef`): not supported (returns None).
      - calls (`CallRef`): only `obj.get(i)` is recognized, as the
        equivalent of `obj[i]` (Java has no subscript syntax for
        `List` — see `_eval_indexed_get_call`). Any other call form
        is not supported (returns None).
    """
    if isinstance(rhs, Const):
        return rhs
    if isinstance(rhs, VarRef):
        return const_state.get(rhs.name)
    if isinstance(rhs, BinOp):
        return _eval_binop(rhs, const_state)
    if isinstance(rhs, Cmp):
        return _eval_cmp(rhs, const_state)
    if isinstance(rhs, UnaryOp):
        return _eval_unary(rhs, const_state)
    if isinstance(rhs, Bool):
        return _eval_bool(rhs, const_state)
    if isinstance(rhs, SubscriptRef):
        return _eval_subscript(rhs, const_state)
    if isinstance(rhs, CallRef):
        result = _eval_indexed_get_call(rhs, const_state)
        if result is not None:
            return result
        return _eval_string_method_call(rhs, const_state)
    if isinstance(rhs, TupleRef):
        items = [eval_const(e, const_state) for e in rhs.elements]
        if all(c is not None for c in items):
            return _wrap(tuple(c.value for c in items if c is not None))
        return None
    if isinstance(rhs, ListRef):
        items = [eval_const(e, const_state) for e in rhs.elements]
        if all(c is not None for c in items):
            return _wrap([c.value for c in items if c is not None])
        return None
    if isinstance(rhs, SetRef):
        items = [eval_const(e, const_state) for e in rhs.elements]
        if all(c is not None for c in items):
            try:
                return _wrap({c.value for c in items if c is not None})
            except TypeError:
                return None
        return None
    # AttrRef, CallRef, DictRef, LambdaRef, Star, etc. → not evaluable here.
    return None


def _eval_binop(rhs: BinOp, const_state: ConstState) -> Optional[Const]:
    """Evaluate a binary arithmetic/bitwise op when both operands are Const."""
    left = eval_const(rhs.left, const_state)
    right = eval_const(rhs.right, const_state)
    if left is None or right is None:
        return None
    try:
        op = rhs.op
        if op == "+":
            return _wrap(left.value + right.value)
        if op == "-":
            return _wrap(left.value - right.value)
        if op == "*":
            return _wrap(left.value * right.value)
        if op == "/":
            return _wrap(left.value / right.value)
        if op == "//":
            return _wrap(left.value // right.value)
        if op == "%":
            return _wrap(left.value % right.value)
        if op == "**":
            return _wrap(left.value ** right.value)
        if op == "&":
            return _wrap(left.value & right.value)
        if op == "|":
            return _wrap(left.value | right.value)
        if op == "^":
            return _wrap(left.value ^ right.value)
        if op == "<<":
            return _wrap(left.value << right.value)
        if op == ">>":
            return _wrap(left.value >> right.value)
    except (TypeError, ZeroDivisionError, ValueError, OverflowError):
        return None
    return None


def _eval_cmp(rhs: Cmp, const_state: ConstState) -> Optional[Const]:
    """Evaluate a comparison op when both operands are Const."""
    left = eval_const(rhs.left, const_state)
    right = eval_const(rhs.right, const_state)
    if left is None or right is None:
        return None
    try:
        op = rhs.op
        if op == "==":
            return _wrap(left.value == right.value)
        if op == "!=":
            return _wrap(left.value != right.value)
        if op == "<":
            return _wrap(left.value < right.value)
        if op == "<=":
            return _wrap(left.value <= right.value)
        if op == ">":
            return _wrap(left.value > right.value)
        if op == ">=":
            return _wrap(left.value >= right.value)
        if op == "is":
            return _wrap(left.value is right.value)
        if op == "is not":
            return _wrap(left.value is not right.value)
        if op == "in":
            return _wrap(left.value in right.value)
        if op == "not in":
            return _wrap(left.value not in right.value)
    except TypeError:
        return None
    return None


def _eval_unary(rhs: UnaryOp, const_state: ConstState) -> Optional[Const]:
    """Evaluate a unary op (not/-/+/~) when the operand is Const."""
    operand = eval_const(rhs.operand, const_state)
    if operand is None:
        return None
    try:
        op = rhs.op
        if op == "not":
            return _wrap(not operand.value)
        if op == "-":
            return _wrap(-operand.value)
        if op == "+":
            return _wrap(+operand.value)
        if op == "~":
            return _wrap(~operand.value)
    except TypeError:
        return None
    return None


def _eval_bool(rhs: Bool, const_state: ConstState) -> Optional[Const]:
    """Evaluate a short-circuit `and`/`or` chain when operands are Const."""
    # Short-circuit: `and` returns the first falsy operand, `or` the first truthy one.
    op = rhs.op
    if op == "and":
        last: Optional[Const] = None
        for operand in rhs.operands:
            v = eval_const(operand, const_state)
            if v is None:
                return None
            if not v.value:
                return v
            last = v
        return last
    if op == "or":
        last = None
        for operand in rhs.operands:
            v = eval_const(operand, const_state)
            if v is None:
                return None
            if v.value:
                return v
            last = v
        return last
    return None


def _eval_subscript(rhs: SubscriptRef, const_state: ConstState) -> Optional[Const]:
    """Evaluate `base[key]` when both base and key are Const."""
    base = eval_const(rhs.base, const_state)
    key = eval_const(rhs.key, const_state)
    if base is None or key is None:
        return None
    try:
        result = base.value[key.value]
    except (TypeError, IndexError, KeyError):
        return None
    # Phase 9.quater — if the targeted element is `_OPAQUE`, it cannot be
    # simplified; the normal taint engine must evaluate the read to
    # capture any taint.
    if result is _OPAQUE:
        return None
    return _wrap(result)


def _eval_indexed_get_call(rhs: CallRef, const_state: ConstState) -> Optional[Const]:
    """`obj.get(i)` — recognized as a positional indexed read, the Java
    equivalent of `lst[i]` (`List` has no subscript syntax).

    Does NOT collide with Python's `dict.get(key)`: a dict literal
    (`DictRef`) is never tracked as `Const(tuple)` by this module
    (`DictRef` is explicitly non-evaluable in `eval_const`) — so `base`
    can only be a `Const(tuple)` here if it comes from a `ListRef`
    (Python `[...]` literal) or a recognized Java list constructor
    (`new ArrayList<>()`, see `java_to_ir.py::_is_list_constructor`). A
    real Python `dict.get()` always falls through to `base is None`
    below (dict never tracked) → no simplification, Python behavior
    unchanged.
    """
    if not isinstance(rhs.callee, AttrRef) or rhs.callee.attr != "get":
        return None
    if len(rhs.args) != 1:
        return None
    return _eval_subscript(SubscriptRef(base=rhs.callee.base, key=rhs.args[0]), const_state)


# Pure, deterministic String methods recognized on a Const(str).
# Extended as calibration needs arose (cf. docs/ROADMAP.md § v2.0.0
# Audit) — a very common OWASP BenchmarkJava pattern:
#   String guess = "ABC"; char c = guess.charAt(1);  // 'B', always
#   switch (c) { case 'B': ... }                     // known live case
def _eval_string_method_call(rhs: CallRef, const_state: ConstState) -> Optional[Const]:
    """`"...".charAt(i)` / `"...".length()` — evaluable at compile time
    when the receiver and arguments are Const. Java has no equivalent
    of `str[i]` (no subscript on String), hence this dedicated
    recognition (mirrors `_eval_indexed_get_call` for `List.get`)."""
    if not isinstance(rhs.callee, AttrRef):
        return None
    base = eval_const(rhs.callee.base, const_state)
    if base is None or not isinstance(base.value, str):
        return None
    method = rhs.callee.attr
    if method == "charAt":
        if len(rhs.args) != 1:
            return None
        idx = eval_const(rhs.args[0], const_state)
        if idx is None or not isinstance(idx.value, int):
            return None
        try:
            return _wrap(base.value[idx.value])
        except IndexError:
            return None
    if method == "length" and not rhs.args:
        return _wrap(len(base.value))
    return None


# ============================================================================
# State update on assignment
# ============================================================================

def update_const_on_assign(
    const_state: ConstState, lhs: LHS, rhs: RHS,
) -> ConstState:
    """Compute the new `const_state` after `lhs := rhs`.

    Strategy:
      - `VarLhs(name)`: if `rhs` is evaluable, store it in
        `const_state[name]`. Otherwise drop the entry (the variable is
        no longer known).
      - `AttrLhs` / `SubscriptLhs`: invalidate the corresponding canonical
        key (attributes/slots are not tracked as concrete values yet —
        risk of desync with the taint lattice).
      - `TupleLhs` / `StarLhs`: invalidate each target (conservative).

    Returns a new dict (functional immutability).
    """
    new_state = dict(const_state)
    _apply_lhs_invalidation(new_state, lhs, rhs)
    return new_state


def _apply_lhs_invalidation(
    state: ConstState, lhs: LHS, rhs: RHS,
) -> None:
    """Mutate `state` in place to reflect an assignment to `lhs`, recursing
    into tuple/star targets."""
    if isinstance(lhs, VarLhs):
        value = eval_const(rhs, state)
        if value is None:
            state.pop(lhs.name, None)
        else:
            state[lhs.name] = value
        return
    if isinstance(lhs, (AttrLhs, SubscriptLhs)):
        key = canon_lhs(lhs)
        state.pop(key, None)
        return
    if isinstance(lhs, TupleLhs):
        for elt in lhs.elements:
            _apply_lhs_invalidation(state, elt, rhs)
        return
    if isinstance(lhs, StarLhs):
        _apply_lhs_invalidation(state, lhs.inner, rhs)
        return


def invalidate_var(const_state: ConstState, name: str) -> ConstState:
    """Remove `name` from `const_state` (external mutation, impure call, etc.)."""
    if name not in const_state:
        return const_state
    new_state = dict(const_state)
    new_state.pop(name, None)
    return new_state


# ============================================================================
# Phase 9.quater — Simulation of mutating operations on Const(tuple)
# ============================================================================

# Simulatable list methods. The exact semantics are implemented by
# `apply_list_mutation` below; any unlisted method triggers a
# conservative invalidation of the tracking. `add`/`remove` (Java, no
# conflict with Python — `list.add`/`list.remove` don't exist in Python)
# are the Java equivalents of `append`/`pop` (by index) — see their
# dedicated dispatch below, `add` also being overloaded with 2 arguments
# (`add(index, element)`, the equivalent of `insert`).
_LIST_MUTATION_METHODS = frozenset({"append", "extend", "insert", "pop", "add", "remove"})


def apply_list_mutation(
    const_state: ConstState, base_key: str, method: str, args,
) -> Optional[ConstState]:
    """Attempt to simulate the effect of a `<base_key>.<method>(args)` call
    on a `Const(tuple)` value currently tracked in `const_state`.

    Return the new `const_state` if the simulation succeeds, `None`
    otherwise (the caller must then invalidate `base_key` to stay sound).

    Conventions:
      - `append(x)`: appends eval_const(x) at the end (or `_OPAQUE` if x
        is not Const).
      - `extend(iter)`: appends all elements of a Const(tuple) (or fails
        if iter is not a Const-tuple).
      - `insert(i, x)`: inserts at index i if i is Const; same as append
        for x.
      - `pop()` (no arg) or `pop(i)`: removes the element (default -1) if
        the index is a valid Const.

    Phase 9.quater — targets the OWASP "list-shuffle" pattern:
        lst.append('safe'); lst.append(param); lst.append('moresafe');
        lst.pop(0); bar = lst[1]  → bar CLEAN
    """
    if method not in _LIST_MUTATION_METHODS:
        return None
    current = const_state.get(base_key)
    if current is None or not isinstance(current.value, tuple):
        return None
    tup = current.value

    if method == "append":
        if len(args) != 1:
            return None
        v = eval_const(args[0], const_state)
        element = v.value if v is not None else _OPAQUE
        new_tup = tup + (element,)
        return _update(const_state, base_key, new_tup)

    if method == "extend":
        if len(args) != 1:
            return None
        v = eval_const(args[0], const_state)
        if v is None or not isinstance(v.value, tuple):
            return None
        new_tup = tup + v.value
        return _update(const_state, base_key, new_tup)

    if method == "insert":
        if len(args) != 2:
            return None
        i = eval_const(args[0], const_state)
        if i is None or not isinstance(i.value, int):
            return None
        v = eval_const(args[1], const_state)
        element = v.value if v is not None else _OPAQUE
        idx = i.value
        new_tup = tup[:idx] + (element,) + tup[idx:]
        return _update(const_state, base_key, new_tup)

    if method == "pop" or method == "remove":
        # Java `remove(int index)` — assumed index-based (the dominant
        # OWASP case, `remove(0)` with a literal). `remove(Object)`
        # (removal by value, with no type info here to distinguish the
        # overload) fails cleanly below (the arg isn't an int Const).
        if len(args) == 0:
            if method == "remove":
                return None  # Java has no argument-less remove()
            idx = -1
        elif len(args) == 1:
            i = eval_const(args[0], const_state)
            if i is None or not isinstance(i.value, int):
                return None
            idx = i.value
        else:
            return None
        try:
            new_tup = tup[:idx] + tup[idx + 1 :] if idx >= 0 else (
                tup[:idx] + tup[idx + 1 :] if idx != -1 else tup[:-1]
            )
        except (TypeError, IndexError):
            return None
        return _update(const_state, base_key, new_tup)

    if method == "add":
        # Java `add(E element)` (1 arg, append) or `add(int index, E element)`
        # (2 args, insertion) — same semantics as append/insert above.
        if len(args) == 1:
            v = eval_const(args[0], const_state)
            element = v.value if v is not None else _OPAQUE
            new_tup = tup + (element,)
            return _update(const_state, base_key, new_tup)
        if len(args) == 2:
            i = eval_const(args[0], const_state)
            if i is None or not isinstance(i.value, int):
                return None
            v = eval_const(args[1], const_state)
            element = v.value if v is not None else _OPAQUE
            idx = i.value
            new_tup = tup[:idx] + (element,) + tup[idx:]
            return _update(const_state, base_key, new_tup)
        return None

    return None


def _update(const_state: ConstState, name: str, new_tuple: tuple) -> ConstState:
    """Internal helper: replace `const_state[name]` with `Const(new_tuple)`.
    Always succeeds (the tuple is immutable and hashable even with _OPAQUE).
    """
    new_state = dict(const_state)
    new_state[name] = Const(value=new_tuple)
    return new_state


# ============================================================================
# Merging states at confluence points (join)
# ============================================================================

def join_const_states(s1: ConstState, s2: ConstState) -> ConstState:
    """Merge two `const_state` at a CFG confluence point.

    Keeps a variable only if it has the **same value** in both states.
    Any divergence → the variable is no longer known.
    """
    if not s1:
        return {}
    if not s2:
        return {}
    out: ConstState = {}
    for name, val in s1.items():
        if s2.get(name) == val:
            out[name] = val
    return out


def const_state_equal(s1: ConstState, s2: ConstState) -> bool:
    """Structural equality used by the fixpoint loop to detect convergence."""
    if set(s1.keys()) != set(s2.keys()):
        return False
    for k in s1:
        if s1[k] != s2[k]:
            return False
    return True


# ============================================================================
# Simplification of evaluable IfExp nodes in an IR expression
# ============================================================================

def simplify_rhs(rhs: RHS, const_state: ConstState) -> RHS:
    """Phase 9 — recursively rewrite `IfExp(cond, then, orelse)` nodes whose
    `cond` is evaluable at compile time: replaced by `then` or `orelse`
    depending on the value of `cond`. Other RHS types are recursed into
    structurally to allow simplification of sub-expressions.

    Returns the original RHS unchanged if no simplification was
    performed — lets `simplify_stmt` detect the absence of change.
    """
    if isinstance(rhs, IfExp):
        cond_val = eval_const(rhs.cond, const_state)
        if cond_val is not None:
            branch = rhs.then if cond_val.value else rhs.orelse
            return simplify_rhs(branch, const_state)
        new_cond = simplify_rhs(rhs.cond, const_state)
        new_then = simplify_rhs(rhs.then, const_state)
        new_orelse = simplify_rhs(rhs.orelse, const_state)
        if new_cond is rhs.cond and new_then is rhs.then and new_orelse is rhs.orelse:
            return rhs
        return IfExp(cond=new_cond, then=new_then, orelse=new_orelse)
    if isinstance(rhs, BinOp):
        nl = simplify_rhs(rhs.left, const_state)
        nr = simplify_rhs(rhs.right, const_state)
        if nl is rhs.left and nr is rhs.right:
            return rhs
        return BinOp(op=rhs.op, left=nl, right=nr)
    if isinstance(rhs, UnaryOp):
        no = simplify_rhs(rhs.operand, const_state)
        if no is rhs.operand:
            return rhs
        return UnaryOp(op=rhs.op, operand=no)
    if isinstance(rhs, Cmp):
        nl = simplify_rhs(rhs.left, const_state)
        nr = simplify_rhs(rhs.right, const_state)
        if nl is rhs.left and nr is rhs.right:
            return rhs
        return Cmp(op=rhs.op, left=nl, right=nr)
    if isinstance(rhs, Bool):
        new_ops = tuple(simplify_rhs(o, const_state) for o in rhs.operands)
        if all(a is b for a, b in zip(new_ops, rhs.operands)):
            return rhs
        return Bool(op=rhs.op, operands=new_ops)
    if isinstance(rhs, AttrRef):
        nb = simplify_rhs(rhs.base, const_state)
        if nb is rhs.base:
            return rhs
        return AttrRef(base=nb, attr=rhs.attr)
    if isinstance(rhs, SubscriptRef):
        # Phase 9.quater — if the subscript can be resolved at compile-time
        # (Const key, Const base, non-_OPAQUE element), replace it
        # directly with the value. Lets `bar = lst[1]` become
        # `bar = 'moresafe'` after list-shuffle simulation.
        direct = _eval_subscript(rhs, const_state)
        if direct is not None:
            return direct
        nb = simplify_rhs(rhs.base, const_state)
        nk = simplify_rhs(rhs.key, const_state)
        if nb is rhs.base and nk is rhs.key:
            return rhs
        return SubscriptRef(base=nb, key=nk)
    if isinstance(rhs, CallRef):
        # Java `obj.get(i)` — same strategy as SubscriptRef above:
        # if resolvable at compile-time (positional list simulation,
        # Phase 9.quater), replace directly with the value. Without this
        # short-circuit, `bar = lst.get(1)` would remain an opaque CallRef
        # in the node_ir consumed by the main taint engine, which
        # would fall back to its `lst[*]` wildcard (over-approximated, tainted).
        direct = _eval_indexed_get_call(rhs, const_state)
        if direct is None:
            direct = _eval_string_method_call(rhs, const_state)
        if direct is not None:
            return direct
        nc = simplify_rhs(rhs.callee, const_state)
        na = tuple(simplify_rhs(a, const_state) for a in rhs.args)
        nk = tuple((n, simplify_rhs(v, const_state)) for n, v in rhs.kwargs)
        if (nc is rhs.callee
                and all(a is b for a, b in zip(na, rhs.args))
                and all(v1 is v2 for (_, v1), (_, v2) in zip(nk, rhs.kwargs))):
            return rhs
        return CallRef(callee=nc, args=na, kwargs=nk)
    if isinstance(rhs, TupleRef):
        ne = tuple(simplify_rhs(e, const_state) for e in rhs.elements)
        if all(a is b for a, b in zip(ne, rhs.elements)):
            return rhs
        return TupleRef(elements=ne)
    if isinstance(rhs, ListRef):
        ne = tuple(simplify_rhs(e, const_state) for e in rhs.elements)
        if all(a is b for a, b in zip(ne, rhs.elements)):
            return rhs
        return ListRef(elements=ne)
    if isinstance(rhs, SetRef):
        ne = tuple(simplify_rhs(e, const_state) for e in rhs.elements)
        if all(a is b for a, b in zip(ne, rhs.elements)):
            return rhs
        return SetRef(elements=ne)
    if isinstance(rhs, DictRef):
        ni = tuple(
            (simplify_rhs(k, const_state), simplify_rhs(v, const_state))
            for k, v in rhs.items
        )
        if all(k1 is k2 and v1 is v2 for (k1, v1), (k2, v2) in zip(ni, rhs.items)):
            return rhs
        return DictRef(items=ni)
    if isinstance(rhs, Star):
        ni = simplify_rhs(rhs.inner, const_state)
        if ni is rhs.inner:
            return rhs
        return Star(inner=ni, double=rhs.double)
    # Const, VarRef, LambdaRef : feuilles, aucune simplification.
    return rhs


def simplify_stmt(stmt: IRStmt, const_state: ConstState) -> IRStmt:
    """Apply `simplify_rhs` to the expressions carried by an IR statement.
    Return the original statement if nothing changes."""
    if isinstance(stmt, Assign):
        new_rhs = simplify_rhs(stmt.rhs, const_state)
        if new_rhs is stmt.rhs:
            return stmt
        return Assign(lhs=stmt.lhs, rhs=new_rhs, lineno=stmt.lineno)
    if isinstance(stmt, Call):
        new_callee = simplify_rhs(stmt.callee, const_state)
        new_args = tuple(simplify_rhs(a, const_state) for a in stmt.args)
        new_kwargs = tuple((n, simplify_rhs(v, const_state)) for n, v in stmt.kwargs)
        if (new_callee is stmt.callee
                and all(a is b for a, b in zip(new_args, stmt.args))
                and all(v1 is v2 for (_, v1), (_, v2) in zip(new_kwargs, stmt.kwargs))):
            return stmt
        return Call(callee=new_callee, args=new_args, kwargs=new_kwargs, lineno=stmt.lineno)
    if isinstance(stmt, Branch):
        new_cond = simplify_rhs(stmt.condition, const_state)
        if new_cond is stmt.condition:
            return stmt
        return Branch(condition=new_cond, lineno=stmt.lineno)
    if isinstance(stmt, Return):
        if stmt.value is None:
            return stmt
        new_val = simplify_rhs(stmt.value, const_state)
        if new_val is stmt.value:
            return stmt
        return Return(value=new_val, lineno=stmt.lineno)
    if isinstance(stmt, Raise):
        if stmt.value is None:
            return stmt
        new_val = simplify_rhs(stmt.value, const_state)
        if new_val is stmt.value:
            return stmt
        return Raise(value=new_val, lineno=stmt.lineno)
    return stmt
