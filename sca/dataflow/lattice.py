"""Taint lattice for the SCA dataflow engine.

Clean-room implementation based on sca/docs/dataflow-spec.md §4.
Algorithms inspired by:
  - Nielson, Nielson, Hankin — Principles of Program Analysis (Springer 2005, ch. 2.3)
  - Schwartz, Avgerinos, Brumley — All You Ever Wanted to Know About Dynamic
    Taint Analysis (IEEE S&P 2010)

No OCaml semgrep code was read to write this module.

Overview:
    The taint lattice is:

        T  ::=  ⊥                          (Clean — not tainted)
             |  Tainted(kinds, source)     (kinds ⊆ Kinds, source: SourceInfo)
             |  ⊤                          (Top — over-approximation)

    Operations:
        - ⊑  partial order
        - ⊔  join (merge at a confluence point)
        - ⊓  meet (rarely used)
        - ∇  widening (accelerates convergence on loops)

    The dataflow state is State = LValue (canon string) → Taint.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple


# ============================================================================
# SourceInfo — metadata attached to a taint
# ============================================================================

@dataclass(frozen=True)
class SourceInfo:
    """Info about the source of a taint.

    Allows reconstructing the flow (source -> sink) for reports.

    Attributes:
        line: line where the taint was introduced (source).
        expr: textual representation of the source (for reports).
        kind: kind of the taint (http, cli, env, etc.).
    """
    line: int
    expr: str = ""
    kind: str = "unknown"


# ============================================================================
# Taint — lattice element
# ============================================================================

class _TopSingleton:
    """Singleton ⊤ (Top) of the lattice.

    Represents a value whose taint is over-approximated: neither the
    precise kinds nor the source are known. Used after widening on
    unstable loops.
    """
    _instance: Optional["_TopSingleton"] = None

    def __new__(cls) -> "_TopSingleton":
        """Return the shared ⊤ instance, creating it on first use."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        """Render as the ⊤ symbol."""
        return "⊤"

    def __hash__(self) -> int:
        """Hash to a fixed value so ⊤ is stable as a dict key/set member."""
        return hash("__taint_top__")

    def __eq__(self, other: object) -> bool:
        """Return True for any other _TopSingleton instance."""
        return isinstance(other, _TopSingleton)


@dataclass(frozen=True)
class Tainted:
    """Tainted value with a set of kinds and a source info.

    Attributes:
        kinds: frozenset of kinds (http, cli, env, etc.). Must be non-empty.
        source: SourceInfo of the first source encountered (report consistency).
    """
    kinds: FrozenSet[str]
    source: SourceInfo

    def __post_init__(self) -> None:
        """Reject construction with an empty kinds set."""
        if not self.kinds:
            raise ValueError("Tainted.kinds must be non-empty (use CLEAN instead)")


# Lattice constants
CLEAN = None  # type: ignore[assignment]
"""⊥ — clean value (not tainted). `None` is used for Python simplicity."""

TOP = _TopSingleton()
"""⊤ — indeterminate over-approximation."""


# Type alias
Taint = "Optional[Tainted | _TopSingleton]"
"""Lattice element: `None` (Clean) | Tainted | TOP."""


# ============================================================================
# Lattice operations (spec §4.3)
# ============================================================================

def is_clean(t: Taint) -> bool:
    """`t == ⊥` (None)."""
    return t is None


def is_top(t: Taint) -> bool:
    """`t == ⊤`."""
    return isinstance(t, _TopSingleton)


def is_tainted(t: Taint) -> bool:
    """`t` is `Tainted(...)` or `⊤`."""
    return not is_clean(t)


def join(a: Taint, b: Taint) -> Taint:
    """⊔ — merge two taints at a control-flow confluence point.

    Rules (spec §4.3):
        ⊥ ⊔ x = x
        x ⊔ ⊥ = x
        ⊤ ⊔ x = ⊤
        x ⊔ ⊤ = ⊤
        Tainted(K₁, S₁) ⊔ Tainted(K₂, S₂) = Tainted(K₁ ∪ K₂, source_merge(S₁, S₂))
    """
    if is_top(a) or is_top(b):
        return TOP
    if is_clean(a):
        return b
    if is_clean(b):
        return a
    # Both are Tainted
    assert isinstance(a, Tainted) and isinstance(b, Tainted)
    return Tainted(
        kinds=a.kinds | b.kinds,
        source=_merge_source(a.source, b.source),
    )


def meet(a: Taint, b: Taint) -> Taint:
    """⊓ — intersect two taints. Spec §4.3.

    Rules:
        ⊥ ⊓ x = ⊥
        x ⊓ ⊥ = ⊥
        ⊤ ⊓ x = x
        x ⊓ ⊤ = x
        Tainted(K₁, S₁) ⊓ Tainted(K₂, S₂) = Tainted(K₁ ∩ K₂, S₁) if K₁ ∩ K₂ ≠ ∅, else ⊥
    """
    if is_clean(a) or is_clean(b):
        return CLEAN
    if is_top(a):
        return b
    if is_top(b):
        return a
    assert isinstance(a, Tainted) and isinstance(b, Tainted)
    inter = a.kinds & b.kinds
    if not inter:
        return CLEAN
    return Tainted(kinds=inter, source=a.source)


def leq(a: Taint, b: Taint) -> bool:
    """⊑ — partial order of the lattice. Spec §4.2.

    Rules:
        ⊥ ⊑ x  for all x
        x ⊑ ⊤  for all x
        Tainted(K₁, _) ⊑ Tainted(K₂, _) iff K₁ ⊆ K₂
    """
    if is_clean(a):
        return True
    if is_top(b):
        return True
    if is_clean(b):
        return False  # a non-clean, b clean
    if is_top(a):
        return False  # a top, b non-top
    assert isinstance(a, Tainted) and isinstance(b, Tainted)
    return a.kinds <= b.kinds


def widen(old: Taint, new: Taint, iteration: int, max_iter: int = 3) -> Taint:
    """∇ — widening operator to force convergence on unstable loops.

    Rules (spec §4.3):
        If iteration > max_iter and old != new: return ⊤
        Otherwise: return new
    """
    if iteration > max_iter and old != new:
        return TOP
    return new


def _merge_source(s1: SourceInfo, s2: SourceInfo) -> SourceInfo:
    """Merge two SourceInfo, keeping the one with the earliest line (spec §4.3)."""
    return s1 if s1.line <= s2.line else s2


# ============================================================================
# State — dict canon_name → Taint
# ============================================================================

State = Dict[str, Taint]
"""Dataflow state: maps each canonical LValue to its taint."""


def empty_state() -> State:
    """Return an initial state where every LValue is ⊥ (clean) by default."""
    return {}


def state_get(state: State, key: str) -> Taint:
    """Look up the taint of an LValue, returning ⊥ if it is absent."""
    return state.get(key, CLEAN)


def state_set(state: State, key: str, taint: Taint) -> State:
    """Return a new state with `key` updated (functional update).

    If taint == ⊥, the key is removed to keep the state compact.
    """
    new_state = dict(state)
    if is_clean(taint):
        new_state.pop(key, None)
    else:
        new_state[key] = taint
    return new_state


def state_join(s1: State, s2: State) -> State:
    """⊔ over states: join the taint of each key present in either state."""
    keys = set(s1.keys()) | set(s2.keys())
    result: State = {}
    for k in keys:
        merged = join(state_get(s1, k), state_get(s2, k))
        if not is_clean(merged):
            result[k] = merged
    return result


def state_equal(s1: State, s2: State) -> bool:
    """Return True if two states are structurally equal."""
    if set(s1.keys()) != set(s2.keys()):
        return False
    for k in s1:
        if s1[k] != s2[k]:
            return False
    return True


def state_widen(old: State, new: State, iteration: int, max_iter: int = 3) -> State:
    """Widen a state element-wise against its previous iteration.

    Keys whose value is unstable across iterations are widened to ⊤.
    """
    keys = set(old.keys()) | set(new.keys())
    result: State = {}
    for k in keys:
        v = widen(state_get(old, k), state_get(new, k), iteration, max_iter)
        if not is_clean(v):
            result[k] = v
    return result


# ============================================================================
# Pretty
# ============================================================================

def pretty_taint(t: Taint) -> str:
    """Render a taint value as a human-readable string for debugging and tests."""
    if is_clean(t):
        return "⊥"
    if is_top(t):
        return "⊤"
    assert isinstance(t, Tainted)
    kinds_str = "{" + ",".join(sorted(t.kinds)) + "}"
    return f"Tainted{kinds_str}@{t.source.line}"


def pretty_state(state: State) -> str:
    """Render a state as a human-readable string."""
    if not state:
        return "{}"
    items = sorted(state.items())
    return "{" + ", ".join(f"{k}: {pretty_taint(v)}" for k, v in items) + "}"
