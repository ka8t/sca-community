"""Tests du lattice taint — Phase 3 du moteur dataflow SCA.

Couvre la sémantique du lattice (spec §4) :
  - ⊑ ordre partiel
  - ⊔ join
  - ⊓ meet
  - ∇ widening
  - Opérations sur State (dict canon_name → Taint)
"""
from __future__ import annotations

import pytest

from sca.dataflow.lattice import (
    CLEAN,
    TOP,
    SourceInfo,
    State,
    Tainted,
    empty_state,
    is_clean,
    is_tainted,
    is_top,
    join,
    leq,
    meet,
    pretty_state,
    pretty_taint,
    state_equal,
    state_get,
    state_join,
    state_set,
    state_widen,
    widen,
)


# ============================================================================
# Constantes du lattice
# ============================================================================

class TestConstants:

    def test_clean_is_none(self):
        assert CLEAN is None
        assert is_clean(CLEAN)
        assert not is_tainted(CLEAN)
        assert not is_top(CLEAN)

    def test_top_is_singleton(self):
        # _TopSingleton est un singleton
        from sca.dataflow.lattice import _TopSingleton
        assert _TopSingleton() is _TopSingleton()
        assert _TopSingleton() == TOP
        assert is_top(TOP)
        assert is_tainted(TOP)
        assert not is_clean(TOP)

    def test_tainted_requires_kinds(self):
        with pytest.raises(ValueError):
            Tainted(kinds=frozenset(), source=SourceInfo(line=1))


# ============================================================================
# Ordre partiel ⊑
# ============================================================================

class TestLeq:

    def _t(self, *kinds, line=1) -> Tainted:
        return Tainted(kinds=frozenset(kinds), source=SourceInfo(line=line))

    def test_clean_is_below_everything(self):
        assert leq(CLEAN, CLEAN)
        assert leq(CLEAN, self._t("http"))
        assert leq(CLEAN, TOP)

    def test_top_is_above_everything(self):
        assert leq(CLEAN, TOP)
        assert leq(self._t("http"), TOP)
        assert leq(TOP, TOP)

    def test_kinds_subset(self):
        t1 = self._t("http")
        t2 = self._t("http", "cli")
        assert leq(t1, t2)
        assert not leq(t2, t1)

    def test_kinds_disjoint(self):
        a = self._t("http")
        b = self._t("cli")
        # Aucun n'est sous l'autre
        assert not leq(a, b)
        assert not leq(b, a)


# ============================================================================
# Join ⊔
# ============================================================================

class TestJoin:

    def _t(self, *kinds, line=1) -> Tainted:
        return Tainted(kinds=frozenset(kinds), source=SourceInfo(line=line))

    def test_join_clean_identity(self):
        t = self._t("http")
        assert join(CLEAN, t) == t
        assert join(t, CLEAN) == t

    def test_join_top_absorbing(self):
        t = self._t("http")
        assert join(TOP, t) is TOP
        assert join(t, TOP) is TOP
        assert join(TOP, CLEAN) is TOP

    def test_join_kinds_union(self):
        a = self._t("http", line=5)
        b = self._t("cli", line=3)
        result = join(a, b)
        assert isinstance(result, Tainted)
        assert result.kinds == frozenset({"http", "cli"})
        # source vient de la première ligne (cohérence rapport)
        assert result.source.line == 3


# ============================================================================
# Meet ⊓
# ============================================================================

class TestMeet:

    def _t(self, *kinds, line=1) -> Tainted:
        return Tainted(kinds=frozenset(kinds), source=SourceInfo(line=line))

    def test_meet_with_clean(self):
        assert meet(CLEAN, self._t("http")) is CLEAN
        assert meet(self._t("http"), CLEAN) is CLEAN

    def test_meet_with_top(self):
        t = self._t("http")
        assert meet(TOP, t) == t
        assert meet(t, TOP) == t

    def test_meet_kinds_intersection(self):
        a = self._t("http", "cli")
        b = self._t("cli", "env")
        result = meet(a, b)
        assert isinstance(result, Tainted)
        assert result.kinds == frozenset({"cli"})

    def test_meet_disjoint_returns_clean(self):
        a = self._t("http")
        b = self._t("cli")
        assert meet(a, b) is CLEAN


# ============================================================================
# Widening ∇
# ============================================================================

class TestWiden:

    def _t(self, *kinds, line=1) -> Tainted:
        return Tainted(kinds=frozenset(kinds), source=SourceInfo(line=line))

    def test_widen_below_max_iter(self):
        old = self._t("http")
        new = self._t("http", "cli")
        # iter 1 → ne widen pas
        result = widen(old, new, iteration=1, max_iter=3)
        assert result == new

    def test_widen_above_max_iter_distinct(self):
        old = self._t("http")
        new = self._t("http", "cli")
        # iter 4 > max_iter=3, old != new → ⊤
        result = widen(old, new, iteration=4, max_iter=3)
        assert is_top(result)

    def test_widen_above_max_iter_same(self):
        t = self._t("http")
        # Même valeur → on garde new (pas de widen)
        result = widen(t, t, iteration=10, max_iter=3)
        assert result == t


# ============================================================================
# State operations
# ============================================================================

class TestState:

    def _t(self, *kinds, line=1) -> Tainted:
        return Tainted(kinds=frozenset(kinds), source=SourceInfo(line=line))

    def test_empty_state(self):
        s = empty_state()
        assert s == {}
        assert is_clean(state_get(s, "x"))

    def test_state_set(self):
        s = empty_state()
        t = self._t("http")
        s2 = state_set(s, "x", t)
        assert state_get(s2, "x") == t
        # s original non modifié
        assert state_get(s, "x") is CLEAN

    def test_state_set_clean_removes_key(self):
        s = state_set(empty_state(), "x", self._t("http"))
        s2 = state_set(s, "x", CLEAN)
        assert "x" not in s2

    def test_state_join(self):
        a = state_set(empty_state(), "x", self._t("http", line=1))
        b = state_set(empty_state(), "x", self._t("cli", line=2))
        merged = state_join(a, b)
        merged_taint = merged["x"]
        assert isinstance(merged_taint, Tainted)
        assert merged_taint.kinds == frozenset({"http", "cli"})

    def test_state_join_keeps_all_keys(self):
        a = state_set(empty_state(), "x", self._t("http"))
        b = state_set(empty_state(), "y", self._t("cli"))
        merged = state_join(a, b)
        assert "x" in merged
        assert "y" in merged

    def test_state_equal(self):
        a = state_set(empty_state(), "x", self._t("http", line=1))
        b = state_set(empty_state(), "x", self._t("http", line=1))
        assert state_equal(a, b)
        c = state_set(empty_state(), "x", self._t("cli", line=1))
        assert not state_equal(a, c)

    def test_state_widen(self):
        old = state_set(empty_state(), "x", self._t("http"))
        new = state_set(empty_state(), "x", self._t("http", "cli"))
        widened = state_widen(old, new, iteration=4, max_iter=3)
        assert is_top(widened["x"])


# ============================================================================
# Pretty printing
# ============================================================================

class TestPretty:

    def test_pretty_clean(self):
        assert pretty_taint(CLEAN) == "⊥"

    def test_pretty_top(self):
        assert pretty_taint(TOP) == "⊤"

    def test_pretty_tainted(self):
        t = Tainted(kinds=frozenset({"http", "cli"}), source=SourceInfo(line=5))
        out = pretty_taint(t)
        assert "http" in out
        assert "cli" in out
        assert "5" in out

    def test_pretty_state(self):
        s = state_set(empty_state(), "x", Tainted(
            kinds=frozenset({"http"}), source=SourceInfo(line=2)
        ))
        out = pretty_state(s)
        assert "x" in out
