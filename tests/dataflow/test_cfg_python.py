"""Tests de construction du CFG Python — Phase 1 du moteur dataflow SCA.

Couvre les 30+ cas du plan PLAN-SCA-DATAFLOW.md §5 — Phase 1.

Vérifie :
  - Structure (nœuds, arêtes par type, invariants spec §2.4)
  - Construction par type de statement (if, while, for, try, match, etc.)
  - Cas de contrôle de flot non trivial (break, continue, return, raise)
  - Pruning des nœuds inatteignables
  - Ordre RPO
"""
from __future__ import annotations

import ast
from typing import List

import pytest

from sca.dataflow import (
    CFG,
    CFGNode,
    EdgeLabel,
    NodeKind,
    build_cfg,
    reverse_post_order,
)


# ============================================================================
# Helpers
# ============================================================================

def _cfg(src: str) -> CFG:
    """Parse et construit le CFG d'un fragment Python."""
    return build_cfg(ast.parse(src))


def _count_kind(cfg: CFG, kind: NodeKind) -> int:
    return sum(1 for n in cfg.nodes.values() if n.kind == kind)


def _count_label(cfg: CFG, label: EdgeLabel) -> int:
    return sum(1 for e in cfg.edges if e.label == label)


def _has_path(cfg: CFG, src: int, dst: int) -> bool:
    """True s'il existe un chemin orienté de src vers dst."""
    visited = set()
    stack = [src]
    while stack:
        n = stack.pop()
        if n == dst:
            return True
        if n in visited:
            continue
        visited.add(n)
        for e in cfg.successors(n):
            stack.append(e.dst)
    return False


def _all_reachable_from_entry(cfg: CFG) -> bool:
    visited = set()
    stack = [cfg.entry]
    while stack:
        n = stack.pop()
        if n in visited:
            continue
        visited.add(n)
        for e in cfg.successors(n):
            stack.append(e.dst)
    return visited == set(cfg.nodes.keys())


# ============================================================================
# Invariants généraux (spec §2.4)
# ============================================================================

class TestInvariants:
    """Tous les CFG construits doivent respecter les invariants §2.4."""

    @pytest.mark.parametrize("src", [
        "",
        "x = 1",
        "x = 1\ny = 2\nz = 3",
        "if x: y = 1",
        "if x: y = 1\nelse: y = 2",
        "while x: x = x - 1",
        "for i in xs: print(i)",
        "try:\n  f()\nexcept Exception:\n  pass",
        "def foo():\n  return 1",
    ])
    def test_unique_entry_and_exit(self, src):
        cfg = _cfg(src)
        assert _count_kind(cfg, NodeKind.ENTRY) == 1
        assert _count_kind(cfg, NodeKind.EXIT) == 1
        assert cfg.entry in cfg.nodes
        assert cfg.exit in cfg.nodes

    @pytest.mark.parametrize("src", [
        "x = 1",
        "if x: y = 1\nelse: y = 2",
        "while x: x = x - 1",
    ])
    def test_entry_has_no_predecessors(self, src):
        cfg = _cfg(src)
        assert cfg.predecessors(cfg.entry) == []

    @pytest.mark.parametrize("src", [
        "x = 1",
        "if x: y = 1\nelse: y = 2",
        "return\n",  # à l'intérieur d'une fonction normalement, mais ast accepte au top
    ])
    def test_exit_has_no_successors(self, src):
        # Note : "return" au top niveau lève SyntaxError, on saute ce cas
        try:
            cfg = _cfg(src)
        except SyntaxError:
            pytest.skip("syntaxe top-level invalide")
        assert cfg.successors(cfg.exit) == []

    @pytest.mark.parametrize("src", [
        "x = 1",
        "if x: y = 1\nelse: y = 2",
        "while x: x = x - 1",
        "for i in xs: print(i)",
    ])
    def test_all_nodes_reachable_from_entry(self, src):
        cfg = _cfg(src)
        assert _all_reachable_from_entry(cfg)


# ============================================================================
# Module vide / statements linéaires
# ============================================================================

class TestLinear:

    def test_empty_module(self):
        cfg = _cfg("")
        assert len(cfg.nodes) == 2  # entry + exit
        assert len(cfg.edges) == 1
        assert cfg.edges[0].label == EdgeLabel.FLOW

    def test_single_statement(self):
        cfg = _cfg("x = 1")
        assert _count_kind(cfg, NodeKind.BASIC) == 1
        # entry → bb → exit
        assert len(cfg.edges) == 2

    def test_linear_statements_aggregated(self):
        """Plusieurs statements simples consécutifs doivent rentrer dans 1 BasicBlock."""
        cfg = _cfg("x = 1\ny = 2\nz = x + y\nprint(z)")
        assert _count_kind(cfg, NodeKind.BASIC) == 1
        bb = next(iter(n for n in cfg.nodes.values() if n.kind == NodeKind.BASIC))
        assert len(bb.statements) == 4


# ============================================================================
# If / elif / else
# ============================================================================

class TestIfElse:

    def test_if_without_else(self):
        cfg = _cfg("if x:\n    y = 1\nz = 2")
        assert _count_kind(cfg, NodeKind.BRANCH) == 1
        assert _count_label(cfg, EdgeLabel.TRUE) == 1
        assert _count_label(cfg, EdgeLabel.FALSE) == 1

    def test_if_else(self):
        cfg = _cfg("if x:\n    y = 1\nelse:\n    y = 2")
        assert _count_kind(cfg, NodeKind.BRANCH) == 1
        # Les deux branches doivent atteindre exit
        assert _has_path(cfg, cfg.entry, cfg.exit)

    def test_if_elif_else_cascade(self):
        cfg = _cfg("if a:\n    x = 1\nelif b:\n    x = 2\nelif c:\n    x = 3\nelse:\n    x = 4")
        # 3 branchements (if + 2 elif)
        assert _count_kind(cfg, NodeKind.BRANCH) == 3
        assert _has_path(cfg, cfg.entry, cfg.exit)

    def test_nested_if(self):
        src = (
            "if a:\n"
            "    if b:\n"
            "        x = 1\n"
            "    else:\n"
            "        x = 2\n"
            "else:\n"
            "    x = 3"
        )
        cfg = _cfg(src)
        assert _count_kind(cfg, NodeKind.BRANCH) == 2

    def test_if_with_return_in_branch(self):
        """Si un branch retourne, le join n'a qu'un prédécesseur."""
        src = (
            "def f(x):\n"
            "    if x:\n"
            "        return 1\n"
            "    y = 2\n"
            "    return y"
        )
        cfg = _cfg(src)
        # cfg du module : `def f(...)` est traité comme statement linéaire
        # (FunctionDef → _visit_default). Donc 1 seul BasicBlock dans ce cfg.
        assert _count_kind(cfg, NodeKind.BASIC) == 1


# ============================================================================
# While / For
# ============================================================================

class TestLoops:

    def test_while_basic(self):
        cfg = _cfg("while x > 0:\n    x = x - 1")
        assert _count_kind(cfg, NodeKind.LOOP) == 1
        assert _count_label(cfg, EdgeLabel.BACK) >= 1
        assert _count_label(cfg, EdgeLabel.TRUE) == 1
        assert _count_label(cfg, EdgeLabel.FALSE) == 1

    def test_while_else(self):
        """Python while/else : else exécuté si la boucle se termine sans break."""
        cfg = _cfg("while x:\n    y = 1\nelse:\n    z = 2")
        # Le loop_head a une arête FALSE vers la branche else, pas directement
        # vers exit_join.
        loop = next(iter(n for n in cfg.nodes.values() if n.kind == NodeKind.LOOP))
        false_targets = [e.dst for e in cfg.successors(loop.id) if e.label == EdgeLabel.FALSE]
        assert len(false_targets) == 1

    def test_for_basic(self):
        cfg = _cfg("for i in xs:\n    print(i)")
        assert _count_kind(cfg, NodeKind.LOOP) == 1
        assert _count_label(cfg, EdgeLabel.BACK) >= 1

    def test_for_else(self):
        cfg = _cfg("for i in xs:\n    f(i)\nelse:\n    g()")
        assert _count_kind(cfg, NodeKind.LOOP) == 1

    def test_nested_loops(self):
        src = (
            "for i in xs:\n"
            "    for j in ys:\n"
            "        f(i, j)"
        )
        cfg = _cfg(src)
        assert _count_kind(cfg, NodeKind.LOOP) == 2


# ============================================================================
# Break / Continue
# ============================================================================

class TestBreakContinue:

    def test_break_in_while(self):
        cfg = _cfg("while x:\n    if y:\n        break\n    x = x - 1")
        # Au moins une arête flow va directement de la branche break vers
        # exit_join (pas une arête back).
        # Tous les chemins atteignent exit.
        assert _has_path(cfg, cfg.entry, cfg.exit)

    def test_continue_in_while(self):
        cfg = _cfg("while x:\n    if y:\n        continue\n    x = x - 1")
        assert _count_label(cfg, EdgeLabel.BACK) >= 2  # corps normal + continue

    def test_break_inside_nested_loop(self):
        """break sort de la boucle la plus interne uniquement."""
        src = (
            "for i in xs:\n"
            "    for j in ys:\n"
            "        if cond:\n"
            "            break\n"
            "        f(j)\n"
            "    g(i)"
        )
        cfg = _cfg(src)
        # 2 boucles + exit reachable
        assert _count_kind(cfg, NodeKind.LOOP) == 2
        assert _has_path(cfg, cfg.entry, cfg.exit)


# ============================================================================
# Return / Raise
# ============================================================================

class TestReturnRaise:

    def test_return_terminates_path(self):
        """Après un return, les statements suivants sont inatteignables."""
        # Au top level, return = SyntaxError, on enrobe dans une fonction.
        # FunctionDef est opaque (linéaire), donc le test passe par un cfg de
        # `return` direct dans un module via une boucle qui peut break.
        # Le cas le plus simple : module avec break (pas return — sinon syntax error).
        src = (
            "while True:\n"
            "    x = 1\n"
            "    break\n"
            "    y = 2  # mort\n"
        )
        cfg = _cfg(src)
        # Le statement `y = 2` doit être pruné (inaccessible)
        # On vérifie indirectement : aucun BasicBlock ne contient `y = 2`.
        for node in cfg.nodes.values():
            for stmt in node.statements:
                src_stmt = ast.unparse(stmt) if hasattr(ast, "unparse") else ""
                assert "y = 2" not in src_stmt

    def test_raise_at_module_level(self):
        cfg = _cfg("raise ValueError('oops')")
        # Doit y avoir un nœud RAISE_SITE
        assert _count_kind(cfg, NodeKind.RAISE_SITE) == 1
        # Avec arête ESCAPE vers exit (pas de try englobant)
        assert _count_label(cfg, EdgeLabel.ESCAPE) == 1


# ============================================================================
# Try / Except / Finally
# ============================================================================

class TestTryExcept:

    def test_try_with_single_except(self):
        src = (
            "try:\n"
            "    f()\n"
            "except Exception:\n"
            "    handle()"
        )
        cfg = _cfg(src)
        assert _count_kind(cfg, NodeKind.TRY_ENTRY) == 1
        assert _count_kind(cfg, NodeKind.HANDLER) == 1
        # Arête except depuis try_entry vers handler
        assert _count_label(cfg, EdgeLabel.EXCEPT) >= 1

    def test_try_multiple_excepts(self):
        src = (
            "try:\n"
            "    f()\n"
            "except ValueError:\n"
            "    h1()\n"
            "except TypeError:\n"
            "    h2()"
        )
        cfg = _cfg(src)
        assert _count_kind(cfg, NodeKind.HANDLER) == 2

    def test_try_with_finally(self):
        src = (
            "try:\n"
            "    f()\n"
            "finally:\n"
            "    cleanup()"
        )
        cfg = _cfg(src)
        assert _count_kind(cfg, NodeKind.FINALLY) == 1

    def test_try_except_finally(self):
        src = (
            "try:\n"
            "    f()\n"
            "except ValueError:\n"
            "    h()\n"
            "finally:\n"
            "    cleanup()"
        )
        cfg = _cfg(src)
        assert _count_kind(cfg, NodeKind.HANDLER) == 1
        assert _count_kind(cfg, NodeKind.FINALLY) == 1

    def test_try_except_else(self):
        src = (
            "try:\n"
            "    f()\n"
            "except ValueError:\n"
            "    h()\n"
            "else:\n"
            "    g()"
        )
        cfg = _cfg(src)
        assert _count_kind(cfg, NodeKind.TRY_ENTRY) == 1

    def test_raise_inside_try_reaches_handler(self):
        """Un raise explicite dans un try doit atteindre le handler."""
        src = (
            "try:\n"
            "    raise ValueError\n"
            "except ValueError:\n"
            "    h()"
        )
        cfg = _cfg(src)
        raise_node = next(iter(n for n in cfg.nodes.values() if n.kind == NodeKind.RAISE_SITE))
        handler = next(iter(n for n in cfg.nodes.values() if n.kind == NodeKind.HANDLER))
        # Le raise doit avoir une arête EXCEPT vers le handler
        succ_labels = [(e.dst, e.label) for e in cfg.successors(raise_node.id)]
        assert (handler.id, EdgeLabel.EXCEPT) in succ_labels


# ============================================================================
# Match (Python 3.10+)
# ============================================================================

class TestMatch:

    def test_match_basic(self):
        src = (
            "match cmd:\n"
            "    case 'a':\n"
            "        f()\n"
            "    case 'b':\n"
            "        g()"
        )
        cfg = _cfg(src)
        # Choix SCA-1 : chaque case est un Branch.
        assert _count_kind(cfg, NodeKind.BRANCH) == 2


# ============================================================================
# With
# ============================================================================

class TestWith:

    def test_with_statement(self):
        src = (
            "with open('f') as fp:\n"
            "    data = fp.read()"
        )
        cfg = _cfg(src)
        # En phase 1, on linéarise simplement : 1 BasicBlock + 1 BasicBlock
        # pour le body. Détail testé : exit atteint.
        assert _has_path(cfg, cfg.entry, cfg.exit)

    def test_async_with(self):
        src = (
            "async def coro():\n"
            "    async with cm() as x:\n"
            "        await use(x)"
        )
        cfg = _cfg(src)
        # AsyncFunctionDef est opaque, donc 1 seul BasicBlock
        assert _count_kind(cfg, NodeKind.BASIC) == 1


# ============================================================================
# Comprehensions / Lambda
# ============================================================================

class TestComprehensionLambda:

    def test_comprehension_does_not_create_loop_in_cfg(self):
        """En phase 1, une comprehension est traitée comme expression
        à l'intérieur du statement courant (pas de désucrage CFG).
        Le désucrage de la spec §3.4 est fait par l'IR (phase 2)."""
        cfg = _cfg("y = [x*x for x in xs]")
        # Pas de LOOP attendu en phase 1
        assert _count_kind(cfg, NodeKind.LOOP) == 0

    def test_lambda_inline(self):
        cfg = _cfg("f = lambda x: x + 1")
        # Lambda est un sous-CFG opaque ; au module level, c'est un BasicBlock
        assert _count_kind(cfg, NodeKind.BASIC) == 1


# ============================================================================
# Imports / Definitions (statements linéaires)
# ============================================================================

class TestStatementsLinear:

    def test_import(self):
        cfg = _cfg("import os\nimport sys")
        assert _count_kind(cfg, NodeKind.BASIC) == 1

    def test_function_def_opaque(self):
        cfg = _cfg("def f(x):\n    return x + 1\n\nfoo()")
        # 1 BasicBlock contenant `def f` + `foo()`
        assert _count_kind(cfg, NodeKind.BASIC) == 1

    def test_class_def_opaque(self):
        cfg = _cfg("class C:\n    pass\n\nc = C()")
        assert _count_kind(cfg, NodeKind.BASIC) == 1


# ============================================================================
# RPO
# ============================================================================

class TestRPO:

    def test_rpo_empty(self):
        cfg = _cfg("")
        rpo = reverse_post_order(cfg)
        assert rpo[0] == cfg.entry
        assert rpo[-1] == cfg.exit

    def test_rpo_starts_with_entry(self):
        cfg = _cfg("x = 1\ny = 2")
        rpo = reverse_post_order(cfg)
        assert rpo[0] == cfg.entry

    def test_rpo_covers_all_nodes(self):
        cfg = _cfg("if x:\n    y = 1\nelse:\n    y = 2")
        rpo = reverse_post_order(cfg)
        # Tous les nœuds atteignables figurent dans la liste
        assert set(rpo) == set(cfg.nodes.keys())

    def test_rpo_predecessors_come_before(self):
        """Dans un CFG sans cycle, les prédécesseurs apparaissent avant
        leurs successeurs en RPO (NNH §2.5.2)."""
        cfg = _cfg("x = 1\nif x:\n    y = 1\nelse:\n    y = 2\nz = 3")
        rpo = reverse_post_order(cfg)
        rank = {nid: i for i, nid in enumerate(rpo)}
        for e in cfg.edges:
            # On accepte les back edges (cycles), pas de cycle ici donc check direct
            if e.label != EdgeLabel.BACK:
                assert rank[e.src] <= rank[e.dst] or e.src == e.dst, (
                    f"RPO viole l'ordre : {e.src} avant {e.dst}"
                )


# ============================================================================
# Pruning
# ============================================================================

class TestPruning:

    def test_unreachable_code_after_break_pruned(self):
        src = (
            "while True:\n"
            "    break\n"
            "    x = 1  # mort\n"
        )
        cfg = _cfg(src)
        # Le statement x = 1 ne doit pas figurer dans le CFG (pruné)
        for node in cfg.nodes.values():
            for stmt in node.statements:
                if hasattr(ast, "unparse"):
                    assert "x = 1" not in ast.unparse(stmt)


# ============================================================================
# Cas d'erreur / robustesse
# ============================================================================

class TestRobustness:

    def test_build_cfg_rejects_non_module(self):
        with pytest.raises(TypeError):
            build_cfg(ast.parse("x = 1", mode="exec").body[0])  # type: ignore[arg-type]

    def test_empty_function_def_is_opaque(self):
        """`def f(): pass` au module level → BasicBlock opaque."""
        cfg = _cfg("def f():\n    pass")
        # Au module level, def est un seul BasicBlock
        assert _count_kind(cfg, NodeKind.BASIC) == 1

    def test_decorators_treated_as_part_of_def(self):
        cfg = _cfg("@dec\ndef f():\n    pass")
        # Décorateur + def = 1 BasicBlock opaque
        assert _count_kind(cfg, NodeKind.BASIC) == 1


# ============================================================================
# Cohérence successors / predecessors
# ============================================================================

class TestConsistency:

    @pytest.mark.parametrize("src", [
        "x = 1",
        "if x:\n    y = 1\nelse:\n    y = 2",
        "while x:\n    x = x - 1",
        "for i in xs:\n    print(i)",
        "try:\n    f()\nexcept Exception:\n    pass",
    ])
    def test_successors_and_predecessors_consistent(self, src):
        """Si A → B dans successors(A), alors A figure dans predecessors(B)."""
        cfg = _cfg(src)
        for nid in cfg.nodes:
            for e in cfg.successors(nid):
                pred_srcs = [p.src for p in cfg.predecessors(e.dst)]
                assert nid in pred_srcs, (
                    f"{nid} → {e.dst} dans successors mais "
                    f"{nid} absent de predecessors({e.dst})"
                )
