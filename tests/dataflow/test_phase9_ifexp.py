"""Tests Phase 9 — élimination de branches mortes dans les IfExp ternaires.

Couverture (évidence corpus : 43 fixtures OWASP contiennent ce pattern,
ex. BenchmarkTest00363/00367/00668/00830) :
  - cond purement constante (1+1 > 0, 7*42 > 200, etc.).
  - cond via une variable const-propagée (`num = 5; bar = X if 7*N+num>K else Y`).
  - cond non-évaluable : sémantique conservatrice (join des deux branches).

Référence : sca/dataflow/const_eval.py + sca/dataflow/worklist.py
(_compute_dead_edges réécrit node_ir au fil du fixpoint).
"""
from __future__ import annotations

from sca.executors.dataflow_taint import run_taint_rule


_RULE = {
    "id": "taint_nosql",
    "mode": "taint",
    "severity": "HIGH",
    "sources": [{"pattern": r"request\.(GET|POST|args|form)", "kind": "http"}],
    "sinks": [{"pattern": r"\.find_one\s*\("}],
}


class TestIfExpConstCondition:
    """cond purement constante, sans variable à résoudre."""

    def test_true_const_keeps_then(self):
        # Pattern OWASP réel : la source est dans une variable séparée,
        # l'IfExp choisit entre safe et param. `1 + 1 > 0` → True → "safe".
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    bar = "safe" if 1 + 1 > 0 else param
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"IfExp cond const True → branche then prise, bar clean "
            f"(got {len(findings)})"
        )

    def test_false_const_keeps_orelse(self):
        # `1 == 2` → False → bar = param tainté.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    bar = "safe" if 1 == 2 else param
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"IfExp cond const False → branche orelse prise, bar tainté "
            f"(got {len(findings)})"
        )


class TestIfExpViaConstState:
    """cond utilisant une variable préalablement propagée par const_state."""

    def test_owasp_arith_with_const_var(self):
        # Reproduction directe de BenchmarkTest00363/00367 :
        # `bar = "safe" if 7 * 18 + num > 200 else param` avec num = 106.
        # 7*18 + 106 = 232 > 200 → True → bar = "safe".
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    num = 106
    bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"Pattern OWASP arith (num=106, 7*18+num>200) doit éliminer "
            f"la branche else (got {len(findings)})"
        )

    def test_arith_negative_keeps_orelse(self):
        # Inverse : num = 1, 7*18+1 = 127 < 200 → cond False → bar = param.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    num = 1
    bar = "safe" if 7 * 18 + num > 200 else param
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"Pattern arith (num=1) → cond False → bar = param tainté "
            f"(got {len(findings)})"
        )


class TestIfExpNonEvaluable:
    """cond non-évaluable : comportement conservateur (join des branches)."""

    def test_variable_cond_joins_both_branches(self):
        # Régression : si cond dépend d'une variable non-Const, on joint
        # les deux branches → bar peut être tainté.
        src = """
from flask import request
db = client.db
def handler(threshold):
    param = request.args.get('p')
    bar = "safe" if threshold > 200 else param
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"IfExp cond variable → join des deux branches → bar tainté "
            f"(got {len(findings)})"
        )

    def test_no_simplification_no_regression(self):
        # Vérifier qu'un IfExp sans simplification possible se comporte
        # comme l'ancien Bool(or) : taint propagé depuis n'importe quelle
        # branche.
        src = """
from flask import request
db = client.db
def handler(cond_var):
    a = request.args.get('p')
    b = "safe"
    bar = a if cond_var else b
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1


class TestIfExpAndConstFolding:
    """Interaction avec les autres mécanismes Phase 9."""

    def test_ifexp_propagates_into_const_state(self):
        # Après simplification, bar = "Hello" devient connu en const_state.
        # Une condition ultérieure peut utiliser bar.
        src = """
from flask import request
db = client.db
def handler():
    bar = "safe" if 2 + 2 == 4 else request.args.get('p')
    if bar == "different":
        leaked = request.args.get('q')
    else:
        leaked = "ok"
    return db.users.find_one(leaked)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"Après IfExp simplifiée, bar='safe' est propagé ; bar=='different' "
            f"est False → branche then morte (got {len(findings)})"
        )
