"""Tests Phase 9.quater — simulation des opérations mutantes sur Const(list).

Évidence corpus : 11 FPs OWASP (pathtraver 8, xss 1, xxe 1, codeinj 1)
utilisent le pattern « list-shuffle » :

    lst = []
    lst.append('safe')          # tuple = ('safe',)
    lst.append(param)           # tuple = ('safe', _OPAQUE)
    lst.append('moresafe')      # tuple = ('safe', _OPAQUE, 'moresafe')
    lst.pop(0)                  # tuple = (_OPAQUE, 'moresafe')
    bar = lst[1]                # = 'moresafe' → bar CLEAN
    sink(bar)                   # ne doit plus flag

L'élément `_OPAQUE` représente un slot rempli par une valeur non-Const
(probablement tainté). À la lecture `lst[i]`, si tuple[i] == _OPAQUE,
`_eval_subscript` retourne None — pas de simplification, le moteur taint
normal continue d'évaluer.

Référence : `sca/dataflow/const_eval.py` (apply_list_mutation,
_OpaqueElement), fixtures OWASP `BenchmarkTest00436` (xss), `00679` (xxe),
`00179` (pathtraver), `00424` (codeinj).
"""
from __future__ import annotations

from sca.executors.dataflow_taint import run_taint_rule


_RULE_SQL = {
    "id": "taint_nosql",
    "mode": "taint",
    "severity": "HIGH",
    "sources": [{"pattern": r"request\.(GET|POST|args|form)", "kind": "http"}],
    "sinks": [{"pattern": r"\.find_one\s*\("}],
}


class TestListShuffleCorpus:
    """Patterns OWASP corpus list-shuffle, reproduction directe."""

    def test_pop_zero_read_index_one_clean(self):
        # Pattern OWASP « lst.pop(0); bar = lst[1] » → bar = 'moresafe'
        # (clean). Reproduction de BenchmarkTest00436.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.append('moresafe')
    lst.pop(0)
    bar = lst[1]
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 0, (
            f"List-shuffle pop(0)+lst[1] doit donner bar='moresafe' clean "
            f"(got {len(findings)} findings)"
        )

    def test_pop_zero_read_index_zero_tainted(self):
        # Variante TP : `lst.pop(0); bar = lst[0]` → bar = param tainté.
        # Le mécanisme ne doit PAS sur-nettoyer un vrai positif.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.append('moresafe')
    lst.pop(0)
    bar = lst[0]
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 1, (
            f"List-shuffle pop(0)+lst[0] doit donner bar=param tainté "
            f"(got {len(findings)} findings)"
        )

    def test_no_pop_read_index_zero_clean(self):
        # Sans pop, lst[0] = 'safe' → clean.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    lst = []
    lst.append('safe')
    lst.append(param)
    bar = lst[0]
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 0

    def test_no_pop_read_index_one_tainted(self):
        # Sans pop, lst[1] = param → tainté.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    lst = []
    lst.append('safe')
    lst.append(param)
    bar = lst[1]
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 1


class TestListMutationEdgeCases:
    """Cas limites des opérations de liste."""

    def test_pop_default_no_arg(self):
        # `lst.pop()` sans arg → retire le dernier élément.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.pop()       # tuple = ('safe',)
    bar = lst[0]    # = 'safe' clean
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 0

    def test_insert_at_index(self):
        # `lst.insert(0, x)` insère à l'index 0.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    lst = []
    lst.append('safe')          # ('safe',)
    lst.insert(0, 'first')      # ('first', 'safe')
    lst.insert(1, param)        # ('first', _OPAQUE, 'safe')
    bar = lst[2]                # = 'safe' clean
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 0

    def test_extend_with_literal_tuple(self):
        # `lst.extend((a, b))` concatène un Const(tuple).
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    lst = []
    lst.append('safe')
    lst.extend(('moresafe', 'extra'))   # ('safe', 'moresafe', 'extra')
    bar = lst[2]                          # = 'extra' clean
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 0


class TestNoRegression:
    """Vérifier que les FN/régression sur cas valides ne sont pas créées."""

    def test_dynamic_index_falls_back_to_taint(self):
        # `lst[i]` avec i variable → la simplification n'a pas lieu, le
        # moteur taint joint les éléments → sur-prudence (TAINT).
        src = """
from flask import request
db = client.db
def handler(i):
    param = request.args.get('p')
    lst = []
    lst.append('safe')
    lst.append(param)
    bar = lst[i]
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 1, (
            f"Index dynamique → sur-prudence taint (got {len(findings)})"
        )

    def test_append_unknown_call_invalidates(self):
        # `lst.append(some_unknown_call())` : le call retourne None en
        # eval_const → _OPAQUE ajouté. Le moteur taint évalue le call
        # normalement et propage si tainté.
        src = """
from flask import request
db = client.db
def handler():
    param = request.args.get('p')
    lst = []
    lst.append(some_call(param))    # _OPAQUE (call tainté via param)
    bar = lst[0]                     # _OPAQUE → fallback taint
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE_SQL, src, language="python"))
        assert len(findings) == 1
