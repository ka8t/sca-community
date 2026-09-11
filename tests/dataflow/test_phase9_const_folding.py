"""Tests Phase 9 — propagation de constantes et marquage des arêtes mortes.

Couverture :
  - P1 — branches `if` arithmétiquement résolues à compile-time.
  - P2 — `match/case` sur valeur connue (subject = "ABC"[1] → 'B').
  - Cas tordus — TypeError / ZeroDivisionError silencieuses.
  - Non-régression — conditions variables jointes normalement.

Référence : sca/docs/dataflow-spec.md §11 (Phase 9) + memory project_owasp_f1.md.
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


class TestArithmeticConditionFolding:
    """P1 — conditions `if` calculables à compile-time."""

    def test_arith_true_const_else_branch_dead(self):
        # `if 7*42 - 5 > 200:` est toujours True (289 > 200) — branche else
        # ne devrait pas contribuer au state du sink. bar reste 'safe'.
        src = """
from flask import request
db = client.db
def handler():
    if 7 * 42 - 5 > 200:
        bar = 'safe'
    else:
        bar = request.args.get('p')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"Condition arithmétique toujours vraie : branche else doit "
            f"être éliminée (got {len(findings)} findings)"
        )

    def test_arith_false_const_then_branch_dead(self):
        src = """
from flask import request
db = client.db
def handler():
    if 1 == 2:
        bar = request.args.get('p')
    else:
        bar = 'safe'
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"Condition `1 == 2` toujours fausse : branche then doit être "
            f"éliminée (got {len(findings)} findings)"
        )

    def test_variable_condition_still_joins(self):
        # Régression : condition non-constante doit toujours joindre.
        src = """
from flask import request
db = client.db
def handler(n):
    if n > 200:
        bar = 'safe'
    else:
        bar = request.args.get('p')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"Condition variable : branches jointes, FP attendu "
            f"(got {len(findings)})"
        )

    def test_not_false_elides_else(self):
        src = """
from flask import request
db = client.db
def handler():
    if not False:
        bar = 'safe'
    else:
        bar = request.args.get('p')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0


class TestMatchConstSubject:
    """P2 — `match` sur subject calculable à compile-time."""

    def test_match_subject_const_string_subscript(self):
        # guess = "ABC"[1] → 'B'. Seule la case 'B' doit être prise.
        src = """
from flask import request
db = client.db
def handler():
    guess = "ABC"[1]
    match guess:
        case 'A':
            bar = request.args.get('p')
        case 'B':
            bar = 'safe'
        case _:
            bar = request.args.get('p')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"match sur subject const : seule la case 'B' doit être prise "
            f"(got {len(findings)} findings)"
        )

    def test_match_subject_variable_joins(self):
        # Régression : subject non-constant → toutes les cases jointes.
        src = """
from flask import request
db = client.db
def handler(g):
    match g:
        case 'A':
            bar = request.args.get('p')
        case 'B':
            bar = 'safe'
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1


class TestSafeAgainstRuntimeErrors:
    """Phase 9 ne doit jamais crasher sur des expressions invalides."""

    def test_type_mismatch_no_crash(self):
        # `1 + "a"` lèverait TypeError au runtime — Phase 9 doit retourner
        # None et joindre les deux branches sans crasher.
        src = """
from flask import request
db = client.db
def handler():
    if 1 + "a" == "1a":
        bar = 'safe'
    else:
        bar = request.args.get('p')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        # Branches jointes ; FP attendu, mais SURTOUT pas de crash.
        assert isinstance(findings, list)

    def test_division_by_zero_no_crash(self):
        src = """
from flask import request
db = client.db
def handler():
    if 1 / 0 > 0:
        bar = 'safe'
    else:
        bar = request.args.get('p')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert isinstance(findings, list)

    def test_subscript_out_of_range_no_crash(self):
        src = """
from flask import request
db = client.db
def handler():
    if "AB"[5] == 'X':
        bar = 'safe'
    else:
        bar = request.args.get('p')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert isinstance(findings, list)


class TestNoRegressionOnGuards:
    """Les guards Phase 7 ne doivent pas être perturbés par Phase 9."""

    def test_guard_sanitizer_still_cleans(self):
        # `if not re.match(...): abort()` doit toujours nettoyer (Phase 7).
        src = """
from flask import request
import re
db = client.db
def handler():
    username = request.args.get('user')
    if not re.match(r'^[a-z]+$', username):
        abort(400)
    return db.users.find_one({'username': username})
"""
        rule = dict(_RULE, sanitizers=[{"pattern": r"re\.match\s*\("}])
        findings = list(run_taint_rule(rule, src, language="python"))
        assert len(findings) == 0, (
            f"Guard sanitizer doit toujours nettoyer (got {len(findings)})"
        )
