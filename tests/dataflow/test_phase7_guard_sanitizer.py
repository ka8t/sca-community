"""Tests Phase 7 — guard sanitizer (predicate-based sanitization).

Pattern reconnu : `if not <sanitizer>(x): abort/raise/return/break/exit`.
La variable x est considérée comme nettoyée APRÈS la garde.

Référence : sca/docs/dataflow-spec.md §10bis.
"""
from __future__ import annotations

from sca.executors.dataflow_taint import run_taint_rule


_BASE_RULE = {
    "id": "taint_nosql",
    "mode": "taint",
    "severity": "HIGH",
    "sources": [{"pattern": r"request\.(GET|POST|args|form)", "kind": "http"}],
    "sinks": [{"pattern": r"\.find_one\s*\("}],
    "sanitizers": [{"pattern": r"re\.match\s*\("}],
}


class TestGuardSanitizer:

    def test_guard_with_abort_kills_taint(self):
        src = """
from flask import request
db = client.db
def handler():
    username = request.args.get('user')
    if not re.match(r'^[a-z]+$', username):
        abort(400)
    return db.users.find_one({'username': username})
"""
        findings = list(run_taint_rule(_BASE_RULE, src, language="python"))
        assert len(findings) == 0, f"Guard avec abort doit nettoyer (got {len(findings)})"

    def test_guard_with_raise_kills_taint(self):
        src = """
from flask import request
db = client.db
def handler():
    username = request.args.get('user')
    if not re.match(r'^[a-z]+$', username):
        raise ValueError('invalid')
    return db.users.find_one({'username': username})
"""
        assert len(list(run_taint_rule(_BASE_RULE, src, language="python"))) == 0

    def test_guard_with_return_kills_taint(self):
        src = """
from flask import request
db = client.db
def handler():
    username = request.args.get('user')
    if not re.match(r'^[a-z]+$', username):
        return None
    return db.users.find_one({'username': username})
"""
        assert len(list(run_taint_rule(_BASE_RULE, src, language="python"))) == 0

    def test_guard_without_terminator_keeps_taint(self):
        """Un `if not san(x):` qui ne termine pas le flux ne doit PAS nettoyer."""
        src = """
from flask import request
db = client.db
def handler():
    username = request.args.get('user')
    if not re.match(r'^[a-z]+$', username):
        log_warning('invalid')  # PAS un terminator
    return db.users.find_one({'username': username})
"""
        findings = list(run_taint_rule(_BASE_RULE, src, language="python"))
        assert len(findings) >= 1, "Sans terminator, le taint doit subsister"

    def test_no_guard_keeps_taint(self):
        """Pas de garde du tout : taint atteint le sink (cas vulnérable)."""
        src = """
from flask import request
db = client.db
def handler():
    username = request.args.get('user')
    return db.users.find_one({'username': username})
"""
        assert len(list(run_taint_rule(_BASE_RULE, src, language="python"))) >= 1

    def test_combined_guards_or_kills_taint(self):
        """`if not isinstance(x, str) or not re.match(...): abort()` — cas fixture SCA."""
        src = """
from flask import request
db = client.db
def handler():
    username = request.args.get('user')
    if not isinstance(username, str) or not re.match(r'^[a-z]+$', username):
        abort(400)
    return db.users.find_one({'username': username})
"""
        assert len(list(run_taint_rule(_BASE_RULE, src, language="python"))) == 0

    def test_guard_with_sys_exit_kills_taint(self):
        src = """
from flask import request
db = client.db
def handler():
    username = request.args.get('user')
    if not re.match(r'^[a-z]+$', username):
        sys.exit(1)
    return db.users.find_one({'username': username})
"""
        assert len(list(run_taint_rule(_BASE_RULE, src, language="python"))) == 0

    def test_nested_if_inside_function_kills_taint(self):
        """Guard à l'intérieur d'une fonction (worklist passe par les sous-modules)."""
        src = """
from flask import request
db = client.db
def validate_and_query(username):
    if not re.match(r'^[a-z]+$', username):
        raise ValueError('invalid')
    return db.users.find_one({'username': username})

def main():
    u = request.args.get('user')
    validate_and_query(u)
"""
        # Le sink est dans `validate_and_query`, le guard l'y précède directement.
        assert len(list(run_taint_rule(_BASE_RULE, src, language="python"))) == 0


# Note : le cas `elif not <san>(x): abort()` n'est pas couvert ici. L'IR Python
# linéarise les elif en branches imbriquées, et la détection de garde n'inspecte
# que la ligne immédiatement suivante (`abort()`). En pratique, il suffit de
# transformer `elif` en `if` (refactor courant et lisible) ou d'ajouter un
# sanitizer explicite à la règle .sca pour ce cas — couvert par les FP
# documentés dans `audit.config.json` si nécessaire.
