"""Tests Phase 9.bis — indexation par clé des mutations dict/configparser.

Vérifie que :
  - Une écriture sur clé constante n'over-tainte pas les lectures à autre clé.
  - Une écriture sur clé dynamique (wildcard `obj[*]`) reste sur-prudente :
    les lectures à clé constante voient le wildcard.
  - Les patterns receveur-entier antérieurs (lecture `sink(obj)`) continuent
    de remonter le taint via l'agrégation VarRef.

Référence : sca/docs/dataflow-spec.md §5 (mutation propagation) + memory
project_owasp_f1.md "Patterns OWASP qui résistent".
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


class TestSubscriptAssignment:

    def test_const_key_write_other_const_key_read_clean(self):
        # Gain Phase 9.bis : écrire sur 'bad' ne doit pas polluer la lecture 'safe'.
        src = """
from flask import request
db = client.db
def handler():
    data = {}
    data['bad'] = request.args.get('p')
    data['safe'] = 'literal'
    return db.users.find_one(data['safe'])
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"Lecture clé constante 'safe' après écriture sur 'bad' "
            f"doit rester clean (got {len(findings)})"
        )

    def test_const_key_write_same_const_key_read_taint(self):
        # Vrai positif préservé : lecture de la même clé que celle écrite.
        src = """
from flask import request
db = client.db
def handler():
    data = {}
    data['bad'] = request.args.get('p')
    return db.users.find_one(data['bad'])
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"Lecture clé constante 'bad' après écriture sur 'bad' "
            f"doit être tainté (got {len(findings)})"
        )

    def test_dynamic_key_write_const_key_read_taint_via_wildcard(self):
        # Sur-prudence : clé dynamique → wildcard, lecture clé constante
        # voit le wildcard (on ne sait pas si k valait 'anything').
        src = """
from flask import request
db = client.db
def handler():
    data = {}
    k = some_input()
    data[k] = request.args.get('p')
    return db.users.find_one(data['anything'])
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"Lecture clé constante après écriture clé dynamique "
            f"doit voir le wildcard (got {len(findings)})"
        )


class TestConfigParserSwitchKeys:

    def test_configparser_different_option_clean(self):
        # Gain Phase 9.bis : configparser switch-keys. Écrire ('s','bad') ne
        # doit pas polluer la lecture ('s','safe').
        src = """
from flask import request
db = client.db
def handler():
    cp = ConfigParser()
    cp.set('section', 'bad', request.args.get('p'))
    bar = cp.get('section', 'safe')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"configparser.get('s','safe') après set('s','bad') "
            f"doit rester clean (got {len(findings)})"
        )

    def test_configparser_same_option_taint(self):
        # Vrai positif préservé.
        src = """
from flask import request
db = client.db
def handler():
    cp = ConfigParser()
    cp.set('section', 'bad', request.args.get('p'))
    bar = cp.get('section', 'bad')
    return db.users.find_one(bar)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"configparser.get('s','bad') après set('s','bad') "
            f"doit être tainté (got {len(findings)})"
        )


class TestDictUpdate:

    def test_update_with_literal_dict_const_keys(self):
        # `update({'bad': p, 'safe': c})` indexe chaque paire ; lecture 'safe'
        # reste clean.
        src = """
from flask import request
db = client.db
def handler():
    data = {}
    data.update({'bad': request.args.get('p'), 'safe': 'literal'})
    return db.users.find_one(data['safe'])
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"d.update({{'bad': p, 'safe': c}}) puis lecture 'safe' "
            f"doit rester clean (got {len(findings)})"
        )

    def test_update_with_unknown_object_taints_wildcard(self):
        # `update(other)` avec `other` variable inconnue tainté → wildcard.
        src = """
from flask import request
db = client.db
def handler():
    data = {}
    other = {'k': request.args.get('p')}
    data.update(other)
    return db.users.find_one(data['anything'])
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"d.update(other_tainted) puis lecture clé constante "
            f"doit voir wildcard (got {len(findings)})"
        )


class TestNoRegression:
    """Patterns existants qui doivent continuer à fonctionner."""

    def test_list_append_then_whole_list_to_sink(self):
        # Régression : `lst.append(p); sink(lst)` doit toujours flag via
        # l'agrégation VarRef (lst[*] tainté → lecture VarRef('lst') agrège).
        src = """
from flask import request
db = client.db
def handler():
    lst = []
    lst.append(request.args.get('p'))
    return db.users.find_one(lst)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"lst.append(p) puis sink(lst) doit flag (got {len(findings)})"
        )

    def test_configparser_dynamic_keys_then_whole_to_sink(self):
        # `cp.set(s, k, p)` avec clés dynamiques → wildcard ; `sink(cp)`
        # agrège et flag.
        src = """
from flask import request
db = client.db
def handler():
    cp = ConfigParser()
    s = pick_section()
    k = pick_key()
    cp.set(s, k, request.args.get('p'))
    return db.users.find_one(cp)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"cp.set(s,k,p) clés dynamiques puis sink(cp) doit flag "
            f"(got {len(findings)})"
        )

    def test_dict_const_key_to_format_via_whole(self):
        # Pattern xss : `d['k'] = p; sink(d)` — l'agrégation VarRef doit
        # remonter le taint du slot indexé.
        src = """
from flask import request
db = client.db
def handler():
    data = {}
    data['bad'] = request.args.get('p')
    return db.users.find_one(data)
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"d['bad']=p puis sink(d) doit flag via agrégation "
            f"(got {len(findings)})"
        )
