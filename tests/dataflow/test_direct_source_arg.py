"""Tests Volet 4 — source écrite directement en argument d'appel.

Avant : seule une source assignée à une variable (`q = request.GET[...]`) puis
passée à un sink était détectée. Désormais une source inline
(`cursor.execute(request.GET["q"])`) l'est aussi, sans tainter les arguments
voisins ni les requêtes paramétrées.

Références : `_aux_match_line` (source inline sur la ligne du sink) et
`_arg_regex_source` (argument source vers une fonction à fiche résumé), dans
`sca/dataflow/transfer.py`.
"""
from __future__ import annotations

from sca.executors.dataflow_taint import run_taint_rule

_RULE = {
    "id": "taint_sqli",
    "mode": "taint",
    "severity": "HIGH",
    "sources": [{"pattern": r"request\.(GET|args|form|json)", "kind": "http"}],
    "sinks": [{"pattern": r"\.execute\s*\((?![^)]*,)"}],
    "sanitizers": [{"pattern": r"re\.fullmatch"}],
}


def _n(src):
    return len(list(run_taint_rule(_RULE, src, language="python")))


class TestDirectSinkArg:
    def test_source_inline_in_sink_detected(self):
        assert _n('def h(request, db):\n    db.execute(request.GET["q"])\n') >= 1

    def test_assigned_form_still_works(self):
        # Non-régression : la forme historique (variable intermédiaire).
        assert _n(
            'def h(request, db):\n'
            '    q = request.GET["q"]\n'
            '    db.execute(q)\n'
        ) >= 1

    def test_constant_arg_not_flagged(self):
        assert _n('def h(request, db):\n    db.execute("static")\n') == 0

    def test_parameterized_query_safe(self):
        # Argument paramétré (virgule) → sink lookahead ne matche pas → clean.
        assert _n(
            'def h(request, db):\n'
            '    db.execute("SELECT %s", (request.GET["q"],))\n'
        ) == 0

    def test_inline_sanitizer_suppresses(self):
        # Sanitizer sur la même ligne → pas de finding (anti-FP).
        assert _n(
            'import re\n'
            'def h(request, db):\n'
            '    db.execute(re.fullmatch(r"x", request.GET["q"]))\n'
        ) == 0

    def test_source_literal_in_return_string_not_flagged(self):
        # Anti-FP (OWASP BenchmarkTest00905/00926) : un littéral ressemblant à
        # une source dans une chaîne retournée ne doit pas ouvrir la détection
        # de sink. Le `break` du Volet 4 est restreint aux statements Call.
        rule = {
            "id": "taint_xss",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.args", "kind": "http"}],
            "sinks": [{"pattern": r"return f"}],
            "sanitizers": [],
        }
        src = (
            'def h(request):\n'
            '    args = request.args.get("q")\n'
            '    return f"le parametre request.args est absent"\n'
        )
        assert len(list(run_taint_rule(rule, src, language="python"))) == 0


class TestDirectArgToSummarizedCallee:
    """Source inline passée à une fonction utilisateur à fiche résumé
    (exerce `_arg_regex_source` dans `eval_call`)."""

    def test_source_arg_to_helper_with_sink(self):
        # get/run_query définis dans le même fichier ; la source inline passée
        # à run_query (dont le param atteint un sink) doit déclencher un flux.
        src = (
            'def run_query(query, db):\n'
            '    db.execute("SELECT " + query)\n'
            'def handler(request, db):\n'
            '    run_query(request.GET["q"], db)\n'
        )
        assert _n(src) >= 1

    def test_arg_regex_source_is_per_argument(self):
        # _arg_regex_source teste le texte de CHAQUE argument, pas la ligne :
        # la source matche, le voisin `db` ne matche pas (pas de FP voisin).
        from sca.dataflow.ir import AttrRef, Const, SubscriptRef, VarRef
        from sca.dataflow.transfer import _arg_regex_source
        from sca.executors.dataflow_taint import rule_json_to_specs

        specs = rule_json_to_specs(_RULE)
        src_arg = SubscriptRef(AttrRef(VarRef("request"), "GET"), Const("q"))
        clean_arg = VarRef("db")
        assert _arg_regex_source(src_arg, specs, 1) is not None
        assert _arg_regex_source(clean_arg, specs, 1) is None
