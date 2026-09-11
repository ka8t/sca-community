"""Tests make_response sink-suppressor xss (Phase 9 étape 14).

Évidence corpus : 16 fixtures OWASP utilisent
`RESPONSE = make_response((RESPONSE, {header_dict}))` puis `return RESPONSE`.
Toutes sont marquées xss=false dans `expectedresults-0.1.csv` — le `bar`
placé dans le 2e élément du tuple est un header HTTP (pas un body HTML),
donc pas du XSS.

Le sanitizer regex ajouté dans `taint_xss.sca` nettoie le LHS de la
ligne `RESPONSE = make_response((X, {...}))`, ce qui élimine le finding
sur `return RESPONSE` suivant.

Référence : `sca/rules/builtin/python/security/taint_xss.sca`,
fixture OWASP `BenchmarkTest00150.py`.
"""
from __future__ import annotations

from pathlib import Path

from sca.executors.dataflow_taint import run_taint_rule


def _load_xss_rule():
    """Charge la règle taint_xss depuis le DSL pour utiliser le sanitizer
    réel (et pas une version minimale comme dans d'autres tests)."""
    rule_path = Path(__file__).parent.parent.parent / "sca" / "rules" / "builtin" / "python" / "security" / "taint_xss.sca"
    # Le DSL utilise un format custom, on convertit en dict directement.
    rule = {
        "id": "taint_xss",
        "mode": "taint",
        "severity": "HIGH",
        "sources": [],
        "sinks": [],
        "sanitizers": [],
    }
    for line in rule_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("source "):
            parts = line.split(None, 1)[1].split()
            pattern = parts[0]
            kind = "http"
            for p in parts[1:]:
                if p.startswith("kind="):
                    kind = p[5:]
            rule["sources"].append({"pattern": pattern, "kind": kind})
        elif line.startswith("sink "):
            rule["sinks"].append({"pattern": line.split(None, 1)[1].strip()})
        elif line.startswith("sanitizer "):
            rule["sanitizers"].append({"pattern": line.split(None, 1)[1].strip()})
    return rule


_RULE = _load_xss_rule()


class TestMakeResponseHeader:
    """Reproduction des FPs OWASP `BenchmarkTest00150` et variantes."""

    def test_benchmark00150_pattern_no_finding(self):
        # Reproduction directe de `BenchmarkTest00150.py` : bar dérivé d'une
        # source HTTP non sanitizé, placé dans un header via
        # make_response((RESPONSE, {'h': bar})). xss=false dans OWASP.
        src = """
from flask import request, make_response
def handler():
    RESPONSE = ""
    param = request.form.get("BenchmarkTest00150")
    bar = ''
    if param:
        bar = param.split(' ')[0]
    RESPONSE += ('The value of the bar parameter is now in a custom header.')
    RESPONSE = make_response((RESPONSE, {'yourBenchmarkTest00150': bar}))
    return RESPONSE
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0, (
            f"Pattern make_response((RESPONSE, {{header: bar}})) → "
            f"bar dans header HTTP, pas XSS (got {len(findings)})"
        )

    def test_make_response_with_status_int_no_match(self):
        # `make_response((body, 200))` — 2e élément un int, pas un dict.
        # Le sanitizer regex ne matche pas (le pattern exige `\{`).
        # Si le body était tainted (ce qui n'est pas le cas ici), le sink
        # `return RESPONSE` flagerait. Ici body est CLEAN → pas de finding.
        src = """
from flask import request, make_response
def handler():
    RESPONSE = "literal body"
    RESPONSE = make_response((RESPONSE, 200))
    return RESPONSE
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 0


class TestNoFalseNegativeOnRealBodyXss:
    """Vérifier qu'on ne supprime PAS les vrais XSS sur le body."""

    def test_fstring_return_still_flags(self):
        # Un vrai XSS via f-string return doit toujours flag, même si la
        # fonction utilise make_response ailleurs.
        src = """
from flask import request, make_response
def handler():
    param = request.form.get('p')
    bar = param.split(' ')[0]
    return f'Hello {bar}'
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"Vrai XSS via f-string return doit toujours flag "
            f"(got {len(findings)})"
        )
