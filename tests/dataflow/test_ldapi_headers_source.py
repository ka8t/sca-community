"""Test ldapi — sources `request.headers` (étape 17).

Évidence corpus : 4 FNs ldapi (`BenchmarkTest00505`, `00506`, `00604`,
`01200`) utilisent tous `request.headers.get/getlist` comme source.
La règle `taint_ldap.sca` ligne 6 n'incluait pas `headers|cookies` dans
le groupe alternation source. Aucun TN ldapi n'utilise `request.headers`,
risque de FP nul (vérifié corpus).

Fix : ajout de `headers|cookies` au pattern source.

Référence : `sca/rules/builtin/python/security/taint_ldap.sca`,
fixtures OWASP `BenchmarkTest00505.py` / `00604.py`.
"""
from __future__ import annotations

from pathlib import Path

from sca.executors.dataflow_taint import run_taint_rule


def _load_ldap_rule():
    """Charge la règle taint_ldap depuis le DSL réel."""
    rule_path = Path(__file__).parent.parent.parent / "sca" / "rules" / "builtin" / "python" / "security" / "taint_ldap.sca"
    rule = {
        "id": "taint_ldap",
        "mode": "taint",
        "severity": "HIGH",
        "sources": [],
        "sinks": [],
        "sanitizers": [],
    }
    for line in rule_path.read_text().splitlines():
        s = line.strip()
        if s.startswith("source "):
            parts = s.split(None, 1)[1].split()
            pattern = parts[0]
            kind = "http"
            for p in parts[1:]:
                if p.startswith("kind="):
                    kind = p[5:]
            rule["sources"].append({"pattern": pattern, "kind": kind})
        elif s.startswith("sink "):
            rule["sinks"].append({"pattern": s.split(None, 1)[1].strip()})
        elif s.startswith("sanitizer "):
            rule["sanitizers"].append({"pattern": s.split(None, 1)[1].strip()})
    return rule


_RULE = _load_ldap_rule()


class TestHeadersSource:
    """Reproductions des FNs OWASP via `request.headers`."""

    def test_benchmark00505_pattern_detected(self):
        # Reproduction de `BenchmarkTest00505.py` : param via
        # request.headers.get, list-shuffle pop(0)+lst[0] → bar = param
        # tainté, f-string filter, conn.search sink.
        src = """
from flask import request
def handler():
    param = request.headers.get("BenchmarkTest00505")
    if not param:
        param = ""
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.append('moresafe')
    lst.pop(0)
    bar = lst[0]
    filter_ = f'(&(objectclass=person)(uid={bar}))'
    conn.search('ou=users,ou=system', filter_, attributes=None)
    return None
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"request.headers.get + list-shuffle pop(0)+lst[0] = bar tainté + "
            f"f-string filter + conn.search doit flag ldapi "
            f"(got {len(findings)})"
        )

    def test_benchmark00604_pattern_detected(self):
        # Reproduction de `BenchmarkTest00604.py` : param via headers.getlist,
        # puis match guess avec guess='A' constant → bar = param tainté.
        src = """
from flask import request
def handler():
    param = ""
    headers = request.headers.getlist("BenchmarkTest00604")
    if headers:
        param = headers[0]
    possible = "ABC"
    guess = possible[0]
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = 'safe'
    filter_ = f'(&(objectclass=person)(uid={bar}))'
    conn.search('ou=users,ou=system', filter_, attributes=None)
    return None
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"request.headers.getlist + match guess const-folded → bar tainté + "
            f"conn.search doit flag ldapi (got {len(findings)})"
        )


class TestNoRegressionExistingSources:
    """Les sources `request.args` etc. doivent toujours fonctionner."""

    def test_request_args_still_source(self):
        src = """
from flask import request
def handler():
    bar = request.args.get("p")
    filter_ = f'(&(objectclass=person)(uid={bar}))'
    conn.search('ou=users,ou=system', filter_, attributes=None)
    return None
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1
