"""Test deserialization — sources `request.headers` (étape 18).

Évidence corpus : 4 FNs deserialization (`BenchmarkTest00507`, `00510`,
`00605`, `00657`) utilisent tous une variante de `request.headers`
(get/getlist/get_all/keys) comme source. La règle
`taint_deserialization.sca` ligne 6 n'incluait pas `headers|cookies`
dans le groupe alternation source — même bug que xxe étape 15 et ldapi
étape 17. Les 9 TN deserialization utilisant `request.headers` sont
déjà nettoyés par d'autres mécanismes (Phase 9 const folding, Phase
9.bis indexed dict, Phase 9.quater list-shuffle, sanitizers existants).

Fix : ajout de `headers|cookies` au pattern source + dédoublonnage
de la ligne 7 redondante.

Référence : `sca/rules/builtin/python/security/taint_deserialization.sca`,
fixtures OWASP `BenchmarkTest00510.py` / `00605.py`.
"""
from __future__ import annotations

from pathlib import Path

from sca.executors.dataflow_taint import run_taint_rule


def _load_deser_rule():
    """Charge la règle taint_deserialization depuis le DSL réel."""
    rule_path = Path(__file__).parent.parent.parent / "sca" / "rules" / "builtin" / "python" / "security" / "taint_deserialization.sca"
    rule = {
        "id": "taint_deserialization",
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


_RULE = _load_deser_rule()


class TestHeadersSource:
    """Reproductions des FNs OWASP via `request.headers`."""

    def test_benchmark00510_pattern_detected(self):
        # Reproduction de `BenchmarkTest00510.py` :
        # param = request.headers.get
        # num = 106; bar = "..." if 7*42 - num > 200 else param
        # → cond False (294-106=188<200) → bar = param tainté
        # → pickle.loads(b64decode(bar)) sink
        src = """
from flask import request
import pickle
import base64
def handler():
    param = request.headers.get("BenchmarkTest00510")
    if not param:
        param = ""
    num = 106
    bar = "This should never happen" if 7 * 42 - num > 200 else param
    unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
    return unpickled
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"request.headers.get + IfExp const-folded → bar tainté + "
            f"pickle.loads sink doit flag deserialization "
            f"(got {len(findings)})"
        )

    def test_benchmark00605_escape_for_html_not_sanitizer_for_pickle(self):
        # Reproduction de `BenchmarkTest00605.py` :
        # param = request.headers.getlist
        # bar = helpers.utils.escape_for_html(param)
        # → escape_for_html n'est PAS un sanitizer pour pickle (rendu HTML
        # ne neutralise pas un payload pickle) — bar reste tainté.
        src = """
from flask import request
import pickle
import base64
import helpers.utils
def handler():
    param = ""
    headers = request.headers.getlist("BenchmarkTest00605")
    if headers:
        param = headers[0]
    bar = helpers.utils.escape_for_html(param)
    unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
    return unpickled
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"request.headers.getlist + escape_for_html (non-sanitizer pour "
            f"pickle) + pickle.loads doit flag (got {len(findings)})"
        )


class TestNoRegressionExistingSources:
    """Les sources existantes (request.args) doivent toujours fonctionner."""

    def test_request_args_still_source(self):
        src = """
from flask import request
import pickle
import base64
def handler():
    bar = request.args.get("p")
    unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
    return unpickled
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1
