"""Test xxe — sources `request.headers` / `request.cookies` (étape 15).

Évidence corpus : 3 FNs xxe (BenchmarkTest00460, 00462, 00541) utilisent
`request.headers.get` ou `request.headers.getlist` comme source. La règle
`taint_xxe.sca` ne reconnaissait pas ce pattern alors qu'il est bien
sourcé dans `taint_xss.sca`. Fix : ajout de `headers` et `cookies` au
groupe alternation de la source `request.(...)`.

Référence : `sca/rules/builtin/python/security/taint_xxe.sca` ligne 9,
fixtures OWASP `BenchmarkTest00460.py` / `00462.py` / `00541.py`.
"""
from __future__ import annotations

from pathlib import Path

from sca.executors.dataflow_taint import run_taint_rule


def _load_xxe_rule():
    """Charge la règle taint_xxe depuis le DSL réel (avec sources/sinks/
    sanitizers + requires complets)."""
    rule_path = Path(__file__).parent.parent.parent / "sca" / "rules" / "builtin" / "python" / "security" / "taint_xxe.sca"
    rule = {
        "id": "taint_xxe",
        "mode": "taint",
        "severity": "HIGH",
        "sources": [],
        "sinks": [],
        "sanitizers": [],
    }
    requires_block = False
    for line in rule_path.read_text().splitlines():
        s = line.strip()
        if s == "requires":
            requires_block = True
            continue
        if requires_block:
            if s == "end":
                requires_block = False
            elif s.startswith("has"):
                rule.setdefault("file_contains", {}).setdefault("has", []).append(
                    s.split(None, 1)[1].strip()
                )
            continue
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


_RULE = _load_xxe_rule()


class TestHeadersSource:
    """Reproduction des FNs OWASP via `request.headers`."""

    def test_benchmark00460_pattern_detected(self):
        # Reproduction directe de `BenchmarkTest00460.py` : bar = param
        # où param vient de request.headers.get, parser.setFeature(...True),
        # minidom.parseString(bar, parser). xxe=true dans OWASP.
        src = """
from flask import request
import xml.dom.minidom
import xml.sax
import xml.sax.handler
def handler():
    param = request.headers.get("BenchmarkTest00460")
    if not param:
        param = ""
    bar = param
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    doc = xml.dom.minidom.parseString(bar, parser)
    return doc
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"request.headers + setFeature(external_ges, True) + parseString "
            f"doit flag xxe (got {len(findings)})"
        )

    def test_benchmark00541_pattern_detected(self):
        # Reproduction de `BenchmarkTest00541.py` : param via
        # request.headers.getlist, puis bar via call utility.
        src = """
from flask import request
import xml.dom.minidom
import xml.sax
import xml.sax.handler
import helpers.ThingFactory
def handler():
    param = ""
    headers = request.headers.getlist("BenchmarkTest00541")
    if headers:
        param = headers[0]
    thing = helpers.ThingFactory.create()
    bar = thing.doSomething(param)
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    doc = xml.dom.minidom.parseString(bar, parser)
    return doc
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1, (
            f"request.headers.getlist + UNKNOWN call propage taint + "
            f"setFeature(True) doit flag (got {len(findings)})"
        )


class TestNoRegressionExistingSources:
    """Les sources `request.args` et autres existantes doivent toujours
    fonctionner."""

    def test_request_args_still_source(self):
        src = """
from flask import request
import xml.dom.minidom
import xml.sax
import xml.sax.handler
def handler():
    bar = request.args.get("p")
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    doc = xml.dom.minidom.parseString(bar, parser)
    return doc
"""
        findings = list(run_taint_rule(_RULE, src, language="python"))
        assert len(findings) == 1
