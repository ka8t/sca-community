"""Tests Phase 7 — matching hybride regex sur ligne source.

Couvre :
  - Détection des sinks Subscript-Assign (e.g. `response.headers['Loc'] = url`)
  - Détection des sanitizers via patterns regex chaînés (e.g. `.replace().replace()`)
  - Cohabitation matching dotted + matching hybride (pas de doublons)
  - Conservation des invariants Phase 6
"""
from __future__ import annotations

import pytest

from sca.executors.dataflow_taint import (
    rule_json_to_specs,
    run_taint_rule,
)


# ============================================================================
# Sinks via Subscript-Assign (cas response.headers['Loc'] = url)
# ============================================================================

class TestSubscriptAssignSink:

    def test_header_injection_via_subscript_assign(self):
        """response.headers['Location'] = url — sink via assign à subscript."""
        rule = {
            "id": "header_inj",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.args", "kind": "http"}],
            "sinks": [{"pattern": r"\.headers\["}],
            "metadata": {"cwe": "CWE-113"},
        }
        src = """
url = request.args
response.headers['Location'] = url
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) >= 1


# ============================================================================
# Sanitizer via chaîne d'appels (.replace().replace())
# ============================================================================

class TestChainedSanitizer:

    def test_replace_kills_taint_when_declared_sanitizer(self):
        """`.replace('\\r', '')` est un sanitizer déclaré → taint tué."""
        rule = {
            "id": "header_inj_clean",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.args", "kind": "http"}],
            "sinks": [{"pattern": r"\.headers\["}],
            "sanitizers": [{"pattern": r"\.replace\s*\("}],
            "metadata": {"cwe": "CWE-113"},
        }
        src = """
url = request.args
safe = url.replace('\\r', '').replace('\\n', '')
response.headers['Location'] = safe
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) == 0


# ============================================================================
# Cohabitation matching dotted + hybride
# ============================================================================

class TestNoDoubleCountingDottedHybrid:

    def test_single_finding_when_both_match(self):
        """Si dotted ET regex matchent la même ligne, on n'a qu'un finding."""
        rule = {
            "id": "test",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"input\s*\(", "kind": "cli"}],
            "sinks": [{"pattern": r"sink\s*\(", "args": [0]}],
        }
        src = "x = input()\nsink(x)\n"
        findings = list(run_taint_rule(rule, src))
        # 1 seul finding sur sink(x)
        assert len(findings) == 1


# ============================================================================
# Régressions Phase 5/6 préservées
# ============================================================================

class TestPhase56Preserved:

    def test_flask_route_still_works(self):
        rule = {
            "id": "xss",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.args", "kind": "http"}],
            "sinks": [{"pattern": r"render_template_string"}],
            "metadata": {"cwe": "CWE-79"},
        }
        src = """
from flask import request
@app.route("/")
def view():
    name = request.args.get('name')
    return render_template_string(name)
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) >= 1

    def test_sanitized_no_finding(self):
        rule = {
            "id": "xss_san",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.args", "kind": "http"}],
            "sinks": [{"pattern": r"render_template_string"}],
            "sanitizers": [{"pattern": r"escape\s*\("}],
        }
        src = """
from flask import request
def view():
    name = request.args.get('name')
    return render_template_string(escape(name))
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) == 0


# ============================================================================
# Specs : raw_regex présent
# ============================================================================

class TestRawRegexCompiled:

    def test_specs_have_raw_regex(self):
        rule_json = {
            "id": "test",
            "mode": "taint",
            "sources": [{"pattern": r"request\.GET", "kind": "http"}],
            "sinks": [{"pattern": r"\.execute\s*\("}],
            "sanitizers": [{"pattern": r"\bescape\s*\("}],
        }
        specs = rule_json_to_specs(rule_json)
        # Chaque spec produit a un raw_regex compilé
        assert specs is not None
        for s in specs.sources:
            assert s.raw_regex is not None
        for s in specs.sinks:
            assert s.raw_regex is not None
        for s in specs.sanitizers:
            assert s.raw_regex is not None

    def test_invalid_regex_does_not_crash(self):
        """Une regex invalide ne casse pas la compilation des specs."""
        rule_json = {
            "id": "test",
            "mode": "taint",
            "sources": [{"pattern": "valid", "kind": "x"}],
            "sinks": [{"pattern": "*(invalid"}],  # regex incorrecte
        }
        # rule_json_to_specs ne doit pas crasher
        specs = rule_json_to_specs(rule_json)
        # Le sink avec regex invalide a quand même son dotted (ou est sauté)
        # Le test passe si on n'a pas d'exception
        assert True
