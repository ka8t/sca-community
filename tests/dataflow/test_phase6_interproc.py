"""Tests Phase 6 — inter-procédural intra-fichier.

Couvre :
  - collect_functions (FunctionDef, méthodes, fonctions imbriquées)
  - Analyse récursive des FunctionDef via run_taint_rule
  - Propagation du taint via le receveur (.method() où le receveur est tainted)
  - Récursion AttrRef.base (source détectée en sous-arbre)
"""
from __future__ import annotations

import ast
from typing import List

import pytest

from sca.dataflow.summary import (
    FunctionInfo,
    collect_functions,
    function_to_sub_module,
)
from sca.executors.dataflow_taint import run_taint_rule


# ============================================================================
# collect_functions
# ============================================================================

class TestCollectFunctions:

    def test_empty_module(self):
        fns = collect_functions(ast.parse(""))
        assert fns == []

    def test_top_level_function(self):
        fns = collect_functions(ast.parse("def f(x): return x"))
        assert len(fns) == 1
        assert fns[0].name == "f"
        assert fns[0].param_names == ("x",)
        assert fns[0].is_method is False

    def test_multiple_functions(self):
        src = """
def a(x): pass
def b(y, z): pass
def c(): pass
"""
        fns = collect_functions(ast.parse(src))
        assert {f.name for f in fns} == {"a", "b", "c"}

    def test_async_function(self):
        src = "async def coro(x): pass"
        fns = collect_functions(ast.parse(src))
        assert fns[0].name == "coro"

    def test_class_methods_dotted_name(self):
        src = """
class Foo:
    def method(self, x):
        return x
    def other(self):
        pass
"""
        fns = collect_functions(ast.parse(src))
        names = {f.name for f in fns}
        assert "Foo.method" in names
        assert "Foo.other" in names
        # Toutes méthodes
        for f in fns:
            assert f.is_method is True

    def test_nested_function(self):
        src = """
def outer():
    def inner():
        pass
"""
        fns = collect_functions(ast.parse(src))
        names = {f.name for f in fns}
        assert "outer" in names
        assert "outer.inner" in names


# ============================================================================
# function_to_sub_module
# ============================================================================

class TestFunctionToSubModule:

    def test_function_body_becomes_module(self):
        src = "def f():\n    x = 1\n    return x"
        tree = ast.parse(src)
        fn = collect_functions(tree)[0]
        sub = function_to_sub_module(fn)
        assert isinstance(sub, ast.Module)
        assert len(sub.body) == 2  # x = 1 + return x


# ============================================================================
# Run taint rule on fixtures with functions
# ============================================================================

def _flask_xss_rule():
    return {
        "id": "test_flask_xss",
        "mode": "taint",
        "severity": "HIGH",
        "sources": [
            {"pattern": r"request\.args", "kind": "http"},
            {"pattern": r"request\.GET", "kind": "http"},
        ],
        "sinks": [
            {"pattern": r"render_template_string"},
        ],
        "sanitizers": [
            {"pattern": r"escape"},
        ],
        "metadata": {"cwe": "CWE-79"},
    }


class TestFlaskRoutes:
    """Le cas typique : code vulnérable dans une route Flask."""

    def test_simple_flask_route_detected(self):
        src = """
from flask import request
@app.route("/")
def index():
    name = request.args.get("name")
    return render_template_string(name)
"""
        findings = list(run_taint_rule(_flask_xss_rule(), src))
        assert len(findings) >= 1
        # Le finding doit pointer la ligne du sink (render_template_string)
        f = findings[0]
        assert "render_template_string" in f.sink_text

    def test_flask_route_sanitized(self):
        src = """
from flask import request
@app.route("/")
def index():
    name = request.args.get("name")
    safe = escape(name)
    return render_template_string(safe)
"""
        findings = list(run_taint_rule(_flask_xss_rule(), src))
        assert len(findings) == 0

    def test_two_functions_only_one_vulnerable(self):
        src = """
def safe_func():
    return render_template_string('hardcoded')

def vulnerable_func():
    name = request.args.get("name")
    return render_template_string(name)
"""
        findings = list(run_taint_rule(_flask_xss_rule(), src))
        # Au moins 1 finding (pour vulnerable_func)
        assert len(findings) >= 1

    def test_class_method_detected(self):
        src = """
class View:
    def get(self):
        name = request.args.get("q")
        return render_template_string(name)
"""
        findings = list(run_taint_rule(_flask_xss_rule(), src))
        assert len(findings) >= 1


# ============================================================================
# Source via receveur tainted (request.args.get(...))
# ============================================================================

class TestReceiverTaint:

    def test_attribute_chain_source_propagates(self):
        """`request.args.get("q")` : `request.args` est source, .get(...) hérite."""
        rule = _flask_xss_rule()
        src = """
val = request.args.get("q")
render_template_string(val)
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) == 1

    def test_deep_attribute_chain(self):
        """`request.args.cookies.get(...)` : taint propage à travers la chaîne."""
        rule = {
            "id": "deep",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"request\.args", "kind": "http"}],
            "sinks": [{"pattern": r"\.execute"}],
        }
        src = """
data = request.args.cookies.get("session")
db.execute(data)
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) >= 1


# ============================================================================
# Dédup entre module-level et sous-analyses
# ============================================================================

class TestDedup:

    def test_no_double_finding_for_function(self):
        """Une fonction analysée ne doit pas produire de doublon."""
        src = """
def f():
    name = request.args
    render_template_string(name)
"""
        findings = list(run_taint_rule(_flask_xss_rule(), src))
        # Au plus 1 finding par sink+source
        unique_keys = {(f.line, f.source_line) for f in findings}
        assert len(findings) == len(unique_keys)


# ============================================================================
# Robustesse Phase 6
# ============================================================================

class TestRobustness:

    def test_empty_function_body(self):
        src = "def f(): pass"
        findings = list(run_taint_rule(_flask_xss_rule(), src))
        assert findings == []

    def test_nested_functions_both_analyzed(self):
        src = """
def outer():
    def inner():
        return render_template_string(request.args)
    return inner
"""
        # outer + inner sont les deux analysées. Le sink est dans inner.
        findings = list(run_taint_rule(_flask_xss_rule(), src))
        assert len(findings) >= 1

    def test_decorators_dont_break_analysis(self):
        src = """
@app.route("/")
@require_auth
@cached
def view():
    return render_template_string(request.args)
"""
        findings = list(run_taint_rule(_flask_xss_rule(), src))
        assert len(findings) >= 1
