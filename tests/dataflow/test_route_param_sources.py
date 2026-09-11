"""Tests Volet 1 — paramètres de route web comme sources HTTP.

Les handlers décorés (`@app.get`, `@router.post`, `@bp.route`…) ont leurs
paramètres de chemin/requête annotés scalaires (`str`, `int`…) traités comme
des sources contrôlées par l'utilisateur (kind=http). Les dépendances
injectées (non annotées, `db`, `session`…) restent neutres.

Référence : `sca/dataflow/summary.py::route_source_params`,
`sca/executors/dataflow_taint.py` (seed initial_state).
"""
from __future__ import annotations

import ast

from sca.dataflow.summary import (
    collect_functions,
    is_route_handler,
    route_source_params,
)
from sca.executors.dataflow_taint import run_taint_rule

_SQLI_RULE = {
    "id": "taint_sqli",
    "mode": "taint",
    "severity": "HIGH",
    "sources": [{"pattern": r"request\.(GET|args|form|json)", "kind": "http"}],
    "sinks": [{"pattern": r"\.execute\s*\("}],
    "sanitizers": [],
}


def _fn(src):
    return collect_functions(ast.parse(src))[0]


class TestIsRouteHandler:
    def test_fastapi_router_post(self):
        fn = _fn('@router.post("/x")\ndef h(q: str): pass')
        assert is_route_handler(fn) is True

    def test_fastapi_app_get(self):
        fn = _fn('@app.get("/x")\nasync def h(q: str): pass')
        assert is_route_handler(fn) is True

    def test_flask_blueprint_route(self):
        fn = _fn('@bp.route("/x")\ndef h(q: str): pass')
        assert is_route_handler(fn) is True

    def test_plain_function_not_route(self):
        fn = _fn('def helper(x): pass')
        assert is_route_handler(fn) is False

    def test_unrelated_decorator_not_route(self):
        fn = _fn('@staticmethod\ndef h(x): pass')
        assert is_route_handler(fn) is False


class TestRouteSourceParams:
    def test_scalar_annotated_param_is_source(self):
        fn = _fn('@app.get("/x")\ndef h(query: str): pass')
        assert route_source_params(fn) == ("query",)

    def test_unannotated_param_excluded(self):
        # `db` non annoté = dépendance → pas une source.
        fn = _fn('@app.get("/x")\ndef h(query: str, db): pass')
        assert route_source_params(fn) == ("query",)

    def test_self_excluded(self):
        fn = _fn('@app.get("/x")\ndef h(self, query: int): pass')
        assert route_source_params(fn) == ("query",)

    def test_non_route_returns_empty(self):
        fn = _fn('def helper(query: str): pass')
        assert route_source_params(fn) == ()

    def test_multiple_scalar_params(self):
        fn = _fn('@router.post("/x")\ndef h(a: str, b: int, db): pass')
        assert route_source_params(fn) == ("a", "b")


class TestRouteParamFlowDetection:
    def test_route_param_to_sink_flags(self):
        src = '''
@router.post("/search")
async def search(query: str, db):
    db.execute("SELECT * FROM t WHERE x = '" + query + "'")
'''
        findings = list(run_taint_rule(_SQLI_RULE, src, language="python"))
        assert len(findings) >= 1
        assert findings[0].source_kind == "http"

    def test_unannotated_param_no_flag(self):
        # `query` non annoté → pas tainté → pas de finding.
        src = '''
@router.post("/search")
async def search(query, db):
    db.execute("SELECT * FROM t WHERE x = '" + query + "'")
'''
        findings = list(run_taint_rule(_SQLI_RULE, src, language="python"))
        assert len(findings) == 0

    def test_plain_function_param_no_flag(self):
        # Même corps mais fonction non décorée → param non tainté.
        src = '''
def search(query: str, db):
    db.execute("SELECT * FROM t WHERE x = '" + query + "'")
'''
        findings = list(run_taint_rule(_SQLI_RULE, src, language="python"))
        assert len(findings) == 0
