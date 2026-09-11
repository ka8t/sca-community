"""Tests Volet 2A — fiches résumé (function summaries) inter-procédurales.

`compute_summary` calcule, pour une fonction, comment le taint traverse ses
appels : retour tainté (inconditionnel via source interne, ou selon les
params), et params atteignant un sink.

Référence : `sca/dataflow/summary.py::compute_summary`.
"""
from __future__ import annotations

import ast

from sca.dataflow.summary import collect_functions, compute_summary
from sca.executors.dataflow_taint import rule_json_to_specs, run_taint_rule

_SQLI_RULE = {
    "id": "taint_sqli",
    "mode": "taint",
    "severity": "HIGH",
    "sources": [{"pattern": r"request\.(GET|args|form|json)", "kind": "http"}],
    "sinks": [{"pattern": r"\.execute\s*\("}],
    "sanitizers": [{"pattern": r"re\.fullmatch"}],
}

_SQLI = rule_json_to_specs({
    "id": "taint_sqli",
    "mode": "taint",
    "severity": "HIGH",
    "sources": [{"pattern": r"request\.(GET|args|form|json)", "kind": "http"}],
    "sinks": [{"pattern": r"\.execute\s*\("}],
    "sanitizers": [{"pattern": r"re\.fullmatch"}],
})


def _summary(src, name):
    fn = [f for f in collect_functions(ast.parse(src)) if f.name == name][0]
    return compute_summary(fn, _SQLI, language="python", source_lines=src.splitlines())


class TestReturnTaint:
    def test_internal_source_taints_return_unconditionally(self):
        s = _summary('def f(request):\n    return request.GET["q"]\n', "f")
        assert s.return_tainted_uncond is True
        assert s.return_kind == "http"

    def test_constant_return_not_tainted(self):
        s = _summary('def f(x):\n    return "constant"\n', "f")
        assert s.return_tainted_uncond is False
        assert 0 not in s.return_taint_params

    def test_param_flows_to_return(self):
        s = _summary('def echo(x, db):\n    y = x\n    return y\n', "echo")
        assert 0 in s.return_taint_params


class TestSinkParams:
    def test_param_reaching_sink_recorded(self):
        s = _summary(
            'def q(query, db):\n'
            '    db.execute("SELECT " + query)\n',
            "q",
        )
        assert 0 in s.sink_param_findings

    def test_sanitized_param_not_sink(self):
        # Le param est validé par un guard avant le sink → pas de sink-param.
        s = _summary(
            'def q(query, db):\n'
            '    if not re.fullmatch(r"[a-z]+", query):\n'
            '        return None\n'
            '    db.execute("SELECT " + query)\n',
            "q",
        )
        assert 0 not in s.sink_param_findings

    def test_clean_function_empty_summary(self):
        s = _summary('def helper(a, b):\n    return a + b\n', "helper")
        assert s.return_tainted_uncond is False
        assert s.sink_param_findings == {}


class TestInterProceduralApplication:
    """Volet 2B — propagation effective à travers les appels (run_taint_rule)."""

    def test_cross_function_source_to_sink(self):
        src = '''
def get_input(request):
    return request.GET["q"]

def run_query(query, db):
    db.execute("SELECT * FROM t WHERE x = '" + query + "'")

def handler(request, db):
    q = get_input(request)
    run_query(q, db)
'''
        findings = list(run_taint_rule(_SQLI_RULE, src, language="python"))
        assert len(findings) >= 1, "Flux source(A) → sink(B) attendu"
        # Au moins un finding porte un saut inter-procédural dans son flow.
        has_hop = any(
            any(step.kind == "propagation" and "→" in step.text for step in f.flow)
            for f in findings
        )
        assert has_hop, "Le flow doit contenir un saut inter-procédural (→)"

    def test_no_flow_when_arg_clean(self):
        # `run_query` appelé avec une constante → pas de flux.
        src = '''
def run_query(query, db):
    db.execute("SELECT * FROM t WHERE x = '" + query + "'")

def handler(db):
    run_query("constant", db)
'''
        findings = list(run_taint_rule(_SQLI_RULE, src, language="python"))
        assert len(findings) == 0

    def test_cli_source_does_not_propagate_interproc(self):
        # Anti-FP : une saisie CLI (input()) ne traverse pas un retour de
        # fonction (sinon FP sur les sinks faussement matchés des outils CLI).
        rule = {
            "id": "taint_cmd",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"input\s*\(", "kind": "stdin"}],
            "sinks": [{"pattern": r"\.execute\s*\("}],
            "sanitizers": [],
        }
        # NB : noms sans le substring "input(" pour ne pas matcher la regex source.
        src = '''
def fetch_cli():
    return input("cmd: ")

def run(query, db):
    db.execute("SELECT " + query)

def main(db):
    arg = fetch_cli()
    run(arg, db)
'''
        findings = list(run_taint_rule(rule, src, language="python"))
        assert len(findings) == 0, "Une source CLI ne doit pas propager inter-proc"

    def test_no_flow_when_helper_sanitizes(self):
        # Le helper valide son param avant le sink → pas de flux même tainté.
        src = '''
import re
def get_input(request):
    return request.GET["q"]

def run_query(query, db):
    if not re.fullmatch(r"[a-z]+", query):
        return None
    db.execute("SELECT * FROM t WHERE x = '" + query + "'")

def handler(request, db):
    run_query(get_input(request), db)
'''
        findings = list(run_taint_rule(_SQLI_RULE, src, language="python"))
        assert len(findings) == 0, "Helper assainissant ne doit pas propager"
