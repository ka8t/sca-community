"""Tests du moteur taint end-to-end — Phase 3 du moteur dataflow SCA.

Couvre :
  - Transfer functions par construct IR (spec §5)
  - Sources / sinks / sanitizers / passthroughs (spec §7)
  - Worklist + propagation (spec §6)
  - Cas d'usage typiques : SQL injection, XSS, command injection, etc.
  - Cas edge : if/else, while, try/except, nested calls
"""
from __future__ import annotations

import pytest

from sca.dataflow import (
    Finding,
    PassthroughSpec,
    RuleSpecs,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
    analyze_module_source,
    compile_glob_pattern,
    match_pattern,
    resolve_spec,
    SpecKind,
)
from sca.dataflow.transfer import (
    eval_call,
    eval_rhs,
)
from sca.dataflow.ir import (
    AttrRef,
    CallRef,
    Const,
    VarRef,
)
from sca.dataflow.lattice import (
    CLEAN,
    SourceInfo,
    Tainted,
    empty_state,
    is_clean,
    is_tainted,
    state_set,
)


# ============================================================================
# Helpers
# ============================================================================

def _basic_specs(**overrides) -> RuleSpecs:
    """Specs minimales pour un SQL injection."""
    return RuleSpecs(
        rule_id=overrides.get("rule_id", "test_rule"),
        severity=overrides.get("severity", "HIGH"),
        cwe=overrides.get("cwe", "CWE-89"),
        message=overrides.get("message", ""),
        sources=overrides.get("sources", (SourceSpec(pattern="input", kind="cli"),)),
        sinks=overrides.get("sinks", (SinkSpec(pattern="execute_query", args=(0,)),)),
        sanitizers=overrides.get("sanitizers", ()),
        passthroughs=overrides.get("passthroughs", ()),
    )


# ============================================================================
# Pattern matching (spec §7.1)
# ============================================================================

class TestPatternMatching:
    """match_pattern attend désormais une regex pré-compilée via
    `compile_glob_pattern` (optimisation cProfile : 10M+ appels par audit).
    """

    @staticmethod
    def _m(name: str, pattern: str) -> bool:
        return match_pattern(name, compile_glob_pattern(pattern))

    def test_exact_match(self):
        assert self._m("subprocess.run", "subprocess.run")

    def test_glob_single_star(self):
        assert self._m("subprocess.run", "subprocess.*")
        # * ne matche pas les dots
        assert not self._m("subprocess.path.join", "subprocess.*")

    def test_glob_method_wildcard(self):
        assert self._m("cursor.execute", "*.execute")
        assert self._m("conn.execute", "*.execute")

    def test_glob_deep_wildcard(self):
        assert self._m("a.b.c.execute", "**.execute")

    def test_no_match(self):
        assert not self._m("foo.bar", "baz.bar")


# ============================================================================
# Resolution de spec (priorité)
# ============================================================================

class TestSpecResolution:

    def test_source_first(self):
        specs = RuleSpecs(
            sources=(SourceSpec(pattern="x"),),
            sinks=(SinkSpec(pattern="x"),),
        )
        kind, _ = resolve_spec("x", specs)
        assert kind == SpecKind.SOURCE

    def test_unknown_default(self):
        kind, _ = resolve_spec("unknown_callee", _basic_specs())
        assert kind == SpecKind.UNKNOWN


# ============================================================================
# Sources
# ============================================================================

class TestSources:

    def test_source_taints_return(self):
        specs = _basic_specs()
        src = """
data = input()
execute_query(data)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1
        f = r.findings[0]
        assert f.rule_id == "test_rule"
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-89"
        assert f.source_line == 2
        assert f.line == 3

    def test_clean_data_no_finding(self):
        specs = _basic_specs()
        src = """
data = 'fixed_query'
execute_query(data)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 0


# ============================================================================
# Sinks
# ============================================================================

class TestSinks:

    def test_sink_with_args_filter(self):
        specs = _basic_specs(
            sinks=(SinkSpec(pattern="execute_query", args=(1,)),),
        )
        src = """
data = input()
execute_query(data, 'safe')
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 0

    def test_sink_kinds_filter(self):
        specs = _basic_specs(
            sinks=(SinkSpec(pattern="execute_query", args=(0,), kinds=("http",)),),
        )
        src = """
data = input()
execute_query(data)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 0

    def test_sink_kinds_match_one(self):
        specs = _basic_specs(
            sinks=(SinkSpec(pattern="execute_query", args=(0,), kinds=("http", "cli")),),
        )
        src = """
data = input()
execute_query(data)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1


# ============================================================================
# Sanitizers
# ============================================================================

class TestSanitizers:

    def test_sanitizer_kills_taint(self):
        specs = _basic_specs(
            sanitizers=(SanitizerSpec(pattern="sanitize"),),
        )
        src = """
data = input()
clean = sanitize(data)
execute_query(clean)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 0

    def test_sanitizer_does_not_kill_original_var(self):
        specs = _basic_specs(
            sanitizers=(SanitizerSpec(pattern="sanitize"),),
        )
        src = """
data = input()
clean = sanitize(data)
execute_query(data)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1


# ============================================================================
# Passthroughs
# ============================================================================

class TestPassthroughs:

    def test_passthrough_propagates(self):
        specs = _basic_specs(
            passthroughs=(PassthroughSpec(pattern="upper", args_in=(0,)),),
        )
        src = """
data = input()
shouty = upper(data)
execute_query(shouty)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1

    def test_unknown_call_propagates_conservatively(self):
        specs = _basic_specs()
        src = """
data = input()
copy = unknown_func(data)
execute_query(copy)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1


# ============================================================================
# Propagation à travers les opérations
# ============================================================================

class TestPropagation:

    def test_binop_propagates(self):
        specs = _basic_specs()
        src = """
data = input()
query = 'SELECT * FROM t WHERE x = ' + data
execute_query(query)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1

    def test_fstring_propagates(self):
        specs = _basic_specs()
        src = """
data = input()
query = f'SELECT {data}'
execute_query(query)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1

    def test_tuple_propagates(self):
        specs = _basic_specs()
        src = """
data = input()
pair = (data, 'safe')
execute_query(pair)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1

    def test_attribute_propagates(self):
        specs = _basic_specs()
        src = """
data = input()
container = SomeClass()
container.payload = data
execute_query(container.payload)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) >= 1


# ============================================================================
# Contrôle de flot
# ============================================================================

class TestControlFlow:

    def test_if_else_taint_in_one_branch(self):
        specs = _basic_specs()
        src = """
if cond:
    x = input()
else:
    x = 'safe'
execute_query(x)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1

    def test_if_else_both_clean(self):
        specs = _basic_specs()
        src = """
if cond:
    x = 'a'
else:
    x = 'b'
execute_query(x)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 0

    def test_while_loop_with_taint(self):
        specs = _basic_specs()
        src = """
data = input()
while cond:
    execute_query(data)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) >= 1

    def test_while_assigns_inside(self):
        specs = _basic_specs()
        src = """
x = 'safe'
while cond:
    x = input()
execute_query(x)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1

    def test_try_except_taint(self):
        specs = _basic_specs()
        src = """
try:
    x = input()
    execute_query(x)
except Exception:
    pass
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) >= 1


# ============================================================================
# Cas réalistes
# ============================================================================

class TestRealisticCases:

    def test_sql_injection_basic(self):
        specs = RuleSpecs(
            rule_id="sql_injection",
            severity="HIGH",
            cwe="CWE-89",
            message="SQL injection",
            sources=(
                SourceSpec(pattern="request.GET", kind="http"),
                SourceSpec(pattern="request.POST", kind="http"),
            ),
            sinks=(
                SinkSpec(pattern="cursor.execute", args=(0,), kinds=("http",)),
                SinkSpec(pattern="db.query", args=(0,), kinds=("http",)),
            ),
        )
        src = """
user_input = request.GET
cursor.execute(user_input)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1

    def test_command_injection_with_sanitizer(self):
        specs = RuleSpecs(
            rule_id="cmd_inj",
            severity="HIGH",
            cwe="CWE-78",
            sources=(SourceSpec(pattern="input", kind="cli"),),
            sinks=(SinkSpec(pattern="subprocess.run", args=(0,)),),
            sanitizers=(SanitizerSpec(pattern="shlex.quote"),),
        )
        src = """
cmd = input()
safe = shlex.quote(cmd)
subprocess.run(safe)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 0

    def test_path_traversal(self):
        specs = RuleSpecs(
            rule_id="path_trav",
            severity="HIGH",
            cwe="CWE-22",
            sources=(SourceSpec(pattern="request.args.get", kind="http"),),
            sinks=(SinkSpec(pattern="open", args=(0,)),),
        )
        src = """
filename = request.args.get('f')
data = open(filename)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1


# ============================================================================
# Findings : structure (contrat §3.2)
# ============================================================================

class TestFindingStructure:

    def test_finding_fields(self):
        specs = _basic_specs(message="Test message")
        src = """
data = input()
execute_query(data)
"""
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 1
        f = r.findings[0]
        assert f.rule_id == "test_rule"
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-89"
        assert f.message == "Test message"
        assert f.line == 3
        assert f.source_line == 2
        assert f.sink_text == "execute_query"

    def test_finding_has_flow_trace(self):
        specs = _basic_specs()
        src = """
data = input()
execute_query(data)
"""
        r = analyze_module_source(src, specs)
        f = r.findings[0]
        assert len(f.flow) >= 2
        kinds = [step.kind for step in f.flow]
        assert "source" in kinds
        assert "sink" in kinds


# ============================================================================
# Edge cases
# ============================================================================

class TestEdgeCases:

    def test_no_source_no_finding(self):
        specs = RuleSpecs(
            rule_id="t",
            sinks=(SinkSpec(pattern="execute_query"),),
        )
        src = "execute_query('hardcoded')"
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 0

    def test_no_sink_no_finding(self):
        specs = RuleSpecs(
            rule_id="t",
            sources=(SourceSpec(pattern="input"),),
        )
        src = "x = input()"
        r = analyze_module_source(src, specs)
        assert len(r.findings) == 0

    def test_empty_module(self):
        specs = _basic_specs()
        r = analyze_module_source("", specs)
        assert r.findings == []

    def test_only_constants(self):
        specs = _basic_specs()
        src = """
x = 1
y = 'abc'
z = x + y
"""
        r = analyze_module_source(src, specs)
        assert r.findings == []


# ============================================================================
# Dédup des findings
# ============================================================================

class TestDedup:

    def test_findings_are_deduped(self):
        specs = _basic_specs()
        src = """
data = input()
while True:
    execute_query(data)
    break
"""
        r = analyze_module_source(src, specs)
        sinks_per_line = {}
        for f in r.findings:
            sinks_per_line.setdefault(f.line, 0)
            sinks_per_line[f.line] += 1
        for line, count in sinks_per_line.items():
            assert count == 1


# ============================================================================
# AnalysisResult
# ============================================================================

class TestAnalysisResult:

    def test_state_out_contains_taint(self):
        specs = _basic_specs()
        src = """
data = input()
execute_query(data)
"""
        r = analyze_module_source(src, specs)
        non_empty = [s for s in r.state_out.values() if s]
        assert len(non_empty) >= 1

    def test_iterations_count(self):
        specs = _basic_specs()
        r = analyze_module_source("x = 1", specs)
        assert r.iterations >= 1
        assert r.iterations < 100
