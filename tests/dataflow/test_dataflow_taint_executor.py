"""Tests de l'executor dataflow_taint — Phase 4 du moteur dataflow SCA.

Couvre :
  - API publique `run_taint_rule(rule_json, content, ...)` (contrat §3.1)
  - Conversion regex DSL → RuleSpecs dataflow
  - Gestion des erreurs (contrat §3.4)
  - Cas d'usage typiques avec règles DSL ressemblant aux .sca builtin
"""
from __future__ import annotations

import pytest

from sca.dataflow.transfer import Finding
from sca.executors.dataflow_taint import (
    UnsupportedLanguage,
    regex_to_dotted_patterns,
    rule_json_to_specs,
    run_taint_rule,
)


# ============================================================================
# Conversion regex → dotted patterns
# ============================================================================

class TestRegexToDotted:

    def test_simple_alternation(self):
        out = regex_to_dotted_patterns(r"request\.(GET|POST|args|form)")
        assert "request.GET" in out
        assert "request.POST" in out
        assert "request.args" in out
        assert "request.form" in out

    def test_method_suffix(self):
        """`.method\\s*\\(` → `**.method` (matche tout préfixe)."""
        out = regex_to_dotted_patterns(r"\.execute\s*\(")
        assert "**.execute" in out

    def test_word_boundary(self):
        out = regex_to_dotted_patterns(r"\bint\s*\(")
        assert "int" in out

    def test_anchored_start(self):
        out = regex_to_dotted_patterns(r"^input\s*\(")
        assert "input" in out

    def test_dotted_name(self):
        out = regex_to_dotted_patterns(r"subprocess\.run")
        assert "subprocess.run" in out

    def test_empty_pattern(self):
        assert regex_to_dotted_patterns("") == []

    def test_complex_pattern_best_effort(self):
        """Pattern complexe : retourne quelque chose, même imparfait."""
        out = regex_to_dotted_patterns(r"request\.(GET|POST)\.get")
        # Au moins on a request.GET.get et request.POST.get
        assert any("request.GET" in p for p in out)
        assert any("request.POST" in p for p in out)


# ============================================================================
# Conversion rule_json → RuleSpecs
# ============================================================================

class TestRuleJsonToSpecs:

    def _minimal_rule(self, **kwargs):
        return {
            "rule_id": "test_rule",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"input", "kind": "cli"}],
            "sinks": [{"pattern": r"sink"}],
            **kwargs,
        }

    def test_minimal_conversion(self):
        specs = rule_json_to_specs(self._minimal_rule())
        assert specs is not None
        assert specs.rule_id == "test_rule"
        assert specs.severity == "HIGH"
        assert len(specs.sources) == 1
        assert specs.sources[0].kind == "cli"

    def test_returns_none_if_no_sources(self):
        rule = self._minimal_rule()
        rule["sources"] = []
        assert rule_json_to_specs(rule) is None

    def test_returns_none_if_no_sinks(self):
        rule = self._minimal_rule()
        rule["sinks"] = []
        assert rule_json_to_specs(rule) is None

    def test_metadata_cwe(self):
        rule = self._minimal_rule(metadata={"cwe": "CWE-89"})
        specs = rule_json_to_specs(rule)
        assert specs.cwe == "CWE-89"

    def test_metadata_cwe_list(self):
        """Si metadata.cwe est une liste, on prend le premier."""
        rule = self._minimal_rule(metadata={"cwe": ["CWE-89", "CWE-78"]})
        specs = rule_json_to_specs(rule)
        assert specs.cwe == "CWE-89"

    def test_message_i18n(self):
        rule = self._minimal_rule(message={"en": "SQL injection", "fr": "Injection SQL"})
        specs = rule_json_to_specs(rule)
        assert specs.message == "SQL injection"

    def test_sink_args(self):
        rule = self._minimal_rule(
            sinks=[{"pattern": r"sink", "args": [0, 1]}]
        )
        specs = rule_json_to_specs(rule)
        assert specs.sinks[0].args == (0, 1)


# ============================================================================
# API publique : run_taint_rule
# ============================================================================

def _sqli_rule():
    return {
        "rule_id": "sqli",
        "mode": "taint",
        "severity": "HIGH",
        "sources": [{"pattern": r"request\.(GET|POST)", "kind": "http"}],
        "sinks": [{"pattern": r"cursor\.execute\s*\(", "args": [0]}],
        "sanitizers": [{"pattern": r"\bint\s*\("}],
        "message": {"en": "SQL injection"},
        "metadata": {"cwe": "CWE-89"},
    }


class TestRunTaintRule:

    def test_detect_sqli(self):
        src = """
data = request.GET
cursor.execute(data)
"""
        findings = list(run_taint_rule(_sqli_rule(), src))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "sqli"
        assert f.severity == "HIGH"
        assert f.cwe == "CWE-89"
        assert f.source_line == 2
        assert f.line == 3

    def test_sanitizer_suppresses_finding(self):
        src = """
data = request.GET
safe = int(data)
cursor.execute(safe)
"""
        findings = list(run_taint_rule(_sqli_rule(), src))
        assert len(findings) == 0

    def test_no_source_no_finding(self):
        src = """
data = 'hardcoded'
cursor.execute(data)
"""
        findings = list(run_taint_rule(_sqli_rule(), src))
        assert len(findings) == 0

    def test_returns_iterable(self):
        """Le contrat dit Iterable[Finding] — on peut yield ou return list."""
        result = run_taint_rule(_sqli_rule(), "x = 1")
        # Doit être itérable (générateur OU liste)
        items = list(result)
        assert isinstance(items, list)


class TestRunTaintRuleEdgeCases:

    def test_non_taint_mode_returns_empty(self):
        rule = _sqli_rule()
        rule["mode"] = "regex"
        result = list(run_taint_rule(rule, "data = request.GET\ncursor.execute(data)"))
        assert result == []

    def test_syntax_error_in_content_returns_empty(self):
        """Contrat §3.4 : syntax error → liste vide, ne pas raise."""
        result = list(run_taint_rule(_sqli_rule(), "def broken("))
        assert result == []

    def test_empty_content(self):
        result = list(run_taint_rule(_sqli_rule(), ""))
        assert result == []

    def test_rule_without_sources_returns_empty(self):
        rule = _sqli_rule()
        rule["sources"] = []
        result = list(run_taint_rule(rule, "x = 1"))
        assert result == []

    def test_rule_without_sinks_returns_empty(self):
        rule = _sqli_rule()
        rule["sinks"] = []
        result = list(run_taint_rule(rule, "x = 1"))
        assert result == []

    def test_unsupported_language_raises(self):
        """Contrat §3.4 : langage non supporté → raise UnsupportedLanguage."""
        with pytest.raises(UnsupportedLanguage):
            list(run_taint_rule(_sqli_rule(), "x = 1", language="rust"))


# ============================================================================
# Cas d'usage réalistes (proche des .sca builtin)
# ============================================================================

class TestRealisticRules:

    def test_xpath_injection(self):
        """Reproduit ~taint_xpathi.sca."""
        rule = {
            "rule_id": "taint_xpathi",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [
                {"pattern": r"request\.(GET|POST|args|form|json|data)", "kind": "http"},
                {"pattern": r"input\s*\(", "kind": "stdin"},
            ],
            "sinks": [
                {"pattern": r"\.xpath\s*\("},
                {"pattern": r"etree\.XPath\s*\("},
            ],
            "sanitizers": [{"pattern": r"\bint\s*\("}],
            "metadata": {"cwe": "CWE-643"},
        }
        src = """
user = request.args
tree.xpath(user)
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) == 1
        assert findings[0].cwe == "CWE-643"

    def test_command_injection(self):
        rule = {
            "rule_id": "taint_cmdi",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"input", "kind": "stdin"}],
            "sinks": [{"pattern": r"subprocess\.(run|call|Popen)"}],
            "sanitizers": [{"pattern": r"shlex\.quote"}],
            "metadata": {"cwe": "CWE-78"},
        }
        src = """
cmd = input()
subprocess.run(cmd)
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) == 1

    def test_command_injection_sanitized(self):
        rule = {
            "rule_id": "taint_cmdi",
            "mode": "taint",
            "severity": "HIGH",
            "sources": [{"pattern": r"input", "kind": "stdin"}],
            "sinks": [{"pattern": r"subprocess\.(run|call|Popen)"}],
            "sanitizers": [{"pattern": r"shlex\.quote"}],
            "metadata": {"cwe": "CWE-78"},
        }
        src = """
cmd = input()
safe = shlex.quote(cmd)
subprocess.run(safe)
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) == 0

    def test_taint_propagation_through_concat(self):
        rule = _sqli_rule()
        src = """
data = request.GET
query = 'SELECT * FROM t WHERE id = ' + data
cursor.execute(query)
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) == 1

    def test_taint_propagation_through_fstring(self):
        rule = _sqli_rule()
        src = """
data = request.GET
query = f'SELECT * FROM t WHERE id = {data}'
cursor.execute(query)
"""
        findings = list(run_taint_rule(rule, src))
        assert len(findings) == 1


# ============================================================================
# Conformité au contrat §3.2 (Finding fields)
# ============================================================================

class TestFindingStructure:

    def test_finding_has_all_required_fields(self):
        src = """
data = request.GET
cursor.execute(data)
"""
        findings = list(run_taint_rule(_sqli_rule(), src))
        f = findings[0]
        # Tous les champs requis du contrat §3.2
        assert hasattr(f, "rule_id")
        assert hasattr(f, "severity")
        assert hasattr(f, "line")
        assert hasattr(f, "column")
        assert hasattr(f, "sink_text")
        assert hasattr(f, "source_line")
        assert hasattr(f, "message")
        assert hasattr(f, "cwe")
        assert hasattr(f, "flow")

    def test_sink_text_is_source_line(self):
        """sink_text est enrichi avec la ligne source brute."""
        src = """
data = request.GET
cursor.execute(data)
"""
        findings = list(run_taint_rule(_sqli_rule(), src))
        f = findings[0]
        assert "cursor.execute" in f.sink_text

    def test_flow_has_source_and_sink_steps(self):
        src = """
data = request.GET
cursor.execute(data)
"""
        findings = list(run_taint_rule(_sqli_rule(), src))
        f = findings[0]
        kinds = [step.kind for step in f.flow]
        assert "source" in kinds
        assert "sink" in kinds
