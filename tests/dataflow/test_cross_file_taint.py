"""Tests Volet 3 — propagation taint inter-fichiers (cross-module).

Couvre :
  - collect_imports : extraction des bindings d'import (A)
  - compute_file_summaries : helper partagé de calcul des fiches (A)
  - ModuleRegistry : résolution d'imports intra-package (B)
  - run_taint_rule(extra_summaries=...) : propagation cross-fichier effective (C)

Référence : `sca/dataflow/summary.py`, `sca/dataflow/module_registry.py`.
"""
from __future__ import annotations

import ast

from sca.dataflow.module_registry import ModuleRegistry
from sca.executors.dataflow_adapter import (
    run_dataflow_taint_for_files,
    run_dataflow_taint_for_files_parallel,
)
from sca.dataflow.summary import (
    ImportInfo,
    collect_imports,
    compute_file_summaries,
)
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


class TestCollectImports:
    def test_from_import_simple(self):
        imps = collect_imports(ast.parse("from pkg.utils import helper\n"))
        assert imps == [ImportInfo("helper", "pkg.utils", "helper", 0)]

    def test_from_import_alias(self):
        imps = collect_imports(ast.parse("from pkg.utils import helper as h\n"))
        assert imps[0].local_name == "h"
        assert imps[0].orig_name == "helper"
        assert imps[0].module == "pkg.utils"

    def test_relative_import_level(self):
        imps = collect_imports(ast.parse("from .utils import helper\n"))
        assert imps[0].level == 1
        assert imps[0].module == "utils"
        imps2 = collect_imports(ast.parse("from ..lib.utils import helper\n"))
        assert imps2[0].level == 2

    def test_from_dot_import_module(self):
        imps = collect_imports(ast.parse("from . import utils\n"))
        assert imps[0].local_name == "utils"
        assert imps[0].orig_name == "utils"
        assert imps[0].level == 1

    def test_plain_import(self):
        imps = collect_imports(ast.parse("import pkg.utils as u\n"))
        assert imps[0].local_name == "u"
        assert imps[0].module == "pkg.utils"
        assert imps[0].orig_name == ""

    def test_wildcard_collected_as_marker(self):
        # Volet 5C — le wildcard est désormais collecté (marqueur orig_name="*").
        imps = collect_imports(ast.parse("from pkg.utils import *\n"))
        assert imps == [ImportInfo("*", "pkg.utils", "*", 0)]

    def test_nested_import_collected(self):
        # Volet 5D — import imbriqué dans une fonction collecté.
        src = "def f():\n    from pkg.utils import helper\n    return helper()\n"
        imps = collect_imports(ast.parse(src))
        assert ImportInfo("helper", "pkg.utils", "helper", 0) in imps

    def test_multiple_names(self):
        imps = collect_imports(ast.parse("from pkg import a, b as c\n"))
        assert {i.local_name for i in imps} == {"a", "c"}


class TestComputeFileSummaries:
    def test_returns_summary_per_function(self):
        src = (
            "def get_input(request):\n"
            "    return request.GET['q']\n"
            "def run_query(query, db):\n"
            "    db.execute(query)\n"
        )
        sums = compute_file_summaries(ast.parse(src), _SQLI,
                                      source_lines=src.splitlines())
        assert "get_input" in sums and "run_query" in sums
        assert sums["get_input"].return_tainted_uncond is True
        assert 0 in sums["run_query"].sink_param_findings

    def test_empty_module(self):
        assert compute_file_summaries(ast.parse("x = 1\n"), _SQLI) == {}


# Le module utilitaire « callee » : helper() atteint un sink sur son param 0.
_UTILS_SRC = (
    "def run_query(query, db):\n"
    "    db.execute('SELECT ' + query)\n"
)


def _registry(files):
    """Construit un ModuleRegistry depuis {filepath: source}."""
    reg = ModuleRegistry()
    for fp, src in files.items():
        tree = ast.parse(src)
        reg.add_file(
            fp,
            compute_file_summaries(tree, _SQLI, source_lines=src.splitlines()),
            collect_imports(tree),
        )
    return reg


class TestModuleRegistry:
    def test_relative_import_resolves(self):
        reg = _registry({
            "pkg/utils.py": _UTILS_SRC,
            "pkg/api.py": "from .utils import run_query\n",
        })
        resolved = reg.resolve_imported_summaries("pkg/api.py")
        assert "run_query" in resolved
        assert 0 in resolved["run_query"].sink_param_findings

    def test_absolute_intra_package_resolves(self):
        reg = _registry({
            "pkg/utils.py": _UTILS_SRC,
            "pkg/api.py": "from pkg.utils import run_query\n",
        })
        assert "run_query" in reg.resolve_imported_summaries("pkg/api.py")

    def test_alias_keyed_by_local_name(self):
        reg = _registry({
            "pkg/utils.py": _UTILS_SRC,
            "pkg/api.py": "from .utils import run_query as rq\n",
        })
        resolved = reg.resolve_imported_summaries("pkg/api.py")
        assert "rq" in resolved and "run_query" not in resolved

    def test_module_object_import_exposes_dotted(self):
        reg = _registry({
            "pkg/utils.py": _UTILS_SRC,
            "pkg/api.py": "from . import utils\n",
        })
        resolved = reg.resolve_imported_summaries("pkg/api.py")
        assert "utils.run_query" in resolved

    def test_unresolved_when_target_absent(self):
        # Le module importé n'est pas dans le jeu analysé → aucune résolution.
        reg = _registry({
            "pkg/api.py": "from external.lib import run_query\n",
        })
        assert reg.resolve_imported_summaries("pkg/api.py") == {}

    def test_ambiguous_absolute_not_resolved(self):
        # Deux fichiers candidats pour le même suffixe absolu → ambigu → None.
        reg = _registry({
            "a/utils.py": _UTILS_SRC,
            "b/utils.py": _UTILS_SRC,
            "pkg/api.py": "from utils import run_query\n",
        })
        assert reg.resolve_imported_summaries("pkg/api.py") == {}


class TestRunTaintRuleCrossFile:
    """Tâche C — extra_summaries injectées dans run_taint_rule."""

    def _utils_registry(self, caller_src):
        files = {"pkg/utils.py": _UTILS_SRC, "pkg/api.py": caller_src}
        reg = _registry(files)
        return reg

    def test_cross_file_source_to_sink(self):
        caller = (
            "from .utils import run_query\n"
            "def handler(request, db):\n"
            "    q = request.GET['q']\n"
            "    run_query(q, db)\n"
        )
        reg = self._utils_registry(caller)
        extra = reg.resolve_imported_summaries("pkg/api.py")
        findings = list(run_taint_rule(
            _SQLI_RULE, caller, filename="pkg/api.py", language="python",
            extra_summaries=extra,
        ))
        assert len(findings) >= 1, "Flux source(A) → sink importé(B) attendu"
        assert any(
            any(step.kind == "propagation" and "→" in step.text for step in f.flow)
            for f in findings
        ), "Le flow doit contenir un saut inter-fichiers (→)"

    def test_no_finding_without_extra_summaries(self):
        # Sans les fiches cross-fichier, run_query est opaque → pas de flux
        # (la fonction importée n'est pas définie dans ce fichier).
        caller = (
            "from .utils import run_query\n"
            "def handler(request, db):\n"
            "    q = request.GET['q']\n"
            "    run_query(q, db)\n"
        )
        findings = list(run_taint_rule(
            _SQLI_RULE, caller, filename="pkg/api.py", language="python",
        ))
        assert findings == []

    def test_clean_arg_no_finding(self):
        caller = (
            "from .utils import run_query\n"
            "def handler(db):\n"
            "    run_query('constant', db)\n"
        )
        reg = self._utils_registry(caller)
        extra = reg.resolve_imported_summaries("pkg/api.py")
        findings = list(run_taint_rule(
            _SQLI_RULE, caller, filename="pkg/api.py", language="python",
            extra_summaries=extra,
        ))
        assert findings == []

    def test_local_def_shadows_import(self):
        # Une def locale du même nom prime sur la fiche importée.
        caller = (
            "from .utils import run_query\n"
            "def run_query(query, db):\n"
            "    db.log(query)\n"          # pas de sink ici
            "def handler(request, db):\n"
            "    q = request.GET['q']\n"
            "    run_query(q, db)\n"
        )
        reg = self._utils_registry(caller)
        extra = reg.resolve_imported_summaries("pkg/api.py")
        findings = list(run_taint_rule(
            _SQLI_RULE, caller, filename="pkg/api.py", language="python",
            extra_summaries=extra,
        ))
        # La def locale (sans sink) masque l'import (avec sink) → pas de flux.
        assert findings == []

    def test_precomputed_summaries_equivalent(self):
        # precomputed_summaries doit donner le même résultat que le calcul interne.
        src = (
            "def get_input(request):\n"
            "    return request.GET['q']\n"
            "def handler(request, db):\n"
            "    db.execute(get_input(request))\n"
        )
        pre = compute_file_summaries(ast.parse(src), _SQLI,
                                     source_lines=src.splitlines())
        with_pre = list(run_taint_rule(
            _SQLI_RULE, src, language="python", precomputed_summaries=pre))
        without = list(run_taint_rule(_SQLI_RULE, src, language="python"))
        assert len(with_pre) == len(without)


# Projet multi-fichiers : source dans api.py → sink importé de utils.py.
_PROJECT = {
    "pkg/utils.py": _UTILS_SRC,
    "pkg/api.py": (
        "from .utils import run_query\n"
        "def handler(request, db):\n"
        "    q = request.GET['q']\n"
        "    run_query(q, db)\n"
    ),
}


class TestVolet5ImportCoverage:
    """Volet 5 — `from x import *` (C) et imports imbriqués dans une fonction (D)."""

    def test_wildcard_import_resolves(self):
        reg = _registry({
            "pkg/utils.py": _UTILS_SRC,
            "pkg/api.py": "from .utils import *\n",
        })
        resolved = reg.resolve_imported_summaries("pkg/api.py")
        assert "run_query" in resolved

    def test_nested_import_in_function_collected(self):
        reg = _registry({
            "pkg/utils.py": _UTILS_SRC,
            "pkg/api.py": (
                "def handler(request, db):\n"
                "    from .utils import run_query\n"
                "    run_query(request, db)\n"
            ),
        })
        assert "run_query" in reg.resolve_imported_summaries("pkg/api.py")

    def test_wildcard_collision_not_resolved(self):
        # Deux `*` apportent run_query avec des corps différents → ambigu → ignoré.
        other = "def run_query(query, db):\n    db.log(query)\n"  # pas de sink
        reg = _registry({
            "pkg/a.py": _UTILS_SRC,
            "pkg/b.py": other,
            "pkg/api.py": "from .a import *\nfrom .b import *\n",
        })
        assert "run_query" not in reg.resolve_imported_summaries("pkg/api.py")

    def test_explicit_import_wins_over_wildcard(self):
        # Import explicite (avec sink) prime sur un `*` qui apporterait autre chose.
        other = "def run_query(query, db):\n    db.log(query)\n"
        reg = _registry({
            "pkg/a.py": _UTILS_SRC,
            "pkg/b.py": other,
            "pkg/api.py": "from .a import run_query\nfrom .b import *\n",
        })
        resolved = reg.resolve_imported_summaries("pkg/api.py")
        # La fiche retenue est celle de a.py (sink), pas celle de b.py.
        assert 0 in resolved["run_query"].sink_param_findings


class TestAdapterOrchestration:
    """Tâche D — pré-passe + injection via l'orchestrateur (séquentiel/parallèle)."""

    def test_sequential_cross_file_flow(self):
        flows = list(run_dataflow_taint_for_files(
            [_SQLI_RULE], _PROJECT, "python", category="security"))
        assert len(flows) >= 1
        # Le flux est attribué au fichier appelant (api.py).
        assert any(tf.source_file == "pkg/api.py" for tf in flows)

    def test_sequential_no_cross_file_when_isolated(self):
        # utils.py seul (sans appelant tainté) → pas de flux.
        flows = list(run_dataflow_taint_for_files(
            [_SQLI_RULE], {"pkg/utils.py": _UTILS_SRC}, "python"))
        assert flows == []

    def test_parallel_path_cross_file_flow(self):
        # Pad à ≥20 fichiers pour déclencher le ProcessPoolExecutor.
        project = dict(_PROJECT)
        for i in range(25):
            project[f"pkg/pad_{i}.py"] = "x = 1\n"
        flows = list(run_dataflow_taint_for_files_parallel(
            [_SQLI_RULE], project, "python", category="security", max_workers=2))
        assert any(
            tf.source_file == "pkg/api.py" and tf.rule_key == "taint_sqli"
            for tf in flows
        ), "Le chemin parallèle doit aussi détecter le flux inter-fichiers"
