"""Tests du graphe d'appels persistant (Volet graphe d'appels, 2026-07-26).

Couvre :
  - CallGraph.build : arêtes intra-fichier ET cross-fichier (imports)
  - topological_order : callees avant callers, cycles sans boucle infinie
  - resolve_summaries : résolution multi-sauts (A→B→C), y compris intra-fichier
    (fonctions sœurs, aveugles l'une à l'autre avant ce chantier)

Référence : `sca/dataflow/call_graph.py`, `docs/ROADMAP.md` § Graphe d'appels
persistant.
"""
from __future__ import annotations

import ast

from sca.dataflow.call_graph import CallGraph
from sca.executors.dataflow_taint import rule_json_to_specs

_SQLI = rule_json_to_specs({
    "id": "taint_sqli",
    "mode": "taint",
    "severity": "HIGH",
    "sources": [{"pattern": r"request\.(GET|args|form|json)", "kind": "http"}],
    "sinks": [{"pattern": r"\.execute\s*\("}],
    "sanitizers": [{"pattern": r"re\.fullmatch"}],
})


def _trees(files: dict) -> dict:
    return {path: ast.parse(src) for path, src in files.items()}


class TestBuildEdges:
    def test_intra_file_edge(self):
        graph = CallGraph.build(_trees({
            "a.py": "def foo():\n    return bar()\ndef bar():\n    return 1\n",
        }))
        assert graph.edges[("a.py", "foo")] == {"bar": ("a.py", "bar")}
        assert graph.edges[("a.py", "bar")] == {}

    def test_cross_file_edge_via_from_import(self):
        graph = CallGraph.build(_trees({
            "a.py": "from b import helper\ndef foo():\n    return helper()\n",
            "b.py": "def helper():\n    return 1\n",
        }))
        assert graph.edges[("a.py", "foo")] == {"helper": ("b.py", "helper")}

    def test_cross_file_edge_via_module_import(self):
        graph = CallGraph.build(_trees({
            "a.py": "import b\ndef foo():\n    return b.helper()\n",
            "b.py": "def helper():\n    return 1\n",
        }))
        assert graph.edges[("a.py", "foo")] == {"b.helper": ("b.py", "helper")}

    def test_unresolvable_call_has_no_edge(self):
        graph = CallGraph.build(_trees({
            "a.py": "def foo(obj):\n    return obj.method()\n",
        }))
        assert graph.edges[("a.py", "foo")] == {}


class TestTopologicalOrder:
    def test_callee_before_caller(self):
        graph = CallGraph.build(_trees({
            "a.py": "def foo():\n    return bar()\ndef bar():\n    return baz()\n"
                    "def baz():\n    return 1\n",
        }))
        order = graph.topological_order()
        assert order.index(("a.py", "baz")) < order.index(("a.py", "bar"))
        assert order.index(("a.py", "bar")) < order.index(("a.py", "foo"))

    def test_cross_file_order(self):
        graph = CallGraph.build(_trees({
            "a.py": "from b import wrapper\ndef foo():\n    return wrapper()\n",
            "b.py": "from c import helper\ndef wrapper():\n    return helper()\n",
            "c.py": "def helper():\n    return 1\n",
        }))
        order = graph.topological_order()
        assert order.index(("c.py", "helper")) < order.index(("b.py", "wrapper"))
        assert order.index(("b.py", "wrapper")) < order.index(("a.py", "foo"))

    def test_cycle_does_not_hang(self):
        graph = CallGraph.build(_trees({
            "a.py": "def foo():\n    return bar()\ndef bar():\n    return foo()\n",
        }))
        order = graph.topological_order()
        assert set(order) == {("a.py", "foo"), ("a.py", "bar")}

    def test_self_recursion_does_not_hang(self):
        graph = CallGraph.build(_trees({
            "a.py": "def fact(n):\n    return fact(n - 1)\n",
        }))
        order = graph.topological_order()
        assert order == [("a.py", "fact")]


class TestResolveSummariesMultiHop:
    def test_transitive_source_reaches_caller_two_hops(self):
        """A→B→C : C source inconditionnelle, B pur wrapper, A appelle B.

        Avant ce chantier : la summary de B (calculée seule, sans connaître C)
        ne peut pas savoir que son retour est taint (l'appel à `source()` est
        opaque). Avec le graphe, B.wrapper est calculé APRES C.source, donc sa
        summary reflète correctement `return_tainted_uncond=True`.
        """
        trees = _trees({
            "a.py": "from b import wrapper\ndef entry():\n    x = wrapper()\n"
                    "    cur.execute(x)\n",
            "b.py": "from c import get_tainted\ndef wrapper():\n    return get_tainted()\n",
            "c.py": "def get_tainted():\n    return request.GET['x']\n",
        })
        graph = CallGraph.build(trees)
        per_file, _extra = graph.resolve_summaries(_SQLI, source_lines_by_file={
            fp: src.splitlines() for fp, src in {
                "a.py": "from b import wrapper\ndef entry():\n    x = wrapper()\n"
                        "    cur.execute(x)\n",
                "b.py": "from c import get_tainted\ndef wrapper():\n    return get_tainted()\n",
                "c.py": "def get_tainted():\n    return request.GET['x']\n",
            }.items()
        })
        assert per_file["c.py"]["get_tainted"].return_tainted_uncond is True
        # Le maillon intermediaire (b.py) doit desormais heriter du taint de C
        # via le seed multi-sauts -- c'est le gain apporte par le graphe.
        assert per_file["b.py"]["wrapper"].return_tainted_uncond is True

    def test_intra_file_sibling_resolution(self):
        """Meme fichier : bar() taint via source, foo() appelle bar() -- foo
        doit heriter du taint de bar (les fonctions soeurs se voient
        desormais pendant le calcul de leur propre summary, pas seulement a
        la passe finale)."""
        src = (
            "def bar():\n    return request.GET['x']\n"
            "def foo():\n    return bar()\n"
        )
        graph = CallGraph.build(_trees({"a.py": src}))
        per_file, _extra = graph.resolve_summaries(
            _SQLI, source_lines_by_file={"a.py": src.splitlines()},
        )
        assert per_file["a.py"]["bar"].return_tainted_uncond is True
        assert per_file["a.py"]["foo"].return_tainted_uncond is True

    def test_cycle_resolves_without_crashing(self):
        src = (
            "def foo(n):\n    return bar(n)\n"
            "def bar(n):\n    return foo(n)\n"
        )
        graph = CallGraph.build(_trees({"a.py": src}))
        per_file, _extra = graph.resolve_summaries(
            _SQLI, source_lines_by_file={"a.py": src.splitlines()},
        )
        assert set(per_file["a.py"]) == {"foo", "bar"}

    def test_extra_summaries_cover_imported_bindings(self):
        """`extra` doit exposer les imports resolus par nom local, y compris
        un import jamais appele depuis une fonction (usage module-level) --
        forme attendue par `run_taint_rule(extra_summaries=...)`."""
        trees = _trees({
            "a.py": "from b import helper as h\ndef foo():\n    return h()\n",
            "b.py": "def helper():\n    return request.GET['x']\n",
        })
        graph = CallGraph.build(trees)
        _own, extra = graph.resolve_summaries(_SQLI, source_lines_by_file={
            "a.py": "from b import helper as h\ndef foo():\n    return h()\n".splitlines(),
            "b.py": "def helper():\n    return request.GET['x']\n".splitlines(),
        })
        assert extra["a.py"]["h"].return_tainted_uncond is True
