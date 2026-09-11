"""Persistent call graph (Python) — multi-hop inter-procedural resolution.

Clean-room implementation. Replaces `ModuleRegistry`'s 1-hop resolution
(`resolve_imported_summaries`: import -> already-computed summary, itself
blind to its own calls) with a real graph (nodes = functions, edges =
resolved calls, including intra-file) and a summary computation done in
**topological order** (callees before callers): when B (imported by A)
itself calls a function of C, that link is now resolved — B's summary is
computed with C's summary already known, instead of treating that call
as opaque (SCA-9 over-approximation).

Reuses the import suffix-matching logic from `module_registry.py`
(`resolve_target_file`) — no duplication of that part, the only one
potentially fragile (ambiguities, anti-FP).

Cycles (mutual recursion A<->B): anti-FP, better to miss a flow than to
invent a false one (same philosophy as `module_registry.py`) — a node in a
cycle is computed last, with the summaries of the not-yet-resolved cycle
links (current behavior unchanged for this specific case, no invented
regression).

Reference: `docs/ROADMAP.md` § Persistent call graph (2026-07-26).
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Set, Tuple

from sca.dataflow.module_registry import resolve_target_file
from sca.dataflow.summary import (
    FunctionInfo,
    FunctionSummary,
    ImportInfo,
    collect_functions,
    collect_imports,
    compute_summary,
)

NodeKey = Tuple[str, str]  # (filepath, function_name)


def _resolve_import_bindings(
    filepath: str,
    imports: List[ImportInfo],
    known_files: List[str],
    file_function_names: Dict[str, Set[str]],
) -> Dict[str, NodeKey]:
    """Return the bindings brought in by `filepath`'s imports, indexed by the
    **local** call name as it appears in that file's code.

    Mirrors `ModuleRegistry._resolve_one_import`/`_apply_star_imports`, but
    returns `NodeKey`s (file, name) instead of `FunctionSummary`s —
    summary resolution itself has not happened yet at this stage
    (structural pre-pass of the graph, independent of rule specs).
    """
    out: Dict[str, NodeKey] = {}
    star_imports: List[ImportInfo] = []
    for imp in imports:
        if imp.orig_name == "*":
            star_imports.append(imp)
            continue
        if not imp.orig_name:
            # `import mod [as m]` -> calls of the form `m.func(...)`.
            target = resolve_target_file(filepath, imp, known_files)
            if target is not None:
                for fname in file_function_names.get(target, ()):
                    if "." not in fname:
                        out[f"{imp.local_name}.{fname}"] = (target, fname)
            continue
        # `from mod import X`: X is either a function or a submodule.
        target = resolve_target_file(filepath, imp, known_files)
        if target is not None and imp.orig_name in file_function_names.get(target, ()):
            out[imp.local_name] = (target, imp.orig_name)
            continue
        submod = resolve_target_file(
            filepath,
            ImportInfo(local_name=imp.local_name,
                      module=f"{imp.module}.{imp.orig_name}".lstrip(".") if imp.module else imp.orig_name,
                      orig_name="", level=imp.level),
            known_files,
        )
        if submod is not None:
            for fname in file_function_names.get(submod, ()):
                if "." not in fname:
                    out[f"{imp.local_name}.{fname}"] = (submod, fname)

    if star_imports:
        seen: Dict[str, NodeKey] = {}
        collided: Set[str] = set()
        for imp in star_imports:
            target = resolve_target_file(filepath, imp, known_files)
            if target is None:
                continue
            for fname in file_function_names.get(target, ()):
                if "." in fname:
                    continue
                key = (target, fname)
                if fname in seen and seen[fname] != key:
                    collided.add(fname)
                else:
                    seen[fname] = key
        for name, key in seen.items():
            if name not in collided and name not in out:
                out[name] = key
    return out


def _call_local_name(call: ast.Call) -> Optional[str]:
    """Return the local call name of an `ast.Call`: `foo` for `foo(...)`,
    `m.func` for `m.func(...)`. `None` for forms not statically
    resolvable (call on an expression, instance method without type
    info — out of scope, stays over-approximated as today)."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    return None


def _outgoing_edges(
    fn: FunctionInfo,
    filepath: str,
    local_names: Set[str],
    import_bindings: Dict[str, NodeKey],
) -> Dict[str, NodeKey]:
    """Return the outgoing edges of a function: local call name → target node.

    Resolves two cases: a call to a function in the **same file** (direct
    name in `local_names`), and a call to an **imported** function (via
    `import_bindings`, imports component). Other call forms (instance
    method, expression) remain unresolved — current behavior unchanged
    (SCA-9 over-approximation in `eval_call`)."""
    edges: Dict[str, NodeKey] = {}
    for node in ast.walk(fn.ast_def):
        if not isinstance(node, ast.Call):
            continue
        local_name = _call_local_name(node)
        if local_name is None or local_name in edges:
            continue
        if local_name in local_names:
            edges[local_name] = (filepath, local_name)
        elif local_name in import_bindings:
            edges[local_name] = import_bindings[local_name]
    return edges


@dataclass
class CallGraph:
    """Call graph of a set of Python files analyzed together.

    `nodes`: every known function/method, indexed by (file, name).
    `edges`: for each node, its resolved outgoing calls (local call name
    -> target node) — a subset of the real calls (calls that cannot be
    resolved statically are simply absent, not an error).
    """
    nodes: Dict[NodeKey, FunctionInfo] = field(default_factory=dict)
    edges: Dict[NodeKey, Dict[str, NodeKey]] = field(default_factory=dict)
    # All of a file's resolved imports (local name -> target node), whether
    # they are called inside a function or at module level — used to
    # reconstruct `extra_summaries` (Part 3), which is not restricted to a
    # particular function. See `resolve_summaries`.
    import_bindings: Dict[str, Dict[str, NodeKey]] = field(default_factory=dict)

    @classmethod
    def build(cls, trees: Dict[str, Optional[ast.Module]]) -> "CallGraph":
        """Build the full call graph (nodes + edges + import bindings) from a
        set of parsed Python modules."""
        graph = cls()
        file_function_names: Dict[str, Set[str]] = {}
        file_functions: Dict[str, List[FunctionInfo]] = {}
        imports_by_file: Dict[str, List[ImportInfo]] = {}

        for filepath, tree in trees.items():
            if tree is None:
                continue
            functions = collect_functions(tree)
            file_functions[filepath] = functions
            file_function_names[filepath] = {fn.name for fn in functions}
            for fn in functions:
                graph.nodes[(filepath, fn.name)] = fn
            imports_by_file[filepath] = collect_imports(tree)

        known_files = list(file_function_names.keys())
        for filepath, functions in file_functions.items():
            import_bindings = _resolve_import_bindings(
                filepath, imports_by_file.get(filepath, []),
                known_files, file_function_names,
            )
            graph.import_bindings[filepath] = import_bindings
            local_names = file_function_names[filepath]
            for fn in functions:
                graph.edges[(filepath, fn.name)] = _outgoing_edges(
                    fn, filepath, local_names, import_bindings,
                )
        return graph

    def topological_order(self) -> List[NodeKey]:
        """Return a callees-before-callers order (DFS post-order). A cycle
        leaves the revisited link unreordered: it will be computed without
        that particular callee being resolved yet (no flow over-invention,
        see module docstring)."""
        order: List[NodeKey] = []
        visited: Set[NodeKey] = set()
        in_progress: Set[NodeKey] = set()

        def visit(node: NodeKey) -> None:
            """Visit `node`'s callees depth-first, then append `node` (post-order)."""
            if node in visited or node not in self.nodes or node in in_progress:
                return
            in_progress.add(node)
            for target in self.edges.get(node, {}).values():
                visit(target)
            in_progress.discard(node)
            visited.add(node)
            order.append(node)

        for node in list(self.nodes):
            visit(node)
        return order

    def resolve_summaries(
        self, specs, language: str = "python",
        source_lines_by_file: Optional[Dict[str, List[str]]] = None,
    ) -> Tuple[Dict[str, Dict[str, FunctionSummary]], Dict[str, Dict[str, FunctionSummary]]]:
        """Compute the summaries of all functions in the graph, in
        topological order, seeding `specs.summaries` with the
        already-resolved summaries of callees (same file or cross-file) —
        multi-hop resolution.

        Returns `(own, extra)`:
          - `own`   : `{filepath: {function_name: FunctionSummary}}` —
            functions defined in each file (`precomputed_summaries` shape).
          - `extra` : `{filepath: {local_import_name: FunctionSummary}}` —
            all resolved imports of each file (`extra_summaries` shape),
            whether called inside a function or at module level.
        """
        resolved: Dict[NodeKey, FunctionSummary] = {}
        own: Dict[str, Dict[str, FunctionSummary]] = {}
        source_lines_by_file = source_lines_by_file or {}

        for node in self.topological_order():
            filepath, name = node
            fn = self.nodes[node]
            seed: Dict[str, FunctionSummary] = {}
            for local_name, target in self.edges.get(node, {}).items():
                if target in resolved:
                    seed[local_name] = resolved[target]
            node_specs = replace(specs, summaries=seed) if seed else specs
            try:
                summary = compute_summary(
                    fn, node_specs, language=language,
                    source_lines=source_lines_by_file.get(filepath),
                )
            except Exception:  # robustness: a broken function doesn't halt the whole pass
                continue
            resolved[node] = summary
            own.setdefault(filepath, {})[name] = summary

        extra: Dict[str, Dict[str, FunctionSummary]] = {}
        for filepath, bindings in self.import_bindings.items():
            for local_name, target in bindings.items():
                if target in resolved:
                    extra.setdefault(filepath, {})[local_name] = resolved[target]

        return own, extra
