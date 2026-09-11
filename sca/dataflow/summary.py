"""Function summaries for interprocedural analysis.

Clean-room implementation based on sca/docs/dataflow-spec.md §8.
Algorithms inspired by:
  - Nielson, Nielson, Hankin — Principles of Program Analysis (Springer 2005, ch. 2)
  - Sridharan & Bodík — Refinement-Based Context-Sensitive Points-To Analysis (PLDI 2006)

No reading of semgrep's OCaml code was done to write this module.

Overview:
    For each function in the module, we compute a summary describing:
        - The reachable sinks and under what condition (tainted params)
        - The taint of the return value depending on tainted params
        - The internal sources that contribute to the return value

    Phase 6 approach: each FunctionDef is treated as a sub-module and an
    intra-procedural analysis is run on it. Findings emitted in the
    sub-analysis are propagated back to the caller with the function's
    lineno.

    Limitations (minimal Phase 6):
        - No cross-file support
        - Recursion handled via a trivial fixed-point (max 2 iterations)
        - Class methods treated as functions (ClassDef.body iterated)
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple


@dataclass
class FunctionInfo:
    """Metadata for a function defined in the module.

    Attributes:
        name: name (for global functions) or dotted name (Class.method).
        ast_def: AST node, FunctionDef / AsyncFunctionDef.
        param_names: positional parameter names.
        is_method: True if a class method (1st param is self/cls).
    """
    name: str
    ast_def: ast.AST                # FunctionDef or AsyncFunctionDef
    param_names: Tuple[str, ...] = field(default_factory=tuple)
    is_method: bool = False


def collect_functions(module: ast.Module) -> List[FunctionInfo]:
    """List all FunctionDef / AsyncFunctionDef / methods of the module.

    Spec §8.1 — summary preparation. Nested functions (def inside def)
    are also collected (dotted name).
    """
    functions: List[FunctionInfo] = []

    def _walk(node: ast.AST, prefix: str = "", is_method: bool = False) -> None:
        """Recursively collect FunctionInfo entries from `node` and its children."""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            full_name = f"{prefix}{node.name}" if prefix else node.name
            params = tuple(a.arg for a in node.args.args)
            functions.append(FunctionInfo(
                name=full_name,
                ast_def=node,
                param_names=params,
                is_method=is_method,
            ))
            # Continue into the body for nested functions
            for child in node.body:
                _walk(child, prefix=f"{full_name}.", is_method=False)
            return

        if isinstance(node, ast.ClassDef):
            class_prefix = f"{prefix}{node.name}."
            for item in node.body:
                _walk(item, prefix=class_prefix, is_method=True)
            return

        # For other nodes, descend into the children
        for child in ast.iter_child_nodes(node):
            _walk(child, prefix=prefix, is_method=is_method)

    for stmt in module.body:
        _walk(stmt)
    return functions


@dataclass
class ImportInfo:
    """A name imported into a module (Component 3 — cross-file resolution).

    Describes the binding created by an `import`/`from … import …`, in
    order to link a `local_name(...)` call to the `orig_name` function
    defined in the source module.

    Attributes:
        local_name: name bound in the importing module (alias included).
        module: dotted path of the source module (e.g. `mypkg.utils`, `utils`).
        orig_name: original name in the source module; `""` for a plain
            `import module` (the binding is then the module itself).
        level: relative import level (0 = absolute, 1 = `.`, 2 = `..`).
    """
    local_name: str
    module: str
    orig_name: str = ""
    level: int = 0


def collect_imports(module: ast.Module) -> List[ImportInfo]:
    """List the imports of a module (components 3 + 5).

    Forms covered:
        - `from pkg.utils import helper [as h]` → ImportInfo(h|helper, pkg.utils, helper, level)
        - `from . import utils`                 → ImportInfo(utils, "", utils, level)
        - `import pkg.utils [as u]`             → ImportInfo(u|pkg.utils, pkg.utils, "", 0)
        - `from .db import *` (component 5C)    → ImportInfo("*", db, "*", level)

    Component 5D — imports **nested inside a function** (lazy imports,
    anti-cycle) are also collected: the whole AST is walked, not just
    `module.body`. The binding is treated at file level (additive
    over-approximation: a locally imported name is resolved for the
    whole file).
    """
    imports: List[ImportInfo] = []
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(ImportInfo(
                    local_name=alias.asname or alias.name,
                    module=alias.name,
                    orig_name="",
                    level=0,
                ))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                # Component 5C — wildcard: "*" marker resolved by exposing all
                # top-level functions of the target module (cf. ModuleRegistry).
                name = alias.name
                imports.append(ImportInfo(
                    local_name=alias.asname or name,
                    module=mod,
                    orig_name=name,
                    level=node.level or 0,
                ))
    return imports


# Recognized route decorators (FastAPI / Flask / Starlette). We match on
# the called attribute (`@app.get(...)`, `@router.post(...)`, `@bp.route(...)`),
# independent of the receiver's name (app/router/bp/api…).
_ROUTE_DECORATOR_ATTRS = frozenset({
    "route", "get", "post", "put", "delete", "patch", "head",
    "options", "websocket",
})

# Scalar types for which an annotated parameter is, by FastAPI convention, a
# user-controlled path/query parameter (hence an HTTP source). Conservative:
# we only taint these explicit annotations (an unannotated parameter or one
# typed `Depends(...)`/`Session`/`Request` stays a dependency).
_USER_PARAM_SCALARS = frozenset({
    "str", "int", "float", "bool", "bytes", "UUID",
})


def is_route_handler(fn: FunctionInfo) -> bool:
    """Return True if the function is a web route handler (recognized decorator).

    Detects patterns like `@app.get(...)`, `@router.post(...)`,
    `@blueprint.route(...)` etc. — a decorator that is a call on an HTTP
    method attribute. See `_ROUTE_DECORATOR_ATTRS`.
    """
    for deco in getattr(fn.ast_def, "decorator_list", []):
        target = deco.func if isinstance(deco, ast.Call) else deco
        if isinstance(target, ast.Attribute) and target.attr in _ROUTE_DECORATOR_ATTRS:
            return True
    return False


def route_source_params(fn: FunctionInfo) -> Tuple[str, ...]:
    """Return the parameters of a route handler to treat as HTTP sources.

    Conservative: only parameters annotated with a user-facing scalar type
    (`str`, `int`, …) are kept — they correspond to FastAPI path/query
    parameters. Injected dependencies (`db`, `session`, `request`,
    unannotated parameters or `Depends(...)`) are ignored to limit false
    positives.
    """
    if not is_route_handler(fn):
        return ()
    params: List[str] = []
    args = fn.ast_def.args
    for arg in args.args:
        if arg.arg in ("self", "cls"):
            continue
        ann = arg.annotation
        ann_name = None
        if isinstance(ann, ast.Name):
            ann_name = ann.id
        elif isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
            # Optional[str], List[int]… — we look at the container AND, for
            # simplicity, accept if the container itself is scalar
            # (rare); otherwise the current scalar argument is inspected.
            ann_name = ann.value.id
        if ann_name in _USER_PARAM_SCALARS:
            params.append(arg.arg)
    return tuple(params)


def function_to_sub_module(fn: FunctionInfo) -> ast.Module:
    """Build a fake ast.Module from a function's body.

    Lets build_cfg + analyze be reused on the function body as if it were
    a standalone module.

    Spec §8.1 — function summaries via sub-analysis.
    """
    body_stmts: List[ast.stmt] = list(fn.ast_def.body)
    sub_module = ast.Module(body=body_stmts, type_ignores=[])
    return sub_module


# ============================================================================
# Function summaries — interprocedural propagation (Component 2)
# ============================================================================

@dataclass
class FunctionSummary:
    """"Summary record" of a function's taint behavior.

    Describes, for a given function, how taint flows through its calls:

    Attributes:
        name: name (dotted for methods).
        param_names: positional parameters (excluding self/cls).
        return_tainted_uncond: True if an internal source reaches the
            `return` regardless of arguments (e.g. `return request.GET[...]`).
        return_kind: kind of the unconditional return taint (http…).
        return_taint_params: indices of params whose taint reaches the return.
        sink_param_findings: for each param index reaching a sink, a
            Finding template (to be re-emitted at the call site).
    """
    name: str
    param_names: Tuple[str, ...] = field(default_factory=tuple)
    return_tainted_uncond: bool = False
    return_kind: Optional[str] = None
    return_taint_params: frozenset = field(default_factory=frozenset)
    sink_param_findings: Dict[int, object] = field(default_factory=dict)


# Anti-FP — source kinds that do NOT propagate through an interprocedural
# unconditional return. CLI/stdin/env input propagated across calls hits too
# many falsely matched sinks (e.g. `input()` → `re.search` mistaken for an
# LDAP sink); these sources are still detected intra-procedurally but do not
# cross a function return. Web/network/file sources, on the other hand, do
# propagate.
_INTERPROC_BLOCKED_RETURN_KINDS = frozenset({"stdin", "cli", "env"})


def _rule_source_kinds(specs) -> frozenset:
    """Return the union of the rule's source kinds (to seed a param
    realistically: a real argument would carry one of these kinds)."""
    kinds = set()
    for s in getattr(specs, "sources", ()):
        k = getattr(s, "kind", None)
        if k:
            kinds.add(k)
    return frozenset(kinds) or frozenset({"http"})


def _return_line_source_taint(lineno, source_lines, specs):
    """Return the taint of a source detected only by a line regex on the
    `return` line (e.g. `return request.GET[...]`); CLEAN if none match.

    Extracted from `return_taint` to flatten its nesting."""
    from sca.dataflow.lattice import CLEAN, SourceInfo, Tainted

    if not source_lines or not (0 < lineno <= len(source_lines)):
        return CLEAN
    line_text = source_lines[lineno - 1]
    for src in getattr(specs, "sources", ()):
        rx = getattr(src, "raw_regex", None)
        if rx is not None and rx.search(line_text):
            return Tainted(
                kinds=frozenset({src.kind}),
                source=SourceInfo(line=lineno, expr=line_text.strip(), kind=src.kind),
            )
    return CLEAN


def return_taint(cfg, result, specs, language, source_lines):
    """Return the taint of the function's return value = join of the taints
    evaluated at each `Return` statement, in the dataflow state computed
    at that point.

    Replays the statements of each node from its `state_in` (to account
    for assignments preceding the return within the same node).

    Public (no `_` prefix): fully language-neutral (parameterized by
    `language`, only consumes the generic IR) — reused as-is by
    `sca/dataflow/java_summary.py` (no duplication, see
    `docs/ARCHITECTURE.md` § multi-language extension of the dataflow
    engine)."""
    from sca.dataflow.ir import Return
    from sca.dataflow.lattice import CLEAN, join
    from sca.dataflow.transfer import eval_rhs, transfer_stmt
    from sca.dataflow.worklist import lower_node_to_ir

    total = CLEAN
    for nid, node in cfg.nodes.items():
        ir = lower_node_to_ir(node, language)
        state = dict(result.state_in.get(nid, {}))
        scratch: List = []
        for stmt in ir:
            if not isinstance(stmt, Return):
                state = transfer_stmt(stmt, state, specs, scratch, source_lines)
                continue
            lineno = getattr(stmt, "lineno", 0)
            if stmt.value is not None:
                total = join(total, eval_rhs(stmt.value, state, specs, scratch, lineno))
            # The return value may be a non-call source detected
            # only by a line regex (e.g. `return request.GET[...]`).
            total = join(total, _return_line_source_taint(lineno, source_lines, specs))
    return total


def compute_summary_from_cfg(cfg, name: str, params: Tuple[str, ...], specs,
                             language: str, source_lines=None,
                             fn_lineno: int = 0) -> FunctionSummary:
    """Language-neutral core of the summary computation (probing sub-analyses).

    Factored out of `compute_summary` to be reused as-is by
    `sca/dataflow/java_summary.py::compute_java_summary` — no algorithm
    duplication, only the CFG construction differs per language (see
    `docs/ARCHITECTURE.md` § multi-language extension of the dataflow
    engine).

    Method:
      - "all params clean" pass: a tainted return ⇒ an internal source
        reaches the return (`return_tainted_uncond`).
      - one pass per parameter, that param alone seeded tainted: a new
        sink triggered ⇒ the param reaches a sink; a tainted return ⇒
        the param contributes to the return value.
    """
    from sca.dataflow.lattice import (
        SourceInfo, Tainted, empty_state, is_tainted, state_set,
    )
    from sca.dataflow.worklist import analyze

    probe_kinds = _rule_source_kinds(specs)

    # Base pass: no param tainted.
    base = analyze(cfg, specs, language=language, source_lines=source_lines)
    base_keys = {(f.rule_id, f.line, f.source_line) for f in base.findings}
    ret_base = return_taint(cfg, base, specs, language, source_lines)
    uncond = is_tainted(ret_base)
    ret_kind = None
    if isinstance(ret_base, Tainted):
        ret_kind = ret_base.source.kind if ret_base.source else None
    # Anti-FP: an internal CLI/stdin/env source does not taint the return
    # inter-procedurally (cf. _INTERPROC_BLOCKED_RETURN_KINDS).
    if ret_kind in _INTERPROC_BLOCKED_RETURN_KINDS:
        uncond = False

    return_params = set()
    sink_findings: Dict[int, object] = {}
    for i, pname in enumerate(params):
        init = state_set(empty_state(), pname, Tainted(
            kinds=probe_kinds,
            source=SourceInfo(line=fn_lineno, expr=f"param:{pname}",
                              kind=next(iter(probe_kinds))),
        ))
        res = analyze(cfg, specs, initial_state=init, language=language,
                      source_lines=source_lines)
        new = [f for f in res.findings
               if (f.rule_id, f.line, f.source_line) not in base_keys]
        if new:
            sink_findings[i] = new[0]
        ret_i = return_taint(cfg, res, specs, language, source_lines)
        if is_tainted(ret_i) and not uncond:
            return_params.add(i)

    return FunctionSummary(
        name=name,
        param_names=params,
        return_tainted_uncond=uncond,
        return_kind=ret_kind,
        return_taint_params=frozenset(return_params),
        sink_param_findings=sink_findings,
    )


def compute_summary(fn: FunctionInfo, specs, language: str = "python",
                    source_lines=None) -> FunctionSummary:
    """Compute the summary of a Python function (probing sub-analyses).

    Builds the CFG from `fn.ast_def` then delegates to
    `compute_summary_from_cfg` (language-neutral).
    """
    from sca.dataflow.cfg import build_cfg

    params = tuple(p for p in fn.param_names if p not in ("self", "cls"))
    cfg = build_cfg(function_to_sub_module(fn))
    return compute_summary_from_cfg(
        cfg, fn.name, params, specs, language, source_lines,
        fn_lineno=getattr(fn.ast_def, "lineno", 0),
    )


def compute_file_summaries(tree, specs, language: str = "python",
                           source_lines=None) -> Dict[str, "FunctionSummary"]:
    """Compute the summaries of all functions in a module.

    Helper shared between `run_taint_rule` (intra-file pass) and the
    inter-file pre-pass (component 3): avoids recomputing summaries
    twice. A function whose sub-analysis crashes is simply omitted
    (robustness — it does not interrupt the others).
    """
    summaries: Dict[str, FunctionSummary] = {}
    for fn in collect_functions(tree):
        try:
            summaries[fn.name] = compute_summary(
                fn, specs, language=language, source_lines=source_lines,
            )
        except Exception:  # robustness: a broken function doesn't stop the rest
            continue
    return summaries
