"""Algorithme worklist du moteur dataflow SCA.

Clean-room implementation based on sca/docs/dataflow-spec.md §6.
Algorithms inspired by:
  - Nielson, Nielson, Hankin — Principles of Program Analysis (Springer 2005, ch. 2.5)
  - Kildall, G. — A Unified Approach to Global Program Optimization (POPL 1973)

Aucune lecture du code OCaml de semgrep n'a été faite pour rédiger ce module.

Vue d'ensemble :
    L'analyse dataflow calcule un point fixe sur le CFG :
      - σ_in[n] = ⊔ { σ_out[p] : p ∈ pred(n) }
      - σ_out[n] = transfer_node(n, σ_in[n])

    Le worklist (deque FIFO) maintient les nœuds à recalculer jusqu'à
    stabilité. Le widening force la convergence sur les cycles.
"""
from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from sca.dataflow.cfg import CFG, CFGNode, EdgeLabel, NodeKind
from sca.dataflow.const_eval import (
    ConstState,
    apply_list_mutation,
    const_state_equal,
    empty_const_state,
    eval_const,
    invalidate_var,
    join_const_states,
    simplify_stmt,
    update_const_on_assign,
)
from sca.dataflow.ir import (
    Assign,
    AttrRef,
    Branch,
    Call,
    IRStmt,
    canon_rhs,
)
from sca.dataflow.lattice import (
    State,
    empty_state,
    pretty_state,
    state_equal,
    state_join,
    state_widen,
)
from sca.dataflow.transfer import (
    Finding,
    RuleSpecs,
    transfer_stmt,
    transfer_stmts,
)
from sca.parsers.python_to_ir import lower_expr as lower_py_expr
from sca.parsers.python_to_ir import lower_stmt as lower_py_stmt
from sca.parsers.python_to_ir import lower_stmts as lower_py_stmts


# ============================================================================
# Configuration
# ============================================================================

MAX_LOOP_ITER = 3
"""Spec §4.3 : seuil de widening pour les boucles."""

MAX_WORKLIST_ITER = 10_000
"""Garde-fou anti-boucle infinie. En pratique, le widening assure la convergence
en quelques itérations, mais on borne pour éviter les pathologies."""


# ============================================================================
# Analysis result
# ============================================================================

@dataclass
class AnalysisResult:
    """Result of the dataflow analysis."""
    state_in: Dict[int, State] = field(default_factory=dict)
    state_out: Dict[int, State] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    iterations: int = 0


# ============================================================================
# Lowering a CFG node to IR
# ============================================================================

def lower_node_to_ir(node: CFGNode, language: str = "python") -> List[IRStmt]:
    """Lower a CFG node's statements to IR (dispatched by language).

    For BASIC: lower the native statements (Python ast.stmt / Java
    tree-sitter Node). For BRANCH / LOOP: lower the condition. For
    FINALLY / RAISE_SITE: lower the carried statements. For others
    (Entry, Exit, Join, TryEntry, Handler): [].
    """
    if language == "python":
        return _lower_node_to_ir_python(node)
    return []


def _lower_node_to_ir_python(node: CFGNode) -> List[IRStmt]:
    """Lower a Python CFG node's statements/condition to IR."""
    if node.kind == NodeKind.BASIC:
        if not node.statements:
            return []
        # Filter out any non-ast statements (safety)
        ast_stmts = [s for s in node.statements if isinstance(s, ast.stmt)]
        return lower_py_stmts(ast_stmts)

    if node.kind in (NodeKind.BRANCH, NodeKind.LOOP):
        if node.condition is not None and isinstance(node.condition, ast.expr):
            # For a LOOP from `for target in iter:`, emit the synthetic
            # assign `target := iter` (otherwise iter's taint does not
            # propagate to target — see the for/break bug).
            if (node.kind == NodeKind.LOOP and node.for_target is not None
                    and isinstance(node.for_target, ast.expr)):
                synth_assign = ast.Assign(
                    targets=[node.for_target],
                    value=node.condition,
                )
                ast.copy_location(synth_assign, node.condition)
                return lower_py_stmt(synth_assign)
            # Lower the condition as an expression and emit a Branch.
            # Strategy: wrap it in an Expr statement to reuse lower_stmt.
            expr_stmt = ast.Expr(value=node.condition)
            # Copy lineno/col_offset for pretty-printing
            ast.copy_location(expr_stmt, node.condition)
            ir = lower_py_stmt(expr_stmt)
            # ir contains Assign nodes (for sub-expressions) possibly
            # followed by a Call if the condition was a direct call.
            # We keep all the statements (side effects) and add a
            # synthetic Branch on the last produced temporary, if applicable.
            return ir

    if node.kind == NodeKind.FINALLY:
        if node.statements:
            ast_stmts = [s for s in node.statements if isinstance(s, ast.stmt)]
            return lower_py_stmts(ast_stmts)

    if node.kind == NodeKind.RAISE_SITE:
        if node.statements:
            ast_stmts = [s for s in node.statements if isinstance(s, ast.stmt)]
            return lower_py_stmts(ast_stmts)

    return []


# ============================================================================
# Phase 9 — Constant propagation and dead-edge marking
# ============================================================================

def _simplify_and_apply_stmts(
    stmts: List[IRStmt], const_state: ConstState,
) -> Tuple[List[IRStmt], ConstState]:
    """Propagate `const_state` through a sequence of IR statements and,
    along the way, simplify evaluable `IfExp` nodes (Phase 9).

    For each statement:
      1. `simplify_stmt(stmt, cs)` recursively rewrites `IfExp` nodes
         whose condition is known in `cs`, or returns `stmt` unchanged.
      2. The simplified statement updates `cs`:
         - `Assign` → updates the target value if the new RHS is
           evaluable.
         - `Call` on a known receiver → invalidates the receiver's value.
         - Others → no effect on `cs`.

    Returns `(simplified_stmts, final_cs)`. If no statement changed, the
    returned list is the original list (identity preserved to allow
    fixpoint detection in `_compute_dead_edges`).
    """
    cs = const_state
    new_stmts: List[IRStmt] = []
    any_changed = False
    for stmt in stmts:
        simplified = simplify_stmt(stmt, cs)
        if simplified is not stmt:
            any_changed = True
        new_stmts.append(simplified)
        if isinstance(simplified, Assign):
            cs = update_const_on_assign(cs, simplified.lhs, simplified.rhs)
            continue
        if isinstance(simplified, Call) and isinstance(simplified.callee, AttrRef):
            base_key = canon_rhs(simplified.callee.base)
            if base_key and not base_key.startswith("<") and base_key in cs:
                # Phase 9.quater — first attempt to simulate the operation
                # on a list tracked as Const(tuple). If the simulation
                # succeeds (`append/pop/insert/extend` with known args),
                # keep the new value. Otherwise, conservative invalidation.
                method = simplified.callee.attr
                simulated = apply_list_mutation(cs, base_key, method, simplified.args)
                if simulated is not None:
                    cs = simulated
                else:
                    cs = invalidate_var(cs, base_key)
    return (new_stmts if any_changed else stmts), cs


def _eval_branch_condition_from_node(
    node: CFGNode, stmts: List[IRStmt], const_state: ConstState,
    language: str = "python",
) -> Optional[bool]:
    """Attempt to evaluate a BRANCH node's condition at compile time.

    Two possible sources depending on how the node was built:
      - `node.condition` (Python ast.expr / Java tree-sitter Node): the
        standard `if`/`while` case — the condition is carried by the CFG
        node (see `lower_node_to_ir`).
      - An explicitly emitted IR `Branch` (the `match/case` lowering case,
        which inserts a Branch into a BasicBlock's linear flow).

    Returns True/False/None depending on whether the condition is known.
    `eval_const` (const_eval.py) is 100% language-neutral (only operates
    on the generic IR) — only the LOWERING of `node.condition` differs
    per language, see `lower_java_expr` below.
    """
    if node.condition is not None:
        if language == "python" and isinstance(node.condition, ast.expr):
            try:
                rhs = lower_py_expr(node.condition)
            except Exception:
                return None
            v = eval_const(rhs, const_state)
            if v is not None:
                return bool(v.value)
            return None
    for stmt in stmts:
        if isinstance(stmt, Branch):
            v = eval_const(stmt.condition, const_state)
            if v is not None:
                return bool(v.value)
            return None
    return None


def _compute_dead_edges(
    cfg: CFG, node_ir: Dict[int, List[IRStmt]], language: str = "python",
) -> Set[Tuple[int, int]]:
    """Compute the set of `(src, dst)` edges dead by constant propagation
    (Phase 9).

    Algorithm: a separate fixpoint over `ConstState`. On each visit of a
    `BRANCH` node, its condition is evaluated in the computed
    `const_out`; if known, the opposite TRUE (or FALSE) edge is marked
    dead. Dead edges are excluded from the computation of
    `const_in[succ]`.

    `LOOP` nodes are never cut (the loop condition may change between
    runtime iterations — over-cautious by design).
    """
    const_in: Dict[int, ConstState] = {nid: empty_const_state() for nid in cfg.nodes}
    const_out: Dict[int, ConstState] = {nid: empty_const_state() for nid in cfg.nodes}
    dead_edges: Set[Tuple[int, int]] = set()

    iter_count: Dict[int, int] = {nid: 0 for nid in cfg.nodes}
    worklist: deque[int] = deque([cfg.entry])
    in_worklist = {cfg.entry}

    iterations = 0
    while worklist:
        if iterations > MAX_WORKLIST_ITER:
            break
        iterations += 1

        n = worklist.popleft()
        in_worklist.discard(n)

        # Recompute const_in[n], ignoring known dead edges.
        if n != cfg.entry:
            preds = cfg.predecessor_ids(n)
            live_preds = [p for p in preds if (p, n) not in dead_edges]
            if live_preds:
                new_in: Optional[ConstState] = None
                for p in live_preds:
                    if new_in is None:
                        new_in = dict(const_out[p])
                    else:
                        new_in = join_const_states(new_in, const_out[p])
                const_in[n] = new_in or empty_const_state()
            # If no pred is live: keep const_in[n] as is (the node
            # effectively becomes orphaned and will be pruned by the taint analysis).

        new_stmts, new_out = _simplify_and_apply_stmts(node_ir[n], const_in[n])
        # Phase 9 — update `node_ir[n]` with the simplified version
        # (evaluated IfExp replaced by the taken branch). The main taint
        # analysis reuses this modified `node_ir`.
        if new_stmts is not node_ir[n]:
            node_ir[n] = new_stmts
        iter_count[n] += 1

        # Simple widening: on a LOOP node, after MAX_LOOP_ITER passes
        # that don't converge, clear the const_state (over-caution).
        if (
            iter_count[n] > MAX_LOOP_ITER
            and cfg.nodes[n].kind == NodeKind.LOOP
            and not const_state_equal(new_out, const_out[n])
        ):
            new_out = empty_const_state()

        node = cfg.nodes[n]
        new_dead_from_n: Set[Tuple[int, int]] = set()
        if node.kind == NodeKind.BRANCH:
            cond_val = _eval_branch_condition_from_node(node, node_ir[n], new_out, language)
            if cond_val is True:
                for edge in cfg.successors(n):
                    if edge.label == EdgeLabel.FALSE:
                        new_dead_from_n.add((n, edge.dst))
            elif cond_val is False:
                for edge in cfg.successors(n):
                    if edge.label == EdgeLabel.TRUE:
                        new_dead_from_n.add((n, edge.dst))

        prev_dead_from_n = {e for e in dead_edges if e[0] == n}
        dead_changed = new_dead_from_n != prev_dead_from_n
        first_pass = iter_count[n] == 1

        if first_pass or not const_state_equal(new_out, const_out[n]) or dead_changed:
            const_out[n] = new_out
            # Update dead_edges for this node.
            if dead_changed:
                dead_edges = {e for e in dead_edges if e[0] != n} | new_dead_from_n
            for succ_id in cfg.successor_ids(n):
                if (n, succ_id) in dead_edges:
                    continue
                if succ_id not in in_worklist:
                    worklist.append(succ_id)
                    in_worklist.add(succ_id)

    return dead_edges


# ============================================================================
# Algorithme worklist (spec §6)
# ============================================================================

def analyze(
    cfg: CFG,
    specs: RuleSpecs,
    initial_state: Optional[State] = None,
    language: str = "python",
    source_lines: Optional[List[str]] = None,
) -> AnalysisResult:
    """Run the dataflow analysis on a CFG with a taint rule.

    Spec §6. Returns σ_in, σ_out and the list of emitted findings.

    Args:
        cfg: Control Flow Graph.
        specs: taint rule (sources/sinks/sanitizers/passthroughs).
        initial_state: entry state (default: empty = clean everywhere).
        language: for lowering (phase 8).

    Returns:
        AnalysisResult with state_in, state_out and findings.
    """
    if initial_state is None:
        initial_state = empty_state()

    # Lower everything once, up front
    node_ir: Dict[int, List[IRStmt]] = {}
    for nid, node in cfg.nodes.items():
        node_ir[nid] = lower_node_to_ir(node, language)

    # Phase 9 — pre-pass: constant propagation to identify dead edges
    # (branches whose condition is known at compile time). Dead edges
    # are excluded from the σ_in[n] computation below.
    dead_edges = _compute_dead_edges(cfg, node_ir, language)

    # Initialization: state_in[entry] = initial_state, others = empty
    state_in: Dict[int, State] = {nid: empty_state() for nid in cfg.nodes}
    state_out: Dict[int, State] = {nid: empty_state() for nid in cfg.nodes}
    state_in[cfg.entry] = dict(initial_state)

    # Findings are accumulated over the whole analysis, deduplicated at the end.
    raw_findings: List[Finding] = []

    # Per-node iteration counter (for widening on loops)
    iter_count: Dict[int, int] = {nid: 0 for nid in cfg.nodes}

    # Identify the loop heads for widening
    loop_heads = {
        nid for nid, node in cfg.nodes.items() if node.kind == NodeKind.LOOP
    }

    # Worklist FIFO (deque)
    worklist: deque[int] = deque([cfg.entry])
    in_worklist = {cfg.entry}

    iterations = 0
    while worklist:
        if iterations > MAX_WORKLIST_ITER:
            # Pathological case: stop (widening should have converged)
            break
        iterations += 1

        n = worklist.popleft()
        in_worklist.discard(n)

        # Recompute state_in[n] = ⊔ state_out[p] for p ∈ pred(n).
        # Phase 9 — we ignore preds whose edge to n has been marked dead
        # (branch condition evaluated at compile time).
        if n != cfg.entry:
            preds = cfg.predecessor_ids(n)
            live_preds = [p for p in preds if (p, n) not in dead_edges]
            if live_preds:
                new_in = empty_state()
                for p in live_preds:
                    new_in = state_join(new_in, state_out[p])
                state_in[n] = new_in

        # Apply the node's transfer function
        # We collect findings PER ITERATION so they can be eliminated
        # if they are emitted on every pass (the final set is the dedup).
        local_findings: List[Finding] = []
        new_out = transfer_stmts(node_ir[n], state_in[n], specs, local_findings, source_lines)

        iter_count[n] += 1
        if iter_count[n] > MAX_LOOP_ITER and n in loop_heads:
            new_out = state_widen(state_out[n], new_out, iter_count[n], MAX_LOOP_ITER)

        # Propagate on change OR if this is the first pass over this node
        # (typical case: entry/exit whose state_out is initially empty).
        # Phase 9 — we do not push successors past a dead edge.
        first_pass = iter_count[n] == 1
        if first_pass or not state_equal(new_out, state_out[n]):
            state_out[n] = new_out
            for succ_id in cfg.successor_ids(n):
                if (n, succ_id) in dead_edges:
                    continue
                if succ_id not in in_worklist:
                    worklist.append(succ_id)
                    in_worklist.add(succ_id)

        # Add the findings (deduplicated at the end)
        raw_findings.extend(local_findings)

    # Dedup findings — key: (rule_id, line, source_line).
    # `sink_text` excluded because it varies between dotted (callee)
    # matching and hybrid regex (full-line) matching (spec §10bis).
    seen = set()
    deduped: List[Finding] = []
    for f in raw_findings:
        key = (f.rule_id, f.line, f.source_line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    return AnalysisResult(
        state_in=state_in,
        state_out=state_out,
        findings=deduped,
        iterations=iterations,
    )


# ============================================================================
# Public helper: analyze a Python source
# ============================================================================

def analyze_module_source(source: str, specs: RuleSpecs) -> AnalysisResult:
    """Helper: analyze a Python source fragment directly.

    Convenient for tests: `analyze_module_source(src, specs)`.
    For production usage, use `analyze(cfg, specs)`.
    """
    from sca.dataflow.cfg import build_cfg
    cfg = build_cfg(ast.parse(source))
    return analyze(cfg, specs)
