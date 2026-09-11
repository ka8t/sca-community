"""Control Flow Graph (CFG) builder for Python.

Clean-room implementation based on sca/docs/dataflow-spec.md §2.
Algorithms inspired by:
  - Nielson, Nielson, Hankin — Principles of Program Analysis (Springer 2005, ch. 2)
  - Aho-Sethi-Ullman — Compilers: Principles, Techniques and Tools (dragon book, ch. 9)

No semgrep OCaml source was read to write this module.

Overview:
    - A CFG is a quadruple (N, E, entry, exit) — see spec §2.1.
    - Nodes represent basic blocks or control points (Branch, Join, Loop,
      TryEntry, Handler, Finally).
    - Edges are labeled (flow, true, false, back, except, escape).
    - Construction is done via recursive traversal of the Python stdlib
      `ast` AST.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ============================================================================
# Enumerations (spec §2.2 and §2.3)
# ============================================================================

class NodeKind(Enum):
    """Kind of a CFG node. See spec §2.2."""

    ENTRY = "entry"           # Entry point of a unit
    EXIT = "exit"             # Unique exit point
    BASIC = "basic"           # Sequence of linear instructions
    BRANCH = "branch"         # Branch head (if, match)
    JOIN = "join"             # Rendezvous point after a branch
    LOOP = "loop"             # Loop head (while, for)
    TRY_ENTRY = "try_entry"   # Entry of a try block
    HANDLER = "handler"       # Except block
    FINALLY = "finally"       # Finally block
    RAISE_SITE = "raise_site" # Raises an exception


class EdgeLabel(Enum):
    """Label of a CFG edge. See spec §2.3."""

    FLOW = "flow"        # Normal sequential transition
    TRUE = "true"        # Condition evaluated true
    FALSE = "false"      # Condition evaluated false
    BACK = "back"        # Return to the loop head
    EXCEPT = "except"    # Transition to a handler (intercepted raise)
    ESCAPE = "escape"    # Uncaught exceptional exit toward exit


# ============================================================================
# Data structures
# ============================================================================

@dataclass
class CFGNode:
    """Node of the CFG.

    Depending on `kind`, some fields are used or not:
      - BASIC: `statements` is non-empty.
      - BRANCH, LOOP: `condition` is non-None.
      - HANDLER: `handler_type` (ast expr) possibly non-None,
                 `handler_name` (str) if `except X as name`.
      - others: all fields empty.
    """

    id: int
    kind: NodeKind
    statements: List[ast.stmt] = field(default_factory=list)
    condition: Optional[ast.expr] = None
    handler_type: Optional[ast.expr] = None
    handler_name: Optional[str] = None
    label: str = ""                       # symbolic name for debugging (e.g. "while_3")
    # for-loop: target of the iteration (`for <target> in <condition>:`).
    # Lets lower_node_to_ir emit `target := iter`.
    for_target: Optional[ast.expr] = None


@dataclass
class CFGEdge:
    """Directed, labeled edge."""

    src: int
    dst: int
    label: EdgeLabel

    def __hash__(self) -> int:
        """Hash the edge by its (src, dst, label) identity."""
        return hash((self.src, self.dst, self.label))


@dataclass
class CFG:
    """Control Flow Graph.

    Attributes:
        nodes: dict id → CFGNode.
        edges: list of edges (logically a set, list for deterministic order).
        entry: id of the unique Entry node.
        exit: id of the unique Exit node.
    """

    nodes: Dict[int, CFGNode] = field(default_factory=dict)
    edges: List[CFGEdge] = field(default_factory=list)
    entry: int = -1
    exit: int = -1
    _next_id: int = 0

    # --- mutations (used by the builder) ---

    def add_node(self, kind: NodeKind, **kwargs) -> int:
        """Create a new node and return its id."""
        nid = self._next_id
        self._next_id += 1
        self.nodes[nid] = CFGNode(id=nid, kind=kind, **kwargs)
        return nid

    def add_edge(self, src: int, dst: int, label: EdgeLabel) -> None:
        """Add an edge, deduplicating against any existing (src, dst, label) triple."""
        edge = CFGEdge(src=src, dst=dst, label=label)
        # Avoid duplicates (by (src, dst, label))
        for existing in self.edges:
            if existing.src == src and existing.dst == dst and existing.label == label:
                return
        self.edges.append(edge)

    # --- queries ---

    def successors(self, node_id: int) -> List[CFGEdge]:
        """Return the outgoing edges of a node."""
        return [e for e in self.edges if e.src == node_id]

    def predecessors(self, node_id: int) -> List[CFGEdge]:
        """Return the incoming edges of a node."""
        return [e for e in self.edges if e.dst == node_id]

    def successor_ids(self, node_id: int) -> List[int]:
        """Return the ids of the successor nodes reachable via outgoing edges."""
        return [e.dst for e in self.successors(node_id)]

    def predecessor_ids(self, node_id: int) -> List[int]:
        """Return the ids of the predecessor nodes reachable via incoming edges."""
        return [e.src for e in self.predecessors(node_id)]


# ============================================================================
# Cursor — "unreachable code" sentinel
# ============================================================================

UNREACHABLE = -1
"""`cursor` value indicating that the next statement is unreachable
(after Return, Raise, or break/continue, which consumed the cursor)."""


# ============================================================================
# CFG Builder
# ============================================================================

class CFGBuilder:
    """Build a CFG from a Python AST.

    Usage:
        builder = CFGBuilder()
        cfg = builder.build(ast.parse(source_code))

    Internals:
        cursor: id of the "current" node from which to add the next flow edge.
                UNREACHABLE = dead code.
        loop_stack: stack of (loop_head_id, exit_join_id) for break/continue.
        try_stack: stack of lists of active handler ids, for raise.
    """

    def __init__(self) -> None:
        """Initialize an empty CFG and the loop/try tracking stacks."""
        self.cfg = CFG()
        self.loop_stack: List[Tuple[int, int]] = []
        self.try_stack: List[List[int]] = []

    # ------------------------------------------------------------------ public

    def build(self, module: ast.Module) -> CFG:
        """Build and return the pruned CFG for a Python module."""
        self.cfg.entry = self.cfg.add_node(NodeKind.ENTRY, label="entry")
        self.cfg.exit = self.cfg.add_node(NodeKind.EXIT, label="exit")
        cursor = self.cfg.entry
        cursor = self._visit_stmts(module.body, cursor)
        if cursor != UNREACHABLE:
            self.cfg.add_edge(cursor, self.cfg.exit, EdgeLabel.FLOW)
        prune_unreachable(self.cfg)
        return self.cfg

    # --------------------------------------------------------------- visitors

    def _visit_stmts(self, stmts: List[ast.stmt], cursor: int) -> int:
        """Visit a list of statements in sequence, returning the final cursor."""
        for stmt in stmts:
            cursor = self._visit_stmt(stmt, cursor)
            if cursor == UNREACHABLE:
                break  # remaining statements unreachable
        return cursor

    def _visit_stmt(self, stmt: ast.stmt, cursor: int) -> int:
        """Dispatch to the visitor method matching the statement's AST type."""
        method_name = f"_visit_{type(stmt).__name__}"
        method = getattr(self, method_name, self._visit_default)
        return method(stmt, cursor)

    def _visit_default(self, stmt: ast.stmt, cursor: int) -> int:
        """Fallback for linear statements: append to the current BasicBlock."""
        return self._append_to_basic(stmt, cursor)

    # ------------------------------------------------------------- basic block

    def _append_to_basic(self, stmt: ast.stmt, cursor: int) -> int:
        """Append a statement to a BasicBlock, extending or creating one.

        If the cursor already points at a BasicBlock with no successor yet,
        this statement extends that block in place. Otherwise a new
        BasicBlock is created and linked from the cursor via a FLOW edge.
        """
        if cursor == UNREACHABLE:
            return UNREACHABLE

        node = self.cfg.nodes[cursor]
        # Can only extend a BasicBlock that has no successor yet
        if (
            node.kind == NodeKind.BASIC
            and not self.cfg.successors(cursor)
        ):
            node.statements.append(stmt)
            return cursor

        # Otherwise, new BasicBlock
        bb = self.cfg.add_node(NodeKind.BASIC, statements=[stmt], label=f"bb_{len(self.cfg.nodes)}")
        self.cfg.add_edge(cursor, bb, EdgeLabel.FLOW)
        return bb

    # ------------------------------------------------------------- statements

    # Simple (linear) statements — use _visit_default

    _visit_Assign = _visit_default
    _visit_AugAssign = _visit_default
    _visit_AnnAssign = _visit_default
    _visit_Expr = _visit_default
    _visit_Pass = _visit_default
    _visit_Import = _visit_default
    _visit_ImportFrom = _visit_default
    _visit_Global = _visit_default
    _visit_Nonlocal = _visit_default
    _visit_Delete = _visit_default
    _visit_Assert = _visit_default          # potential raise ignored in phase 1
    _visit_FunctionDef = _visit_default     # opaque block (SCA-3 extended choice)
    _visit_AsyncFunctionDef = _visit_default
    _visit_ClassDef = _visit_default

    # Return — flow to exit, cursor consumed

    def _visit_Return(self, stmt: ast.Return, cursor: int) -> int:
        """Emit a BasicBlock for the return and link it directly to exit."""
        bb = self.cfg.add_node(
            NodeKind.BASIC, statements=[stmt], label=f"return_{stmt.lineno}"
        )
        self.cfg.add_edge(cursor, bb, EdgeLabel.FLOW)
        self.cfg.add_edge(bb, self.cfg.exit, EdgeLabel.FLOW)
        return UNREACHABLE

    # Raise — flow to the nearest handler, or escape to exit

    def _visit_Raise(self, stmt: ast.Raise, cursor: int) -> int:
        """Emit a RAISE_SITE node and link it to the nearest handler, or escape to exit."""
        rs = self.cfg.add_node(
            NodeKind.RAISE_SITE, statements=[stmt], label=f"raise_{stmt.lineno}"
        )
        self.cfg.add_edge(cursor, rs, EdgeLabel.FLOW)
        # Try to reach the nearest handler (try_stack)
        if self.try_stack and self.try_stack[-1]:
            for handler_id in self.try_stack[-1]:
                self.cfg.add_edge(rs, handler_id, EdgeLabel.EXCEPT)
        else:
            self.cfg.add_edge(rs, self.cfg.exit, EdgeLabel.ESCAPE)
        return UNREACHABLE

    # Break — direct flow to the current loop's exit_join, cursor consumed

    def _visit_Break(self, stmt: ast.Break, cursor: int) -> int:
        """Link the cursor to the exit join of the innermost enclosing loop."""
        if not self.loop_stack:
            # Source code error, but don't crash: noop
            return cursor
        _loop_head, exit_join = self.loop_stack[-1]
        self.cfg.add_edge(cursor, exit_join, EdgeLabel.FLOW)
        return UNREACHABLE

    # Continue — direct flow to the loop head (back edge), cursor consumed

    def _visit_Continue(self, stmt: ast.Continue, cursor: int) -> int:
        """Link the cursor back to the head of the innermost enclosing loop."""
        if not self.loop_stack:
            return cursor
        loop_head, _exit_join = self.loop_stack[-1]
        self.cfg.add_edge(cursor, loop_head, EdgeLabel.BACK)
        return UNREACHABLE

    # If / elif / else

    def _visit_If(self, stmt: ast.If, cursor: int) -> int:
        """Build a BRANCH node with true/false arms and a join for `if`/`elif`/`else`."""
        branch = self.cfg.add_node(
            NodeKind.BRANCH, condition=stmt.test, label=f"if_{stmt.lineno}"
        )
        self.cfg.add_edge(cursor, branch, EdgeLabel.FLOW)

        # True branch
        t_cursor = branch
        # To materialize the TRUE edge, we insert an empty BB or attach to
        # the first instruction of the body. We use an intermediate Join
        # for simplicity: the first edge after the Branch carries true/false.
        true_seed = self.cfg.add_node(NodeKind.JOIN, label=f"if_true_{stmt.lineno}")
        self.cfg.add_edge(branch, true_seed, EdgeLabel.TRUE)
        t_end = self._visit_stmts(stmt.body, true_seed)

        # False branch (orelse, which may contain an elif or an else)
        false_seed = self.cfg.add_node(NodeKind.JOIN, label=f"if_false_{stmt.lineno}")
        self.cfg.add_edge(branch, false_seed, EdgeLabel.FALSE)
        f_end = self._visit_stmts(stmt.orelse, false_seed)

        # Join
        join = self.cfg.add_node(NodeKind.JOIN, label=f"if_join_{stmt.lineno}")
        if t_end != UNREACHABLE:
            self.cfg.add_edge(t_end, join, EdgeLabel.FLOW)
        if f_end != UNREACHABLE:
            self.cfg.add_edge(f_end, join, EdgeLabel.FLOW)

        # If both branches are unreachable, the join itself is
        # unreachable and will be pruned — we still return its id (will be pruned).
        if t_end == UNREACHABLE and f_end == UNREACHABLE:
            return UNREACHABLE
        return join

    # While

    def _visit_While(self, stmt: ast.While, cursor: int) -> int:
        """Build a LOOP node for `while`, wiring body, back-edge, and optional `else`."""
        loop_head = self.cfg.add_node(
            NodeKind.LOOP, condition=stmt.test, label=f"while_{stmt.lineno}"
        )
        self.cfg.add_edge(cursor, loop_head, EdgeLabel.FLOW)

        exit_join = self.cfg.add_node(NodeKind.JOIN, label=f"while_end_{stmt.lineno}")

        # Push for break/continue
        self.loop_stack.append((loop_head, exit_join))

        # Body (true edge from loop_head)
        body_seed = self.cfg.add_node(NodeKind.JOIN, label=f"while_body_{stmt.lineno}")
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel.TRUE)
        body_end = self._visit_stmts(stmt.body, body_seed)
        if body_end != UNREACHABLE:
            self.cfg.add_edge(body_end, loop_head, EdgeLabel.BACK)

        # Else (Python while/else): executed if the loop ends without break
        if stmt.orelse:
            else_seed = self.cfg.add_node(
                NodeKind.JOIN, label=f"while_else_{stmt.lineno}"
            )
            self.cfg.add_edge(loop_head, else_seed, EdgeLabel.FALSE)
            else_end = self._visit_stmts(stmt.orelse, else_seed)
            if else_end != UNREACHABLE:
                self.cfg.add_edge(else_end, exit_join, EdgeLabel.FLOW)
        else:
            # No else: direct exit on false condition
            self.cfg.add_edge(loop_head, exit_join, EdgeLabel.FALSE)

        self.loop_stack.pop()
        return exit_join

    # For

    def _visit_For(self, stmt: ast.For, cursor: int) -> int:
        """Build a LOOP node for `for`, wiring body, back-edge, and optional `else`."""
        loop_head = self.cfg.add_node(
            NodeKind.LOOP, condition=stmt.iter, label=f"for_{stmt.lineno}",
            for_target=stmt.target,
        )
        self.cfg.add_edge(cursor, loop_head, EdgeLabel.FLOW)
        exit_join = self.cfg.add_node(NodeKind.JOIN, label=f"for_end_{stmt.lineno}")

        self.loop_stack.append((loop_head, exit_join))

        body_seed = self.cfg.add_node(NodeKind.JOIN, label=f"for_body_{stmt.lineno}")
        self.cfg.add_edge(loop_head, body_seed, EdgeLabel.TRUE)
        # The target (iteration variable) is an implicit statement: we
        # attach it to body_seed as a virtual assignment. We represent
        # it by injecting a synthetic Assign.
        # Choice: to avoid polluting the original AST, we record the target
        # as a statement-equivalent via a synthetic wrapper on the
        # first basic block. The convention is noted in the dataflow doc.
        # Phase 2 (IR) will handle this properly.
        body_end = self._visit_stmts(stmt.body, body_seed)
        if body_end != UNREACHABLE:
            self.cfg.add_edge(body_end, loop_head, EdgeLabel.BACK)

        if stmt.orelse:
            else_seed = self.cfg.add_node(
                NodeKind.JOIN, label=f"for_else_{stmt.lineno}"
            )
            self.cfg.add_edge(loop_head, else_seed, EdgeLabel.FALSE)
            else_end = self._visit_stmts(stmt.orelse, else_seed)
            if else_end != UNREACHABLE:
                self.cfg.add_edge(else_end, exit_join, EdgeLabel.FLOW)
        else:
            self.cfg.add_edge(loop_head, exit_join, EdgeLabel.FALSE)

        self.loop_stack.pop()
        return exit_join

    _visit_AsyncFor = _visit_For

    # Try / except / else / finally

    def _visit_Try(self, stmt: ast.Try, cursor: int) -> int:
        """Build TRY_ENTRY/HANDLER/FINALLY nodes and wire body, handlers, orelse, finally."""
        try_entry = self.cfg.add_node(
            NodeKind.TRY_ENTRY, label=f"try_{stmt.lineno}"
        )
        self.cfg.add_edge(cursor, try_entry, EdgeLabel.FLOW)

        # Create the handlers first so they can be pushed before visiting the body
        handler_ids: List[int] = []
        for h in stmt.handlers:
            hid = self.cfg.add_node(
                NodeKind.HANDLER,
                handler_type=h.type,
                handler_name=h.name,
                label=f"except_{h.lineno}",
            )
            handler_ids.append(hid)

        self.try_stack.append(handler_ids)

        # Body
        body_cursor = self._visit_stmts(stmt.body, try_entry)

        # orelse — executed if body terminates normally (no raise)
        if stmt.orelse and body_cursor != UNREACHABLE:
            orelse_seed = self.cfg.add_node(
                NodeKind.JOIN, label=f"try_orelse_{stmt.lineno}"
            )
            self.cfg.add_edge(body_cursor, orelse_seed, EdgeLabel.FLOW)
            body_cursor = self._visit_stmts(stmt.orelse, orelse_seed)

        self.try_stack.pop()

        # Visit the handlers
        handler_end_cursors: List[int] = []
        for h, hid in zip(stmt.handlers, handler_ids):
            # Implicit EXCEPT edge: a raise in the body already reaches hid.
            # But if NO explicit raise touched this handler, we must
            # still make it reachable from try_entry to model
            # that it *can* be triggered by an exception raised by an
            # implicit call. SCA-Phase1 choice: we add an except edge from
            # try_entry to each handler to preserve the over-approximation.
            self.cfg.add_edge(try_entry, hid, EdgeLabel.EXCEPT)
            h_cursor = self._visit_stmts(h.body, hid)
            handler_end_cursors.append(h_cursor)

        # Convergence: all paths reach finally if it exists, otherwise a join
        if stmt.finalbody:
            fin = self.cfg.add_node(
                NodeKind.FINALLY, statements=list(stmt.finalbody), label=f"finally_{stmt.lineno}"
            )
        else:
            fin = self.cfg.add_node(NodeKind.JOIN, label=f"try_join_{stmt.lineno}")

        if body_cursor != UNREACHABLE:
            self.cfg.add_edge(body_cursor, fin, EdgeLabel.FLOW)
        for hc in handler_end_cursors:
            if hc != UNREACHABLE:
                self.cfg.add_edge(hc, fin, EdgeLabel.FLOW)

        return fin

    # With / Async with — minimally desugared as a pass-through over the body

    def _visit_With(self, stmt: ast.With, cursor: int) -> int:
        """Treat `with`/`async with` as an opaque entry BasicBlock followed by the body.

        The with-items are recorded as a single linear statement (no
        `__enter__`/`__exit__` modeling yet); Phase 2 (IR) will refine this.
        """
        with_bb = self.cfg.add_node(
            NodeKind.BASIC, statements=[stmt], label=f"with_{stmt.lineno}"
        )
        self.cfg.add_edge(cursor, with_bb, EdgeLabel.FLOW)
        return self._visit_stmts(stmt.body, with_bb)

    _visit_AsyncWith = _visit_With

    # Match (Python 3.10+) — cascade of Branch nodes (SCA-1 choice)

    def _visit_Match(self, stmt: ast.Match, cursor: int) -> int:
        """Build a cascade of BRANCH nodes for `match`/`case`, one per case."""
        # subject is the matched expression, cases is the list of cases.
        # Modeling: for each case, a Branch (the match condition),
        # TRUE edge to the case body, FALSE edge to the next case.
        # The last case's false edge → exit join.
        #
        # Phase 9 — for literal patterns (`case 'A':`), we build a
        # synthetic `ast.Compare(subject == value)` so that constant
        # propagation can mark cases as dead when the subject is
        # known at compile-time. For more complex patterns
        # (MatchAs, MatchOr, MatchClass, MatchMapping…), we
        # keep `condition=subject` (opaque, conservative semantics).
        exit_join = self.cfg.add_node(NodeKind.JOIN, label=f"match_end_{stmt.lineno}")

        prev_false = cursor
        last_end: Optional[int] = None
        for i, case in enumerate(stmt.cases):
            condition = self._match_case_condition(stmt.subject, case)
            branch = self.cfg.add_node(
                NodeKind.BRANCH,
                condition=condition,
                label=f"match_case_{stmt.lineno}_{i}",
            )
            self.cfg.add_edge(prev_false, branch, EdgeLabel.FLOW)

            body_seed = self.cfg.add_node(
                NodeKind.JOIN, label=f"match_body_{stmt.lineno}_{i}"
            )
            self.cfg.add_edge(branch, body_seed, EdgeLabel.TRUE)
            body_end = self._visit_stmts(case.body, body_seed)
            if body_end != UNREACHABLE:
                self.cfg.add_edge(body_end, exit_join, EdgeLabel.FLOW)
            last_end = body_end

            # The next case takes the FALSE branch
            next_false = self.cfg.add_node(
                NodeKind.JOIN, label=f"match_else_{stmt.lineno}_{i}"
            )
            self.cfg.add_edge(branch, next_false, EdgeLabel.FALSE)
            prev_false = next_false

        # The last "false" falls through to exit_join (no case matches → fall-through)
        self.cfg.add_edge(prev_false, exit_join, EdgeLabel.FLOW)
        return exit_join

    @staticmethod
    def _match_case_condition(subject: ast.expr, case: ast.match_case) -> ast.expr:
        """Build the branch condition for a `match_case`, synthesizing an equality check.

        For `case <value>:` without a guard, returns `subject == value`
        (usable by Phase 9 constant propagation). For any other pattern
        (`MatchAs`, `MatchOr`, `MatchClass`, a guard present…), returns the
        raw `subject` (opaque, conservative).
        """
        pattern = getattr(case, "pattern", None)
        guard = getattr(case, "guard", None)
        if guard is None and isinstance(pattern, ast.MatchValue):
            cmp_node = ast.Compare(
                left=subject,
                ops=[ast.Eq()],
                comparators=[pattern.value],
            )
            ast.copy_location(cmp_node, pattern.value)
            return cmp_node
        return subject


# ============================================================================
# Public API
# ============================================================================

def build_cfg(module: ast.Module) -> CFG:
    """Build a CFG from a Python AST.

    Args:
        module: Python AST (result of ast.parse).

    Returns:
        The constructed CFG, pruned of unreachable nodes.
    """
    if not isinstance(module, ast.Module):
        raise TypeError(f"build_cfg expects ast.Module, got {type(module).__name__}")
    return CFGBuilder().build(module)


# ============================================================================
# Pruning and ordering
# ============================================================================

def prune_unreachable(cfg: CFG) -> None:
    """Remove in-place all nodes not reachable from entry.

    Invariant spec §2.4: every node must be reachable from entry. This
    function also removes edges pointing to removed nodes. entry and exit
    are NEVER removed even if exit is unreachable (a violation of the
    invariant that the caller must handle).
    """
    if cfg.entry < 0:
        return

    # BFS from entry
    reachable: Set[int] = set()
    stack = [cfg.entry]
    while stack:
        nid = stack.pop()
        if nid in reachable:
            continue
        reachable.add(nid)
        for e in cfg.successors(nid):
            if e.dst not in reachable:
                stack.append(e.dst)

    # Always keep the exit (even orphaned) for readability.
    reachable.add(cfg.exit)

    # Remove unreachable nodes
    to_remove = [nid for nid in cfg.nodes if nid not in reachable]
    for nid in to_remove:
        del cfg.nodes[nid]

    # Remove orphaned edges
    cfg.edges = [e for e in cfg.edges if e.src in reachable and e.dst in reachable]


def reverse_post_order(cfg: CFG) -> List[int]:
    """Compute the Reverse Post-Order (RPO) traversal of the CFG.

    DFS from entry, recording finish order, then reversed. Spec §6.1. Used
    by the worklist algorithm to minimize the number of iterations (NNH
    §2.5.2).
    """
    if cfg.entry < 0:
        return []

    visited: Set[int] = set()
    post_order: List[int] = []

    def _dfs(node_id: int) -> None:
        """Recursively visit successors depth-first, recording post-order finish."""
        if node_id in visited:
            return
        visited.add(node_id)
        for e in cfg.successors(node_id):
            _dfs(e.dst)
        post_order.append(node_id)

    _dfs(cfg.entry)
    return list(reversed(post_order))


# ============================================================================
# Debug helpers
# ============================================================================

def to_dot(cfg: CFG) -> str:
    """Convert the CFG to Graphviz DOT notation for visual debugging.

    Usage:
        with open("/tmp/cfg.dot", "w") as f:
            f.write(to_dot(cfg))
        # then: dot -Tpng /tmp/cfg.dot -o /tmp/cfg.png
    """
    lines = ["digraph cfg {", "    rankdir=TB;", '    node [shape=box, fontname="Menlo"];']
    for nid, node in sorted(cfg.nodes.items()):
        label = node.label or f"n{nid}"
        if node.kind == NodeKind.BASIC and node.statements:
            preview = ast.unparse(node.statements[0]).split("\n")[0][:40]
            label = f"{label}\\n{preview}"
        shape = {
            NodeKind.ENTRY: "circle",
            NodeKind.EXIT: "doublecircle",
            NodeKind.BRANCH: "diamond",
            NodeKind.LOOP: "hexagon",
            NodeKind.JOIN: "point",
        }.get(node.kind, "box")
        lines.append(f'    n{nid} [label="{label}", shape={shape}];')
    for e in cfg.edges:
        style = "" if e.label == EdgeLabel.FLOW else f', label="{e.label.value}"'
        color = {
            EdgeLabel.TRUE: ', color="green"',
            EdgeLabel.FALSE: ', color="red"',
            EdgeLabel.BACK: ', color="blue", style=dashed',
            EdgeLabel.EXCEPT: ', color="orange", style=dotted',
            EdgeLabel.ESCAPE: ', color="purple", style=dotted',
        }.get(e.label, "")
        lines.append(f"    n{e.src} -> n{e.dst} [{style.lstrip(', ')}{color}];")
    lines.append("}")
    return "\n".join(lines)


def iter_nodes_by_kind(cfg: CFG, kind: NodeKind) -> Iterator[CFGNode]:
    """Iterate over all nodes of a given kind."""
    for node in cfg.nodes.values():
        if node.kind == kind:
            yield node
