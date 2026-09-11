"""SCA dataflow / taint engine.

Clean-room implementation based on sca/docs/dataflow-spec.md.
Algorithms inspired by:
  - Nielson, Nielson, Hankin — Principles of Program Analysis (Springer 2005)
  - Schwartz et al. — All You Ever Wanted to Know About Dynamic Taint Analysis (IEEE S&P 2010)
  - Aho-Sethi-Ullman — Compilers: Principles, Techniques and Tools (dragon book)

The engine is built incrementally following docs/PLAN-SCA-DATAFLOW.md:
  - Phase 1: Python CFG (sca/dataflow/cfg.py)
  - Phase 2: IR
  - Phase 3: Intra-procedural taint engine
  - Phase 4: DSL integration
  - Phase 5: Intermediate OWASP benchmark
  - Phase 6: Intra-file inter-procedural
  - Phase 7: Aliasing, conditional sanitizers, constant-folding
  - Phase 8: Multi-language ports (JS, Java, C#, PHP)
"""
from sca.dataflow.cfg import (
    CFG,
    CFGNode,
    CFGEdge,
    NodeKind,
    EdgeLabel,
    build_cfg,
    reverse_post_order,
)
from sca.dataflow.ir import (
    # Statements
    Assign,
    Call,
    Return,
    Raise,
    Branch,
    Noop,
    IRStmt,
    # LHS
    VarLhs,
    AttrLhs,
    SubscriptLhs,
    TupleLhs,
    StarLhs,
    LHS,
    # RHS
    Const,
    VarRef,
    AttrRef,
    SubscriptRef,
    CallRef,
    BinOp,
    UnaryOp,
    Cmp,
    Bool,
    TupleRef,
    ListRef,
    DictRef,
    SetRef,
    LambdaRef,
    Star,
    RHS,
    # Helpers
    canon_lhs,
    canon_rhs,
    canon_callee,
    pretty_stmt,
    pretty_stmts,
)

from sca.dataflow.lattice import (
    CLEAN,
    TOP,
    Tainted,
    Taint,
    SourceInfo,
    State,
    empty_state,
    is_clean,
    is_tainted,
    is_top,
    join as taint_join,
    pretty_state,
    pretty_taint,
)
from sca.dataflow.transfer import (
    Finding,
    FlowStep,
    PassthroughSpec,
    RuleSpecs,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
    SpecKind,
    compile_glob_pattern,
    match_pattern,
    resolve_spec,
    transfer_stmt,
    transfer_stmts,
)
from sca.dataflow.worklist import (
    AnalysisResult,
    analyze,
    analyze_module_source,
)

# Note: the stable public API `run_taint_rule` (contract §3.1) lives in
# sca.executors.dataflow_taint. Not re-exported here to avoid an import
# cycle (executors.dataflow_taint depends on sca.dataflow.cfg).
#
# Usage:
#     from sca.executors.dataflow_taint import run_taint_rule, UnsupportedLanguage

__all__ = [
    # CFG
    "CFG", "CFGNode", "CFGEdge", "NodeKind", "EdgeLabel",
    "build_cfg", "reverse_post_order",
    # IR Statements
    "Assign", "Call", "Return", "Raise", "Branch", "Noop", "IRStmt",
    # IR LHS
    "VarLhs", "AttrLhs", "SubscriptLhs", "TupleLhs", "StarLhs", "LHS",
    # IR RHS
    "Const", "VarRef", "AttrRef", "SubscriptRef", "CallRef",
    "BinOp", "UnaryOp", "Cmp", "Bool",
    "TupleRef", "ListRef", "DictRef", "SetRef",
    "LambdaRef", "Star", "RHS",
    # IR Helpers
    "canon_lhs", "canon_rhs", "canon_callee",
    "pretty_stmt", "pretty_stmts",
    # Lattice
    "CLEAN", "TOP", "Tainted", "Taint", "SourceInfo", "State",
    "empty_state", "is_clean", "is_tainted", "is_top", "taint_join",
    "pretty_state", "pretty_taint",
    # Transfer
    "Finding", "FlowStep",
    "RuleSpecs", "SourceSpec", "SinkSpec", "SanitizerSpec", "PassthroughSpec",
    "SpecKind", "compile_glob_pattern", "match_pattern", "resolve_spec",
    "transfer_stmt", "transfer_stmts",
    # Worklist
    "AnalysisResult", "analyze", "analyze_module_source",
]
