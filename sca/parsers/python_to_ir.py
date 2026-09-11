"""Lowering Python AST → IR dataflow.

Clean-room implementation based on sca/docs/dataflow-spec.md §3.
Algorithms inspired by:
  - Aho-Sethi-Ullman — Compilers: Principles, Techniques and Tools (3-address code)
  - Nielson, Nielson, Hankin — Principles of Program Analysis (Springer 2005)

No OCaml semgrep source code was read to write this module.

Overview:
    The lowerer walks a Python AST (stdlib `ast`) and produces a list of
    canonical 3-address IR statements. Complex expressions are linearized
    by introducing temporaries `__t0, __t1, ...`.

See spec §3.3 (normalization) and §3.4 (Python special cases).
"""
from __future__ import annotations

import ast
from typing import List, Optional, Tuple, Union

from sca.dataflow.ir import (
    AttrLhs,
    AttrRef,
    Assign,
    BinOp,
    Bool,
    Branch,
    Call,
    CallRef,
    Cmp,
    Const,
    DictRef,
    IfExp,
    IRStmt,
    LHS,
    LambdaRef,
    ListRef,
    Noop,
    RHS,
    Raise,
    Return,
    SetRef,
    Star,
    StarLhs,
    SubscriptLhs,
    SubscriptRef,
    TupleLhs,
    TupleRef,
    UnaryOp,
    VarLhs,
    VarRef,
)


# ============================================================================
# Operators: mapping ast.<Op> → string
# ============================================================================

_BIN_OPS = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.Div: "/",
    ast.FloorDiv: "//",
    ast.Mod: "%",
    ast.Pow: "**",
    ast.LShift: "<<",
    ast.RShift: ">>",
    ast.BitOr: "|",
    ast.BitXor: "^",
    ast.BitAnd: "&",
    ast.MatMult: "@",
}

_UNARY_OPS = {
    ast.Invert: "~",
    ast.Not: "not",
    ast.UAdd: "+",
    ast.USub: "-",
}

_CMP_OPS = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Is: "is",
    ast.IsNot: "is not",
    ast.In: "in",
    ast.NotIn: "not in",
}


# ============================================================================
# Lowerer
# ============================================================================

class PythonLowerer:
    """Converts a Python AST into a list of IR statements.

    Usage:
        lowerer = PythonLowerer()
        stmts = lowerer.lower_module(ast.parse(source))

    Internals:
        _temp_counter: incremented on each _fresh_temp() call, generates __t0, __t1, ...
        _output: list accumulating IR statements during lowering.
    """

    def __init__(self) -> None:
        """Initialize the lowerer with an empty output buffer and temp-var counter."""
        self._temp_counter = 0
        self._output: List[IRStmt] = []

    # -------------------------------------------------------------------- API

    def lower_module(self, module: ast.Module) -> List[IRStmt]:
        """Lower a full module."""
        if not isinstance(module, ast.Module):
            raise TypeError(f"expected ast.Module, got {type(module).__name__}")
        self._output = []
        self._temp_counter = 0
        for stmt in module.body:
            self._lower_stmt(stmt)
        return list(self._output)

    def lower_stmts(self, stmts: List[ast.stmt]) -> List[IRStmt]:
        """Lower a list of statements (e.g. a function body)."""
        self._output = []
        self._temp_counter = 0
        for stmt in stmts:
            self._lower_stmt(stmt)
        return list(self._output)

    def lower_stmt(self, stmt: ast.stmt) -> List[IRStmt]:
        """Lower a single statement. Resets the temporary-variable counter."""
        self._output = []
        self._temp_counter = 0
        self._lower_stmt(stmt)
        return list(self._output)

    # -------------------------------------------------------------- internals

    def _fresh_temp(self) -> str:
        """Generate a new unique temporary variable name (`__t0`, `__t1`, ...)."""
        name = f"__t{self._temp_counter}"
        self._temp_counter += 1
        return name

    def _emit(self, stmt: IRStmt) -> None:
        """Append an IR statement to the output list."""
        self._output.append(stmt)

    # --- expression lowering ------------------------------------------------

    def _lower_expr(self, expr: ast.expr) -> RHS:
        """Lower a Python expression into a canonical RHS.

        Emits any necessary intermediate statements along the way (for
        complex sub-expressions). Returns the RHS representing the
        expression's final result (typically a VarRef to a temporary for
        compound expressions).

        Spec §3.3 — 3-address normalization.
        """
        if isinstance(expr, ast.Constant):
            return Const(expr.value)

        if isinstance(expr, ast.Name):
            return VarRef(expr.id)

        if isinstance(expr, ast.Attribute):
            base = self._lower_expr(expr.value)
            return AttrRef(base, expr.attr)

        if isinstance(expr, ast.Subscript):
            base = self._lower_expr(expr.value)
            # Python 3.9+: slice is the direct expression
            key = self._lower_expr(expr.slice)
            return SubscriptRef(base, key)

        if isinstance(expr, ast.Slice):
            # Simple modeling: a slice is represented as a tuple
            # (lower, upper, step) to preserve taint.
            lower = self._lower_expr(expr.lower) if expr.lower else Const(None)
            upper = self._lower_expr(expr.upper) if expr.upper else Const(None)
            step = self._lower_expr(expr.step) if expr.step else Const(None)
            return TupleRef((lower, upper, step))

        if isinstance(expr, ast.BinOp):
            left = self._lower_expr(expr.left)
            right = self._lower_expr(expr.right)
            op = _BIN_OPS.get(type(expr.op), "?")
            # Linearize: __tN := BinOp(op, left, right)
            tmp = self._fresh_temp()
            self._emit(Assign(
                lhs=VarLhs(tmp),
                rhs=BinOp(op=op, left=left, right=right),
                lineno=getattr(expr, "lineno", 0),
            ))
            return VarRef(tmp)

        if isinstance(expr, ast.UnaryOp):
            operand = self._lower_expr(expr.operand)
            op = _UNARY_OPS.get(type(expr.op), "?")
            tmp = self._fresh_temp()
            self._emit(Assign(
                lhs=VarLhs(tmp),
                rhs=UnaryOp(op=op, operand=operand),
                lineno=getattr(expr, "lineno", 0),
            ))
            return VarRef(tmp)

        if isinstance(expr, ast.Compare):
            # Python allows chained comparisons: a < b <= c.
            # Semantics: (a < b) and (b <= c). For taint, we simplify by
            # joining all operands via separate Cmp nodes and a Bool(and, ...).
            left = self._lower_expr(expr.left)
            comparators = [self._lower_expr(c) for c in expr.comparators]
            ops = [_CMP_OPS.get(type(o), "?") for o in expr.ops]
            if len(comparators) == 1:
                tmp = self._fresh_temp()
                self._emit(Assign(
                    lhs=VarLhs(tmp),
                    rhs=Cmp(op=ops[0], left=left, right=comparators[0]),
                    lineno=getattr(expr, "lineno", 0),
                ))
                return VarRef(tmp)
            # Chain: (l op0 c0) and (c0 op1 c1) and ...
            cmps: List[RHS] = []
            prev = left
            for op_str, comp in zip(ops, comparators):
                cmps.append(Cmp(op=op_str, left=prev, right=comp))
                prev = comp
            tmp = self._fresh_temp()
            self._emit(Assign(
                lhs=VarLhs(tmp),
                rhs=Bool(op="and", operands=tuple(cmps)),
                lineno=getattr(expr, "lineno", 0),
            ))
            return VarRef(tmp)

        if isinstance(expr, ast.BoolOp):
            # `a and b`, `a or b`
            operands = tuple(self._lower_expr(v) for v in expr.values)
            op = "and" if isinstance(expr.op, ast.And) else "or"
            tmp = self._fresh_temp()
            self._emit(Assign(
                lhs=VarLhs(tmp),
                rhs=Bool(op=op, operands=operands),
                lineno=getattr(expr, "lineno", 0),
            ))
            return VarRef(tmp)

        if isinstance(expr, ast.Call):
            callee = self._lower_expr(expr.func)
            args = tuple(self._lower_call_arg(a) for a in expr.args)
            kwargs = tuple(
                (kw.arg or "**", self._lower_call_arg(kw.value))
                for kw in expr.keywords
            )
            tmp = self._fresh_temp()
            self._emit(Assign(
                lhs=VarLhs(tmp),
                rhs=CallRef(callee=callee, args=args, kwargs=kwargs),
                lineno=getattr(expr, "lineno", 0),
            ))
            return VarRef(tmp)

        if isinstance(expr, ast.Tuple):
            elements = tuple(self._lower_expr(e) for e in expr.elts)
            return TupleRef(elements)

        if isinstance(expr, ast.List):
            elements = tuple(self._lower_expr(e) for e in expr.elts)
            return ListRef(elements)

        if isinstance(expr, ast.Dict):
            items: List[Tuple[RHS, RHS]] = []
            for k, v in zip(expr.keys, expr.values):
                # `**d` in a dict literal: key is None
                if k is None:
                    items.append((Const(None), self._lower_expr(v)))
                else:
                    items.append((self._lower_expr(k), self._lower_expr(v)))
            return DictRef(tuple(items))

        if isinstance(expr, ast.Set):
            elements = tuple(self._lower_expr(e) for e in expr.elts)
            return SetRef(elements)

        if isinstance(expr, ast.IfExp):
            # Ternary expression: `then if cond else orelse`.
            # Phase 9 — kept as a distinct IR node so that constant
            # propagation (`_compute_dead_edges`) can simplify the
            # expression when `cond` is evaluable at compile time.
            # Conservative semantics by default:
            # `eval_rhs(IfExp)` = join(eval_rhs(then), eval_rhs(orelse)),
            # identical to the former `Bool(or, [then, orelse])`.
            cond_rhs = self._lower_expr(expr.test)
            then_rhs = self._lower_expr(expr.body)
            orelse_rhs = self._lower_expr(expr.orelse)
            tmp = self._fresh_temp()
            self._emit(Assign(
                lhs=VarLhs(tmp),
                rhs=IfExp(cond=cond_rhs, then=then_rhs, orelse=orelse_rhs),
                lineno=getattr(expr, "lineno", 0),
            ))
            return VarRef(tmp)

        if isinstance(expr, ast.Lambda):
            arg_names = tuple(arg.arg for arg in expr.args.args)
            return LambdaRef(arg_names=arg_names)

        if isinstance(expr, ast.JoinedStr):
            # f-string: passthrough on all holes (choice SCA-5)
            # Modeled as a Call(__format__, [hole1, hole2, ...])
            args: List[RHS] = []
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    args.append(self._lower_expr(v.value))
                elif isinstance(v, ast.Constant):
                    args.append(Const(v.value))
                else:
                    args.append(self._lower_expr(v))
            tmp = self._fresh_temp()
            self._emit(Assign(
                lhs=VarLhs(tmp),
                rhs=CallRef(
                    callee=VarRef("__format__"),
                    args=tuple(args),
                ),
                lineno=getattr(expr, "lineno", 0),
            ))
            return VarRef(tmp)

        if isinstance(expr, ast.FormattedValue):
            # If encountered alone (rare), it's just the formatted value.
            return self._lower_expr(expr.value)

        if isinstance(expr, ast.Await):
            # `await x` propagates the taint of x (spec choice §3.4)
            return self._lower_expr(expr.value)

        if isinstance(expr, ast.Yield):
            # `yield x` returns x but the CFG continues afterward. Modeled
            # as a trivial passthrough in the IR: the taint of x is
            # preserved on the caller side via the summary (Phase 6).
            if expr.value:
                return self._lower_expr(expr.value)
            return Const(None)

        if isinstance(expr, ast.YieldFrom):
            return self._lower_expr(expr.value)

        if isinstance(expr, ast.Starred):
            inner = self._lower_expr(expr.value)
            return Star(inner=inner, double=False)

        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            # Comprehension: choice SCA-2 — desugared into a loop in Phase 7 IR.
            # In phase 2, we flatten it into: __tN := <comprehension_result>
            # where the result preserves the taint of the generators and elts.
            # Strategy: collect the taint of all `for` generators and of
            # the element, return an appropriate container.
            inner_tracker: List[RHS] = []
            # Taint of the iters
            for gen in expr.generators:
                inner_tracker.append(self._lower_expr(gen.iter))
                for cond in gen.ifs:
                    self._lower_expr(cond)  # emits the statements, ignores the result
            # Taint of the element
            if isinstance(expr, ast.DictComp):
                inner_tracker.append(self._lower_expr(expr.key))
                inner_tracker.append(self._lower_expr(expr.value))
            else:
                inner_tracker.append(self._lower_expr(expr.elt))
            # Model as a container with these aggregated elements
            if isinstance(expr, ast.ListComp):
                return ListRef(tuple(inner_tracker))
            if isinstance(expr, ast.SetComp):
                return SetRef(tuple(inner_tracker))
            if isinstance(expr, ast.DictComp):
                # Rebuild as key/val pairs
                return DictRef(tuple((Const("*"), elt) for elt in inner_tracker))
            # GeneratorExp: treated like a list
            return ListRef(tuple(inner_tracker))

        if isinstance(expr, ast.NamedExpr):
            # `x := expr` (walrus). Emits the assign + returns VarRef.
            rhs = self._lower_expr(expr.value)
            target_name = expr.target.id if isinstance(expr.target, ast.Name) else self._fresh_temp()
            self._emit(Assign(
                lhs=VarLhs(target_name),
                rhs=rhs,
                lineno=getattr(expr, "lineno", 0),
            ))
            return VarRef(target_name)

        # Fallback: unknown expression → Const(None) safe (does not propagate).
        return Const(None)

    def _lower_call_arg(self, arg: ast.expr) -> RHS:
        """Lower a call argument, handling `*args` starred unpacking."""
        if isinstance(arg, ast.Starred):
            inner = self._lower_expr(arg.value)
            return Star(inner=inner, double=False)
        return self._lower_expr(arg)

    # --- target (LHS) lowering ----------------------------------------------

    def _lower_target(self, target: ast.expr) -> LHS:
        """Lower an assignment target into a canonical LHS."""
        if isinstance(target, ast.Name):
            return VarLhs(target.id)
        if isinstance(target, ast.Attribute):
            base = self._lower_expr(target.value)
            return AttrLhs(base=base, attr=target.attr)
        if isinstance(target, ast.Subscript):
            base = self._lower_expr(target.value)
            key = self._lower_expr(target.slice)
            return SubscriptLhs(base=base, key=key)
        if isinstance(target, (ast.Tuple, ast.List)):
            return TupleLhs(tuple(self._lower_target(e) for e in target.elts))
        if isinstance(target, ast.Starred):
            return StarLhs(inner=self._lower_target(target.value))
        # Fallback: synthetic name to avoid crashing
        return VarLhs(name=f"__unknown_target_{id(target)}")

    # --- statement lowering -------------------------------------------------

    def _lower_stmt(self, stmt: ast.stmt) -> None:
        """Dispatch a statement node to its `_lower_<NodeType>` handler,
        emitting a Noop if no handler exists for that node type."""
        method = getattr(self, f"_lower_{type(stmt).__name__}", None)
        if method is None:
            # Unknown statement: noop
            self._emit(Noop(lineno=getattr(stmt, "lineno", 0)))
            return
        method(stmt)

    def _lower_Assign(self, stmt: ast.Assign) -> None:
        """Lower `a = b = expr` into a chain of assignments."""
        rhs = self._lower_expr(stmt.value)
        for target in stmt.targets:
            self._emit_assign(target, rhs, stmt.lineno)

    def _emit_assign(self, target: ast.expr, rhs: RHS, lineno: int) -> None:
        """Emit the assignment, handling destructuring when target is a tuple/list.

        Spec §3.4: `a, b = expr` → `__t := expr; a := __t[0]; b := __t[1]`.
        A TupleLhs could also be kept if the expression is already a
        TupleRef of matching arity, but for simplicity this always
        desugars into SubscriptRef.
        """
        if isinstance(target, (ast.Tuple, ast.List)):
            # Store RHS in a temp first
            tmp = self._fresh_temp()
            self._emit(Assign(lhs=VarLhs(tmp), rhs=rhs, lineno=lineno))
            tmp_ref = VarRef(tmp)
            for i, sub_target in enumerate(target.elts):
                if isinstance(sub_target, ast.Starred):
                    # `*rest = ...`: represented by StarLhs with a full slice
                    self._emit(Assign(
                        lhs=StarLhs(inner=self._lower_target(sub_target.value)),
                        rhs=tmp_ref,
                        lineno=lineno,
                    ))
                else:
                    sub_rhs = SubscriptRef(base=tmp_ref, key=Const(i))
                    self._emit_assign(sub_target, sub_rhs, lineno)
        else:
            self._emit(Assign(
                lhs=self._lower_target(target),
                rhs=rhs,
                lineno=lineno,
            ))

    def _lower_AugAssign(self, stmt: ast.AugAssign) -> None:
        """Lower `a += expr` into `a := BinOp(+, VarRef(a), expr)` (spec §3.4)."""
        rhs = self._lower_expr(stmt.value)
        op = _BIN_OPS.get(type(stmt.op), "?")
        # Read the target as an rvalue
        read_target = self._target_as_rvalue(stmt.target)
        new_rhs = BinOp(op=op, left=read_target, right=rhs)
        self._emit(Assign(
            lhs=self._lower_target(stmt.target),
            rhs=new_rhs,
            lineno=stmt.lineno,
        ))

    def _target_as_rvalue(self, target: ast.expr) -> RHS:
        """Convert an assignment target into its rvalue form, for AugAssign."""
        if isinstance(target, ast.Name):
            return VarRef(target.id)
        if isinstance(target, ast.Attribute):
            return AttrRef(base=self._lower_expr(target.value), attr=target.attr)
        if isinstance(target, ast.Subscript):
            return SubscriptRef(
                base=self._lower_expr(target.value),
                key=self._lower_expr(target.slice),
            )
        return Const(None)

    def _lower_AnnAssign(self, stmt: ast.AnnAssign) -> None:
        """Lower `a: T = expr`; emits a Noop when there is no value (`a: T`)."""
        if stmt.value is None:
            self._emit(Noop(lineno=stmt.lineno))
            return
        rhs = self._lower_expr(stmt.value)
        self._emit(Assign(
            lhs=self._lower_target(stmt.target),
            rhs=rhs,
            lineno=stmt.lineno,
        ))

    def _lower_Expr(self, stmt: ast.Expr) -> None:
        """Lower an expression-statement: `foo()` or `print(x)`.

        If it is a call, emits a Call statement (visible to the taint
        worklist to detect sinks). Otherwise lowers it but discards the
        result (no taint side effect to record).
        """
        if isinstance(stmt.value, ast.Call):
            callee = self._lower_expr(stmt.value.func)
            args = tuple(self._lower_call_arg(a) for a in stmt.value.args)
            kwargs = tuple(
                (kw.arg or "**", self._lower_call_arg(kw.value))
                for kw in stmt.value.keywords
            )
            self._emit(Call(
                callee=callee,
                args=args,
                kwargs=kwargs,
                lineno=stmt.lineno,
            ))
        else:
            # Expression with no effect: emits its sub-statements and discards the result
            self._lower_expr(stmt.value)

    def _lower_Return(self, stmt: ast.Return) -> None:
        """Lower a `return` statement into an emitted Return IR node."""
        value = self._lower_expr(stmt.value) if stmt.value else None
        self._emit(Return(value=value, lineno=stmt.lineno))

    def _lower_Raise(self, stmt: ast.Raise) -> None:
        """Lower a `raise` statement into an emitted Raise IR node."""
        value = self._lower_expr(stmt.exc) if stmt.exc else None
        self._emit(Raise(value=value, lineno=stmt.lineno))

    def _lower_Pass(self, stmt: ast.Pass) -> None:
        """Lower a `pass` statement into a Noop."""
        self._emit(Noop(lineno=stmt.lineno))

    def _lower_Delete(self, stmt: ast.Delete) -> None:
        """Lower `del x` as an assignment of Const(None), clearing its taint."""
        for target in stmt.targets:
            self._emit(Assign(
                lhs=self._lower_target(target),
                rhs=Const(None),
                lineno=stmt.lineno,
            ))

    def _lower_Import(self, stmt: ast.Import) -> None:
        """Lower `import x` or `import x as y` as `x := __import__(...)`."""
        for alias in stmt.names:
            name = alias.asname or alias.name
            self._emit(Assign(
                lhs=VarLhs(name.split(".")[0]),
                rhs=CallRef(
                    callee=VarRef("__import__"),
                    args=(Const(alias.name),),
                ),
                lineno=stmt.lineno,
            ))

    def _lower_ImportFrom(self, stmt: ast.ImportFrom) -> None:
        """Lower `from x import y, z` as `y := __import__('x').y; z := __import__('x').z`."""
        module = stmt.module or ""
        for alias in stmt.names:
            local_name = alias.asname or alias.name
            if alias.name == "*":
                # `from x import *`: skip (unknown taint)
                self._emit(Noop(lineno=stmt.lineno))
                continue
            self._emit(Assign(
                lhs=VarLhs(local_name),
                rhs=AttrRef(
                    base=CallRef(callee=VarRef("__import__"), args=(Const(module),)),
                    attr=alias.name,
                ),
                lineno=stmt.lineno,
            ))

    def _lower_Global(self, stmt: ast.Global) -> None:
        """Lower a `global` declaration into a Noop (scope binding is not tracked)."""
        self._emit(Noop(lineno=stmt.lineno))

    def _lower_Nonlocal(self, stmt: ast.Nonlocal) -> None:
        """Lower a `nonlocal` declaration into a Noop (scope binding is not tracked)."""
        self._emit(Noop(lineno=stmt.lineno))

    def _lower_Assert(self, stmt: ast.Assert) -> None:
        """Lower `assert cond[, msg]` for its side effects; the assertion
        itself has no propagation effect on the IR."""
        self._lower_expr(stmt.test)
        if stmt.msg:
            self._lower_expr(stmt.msg)
        self._emit(Noop(lineno=stmt.lineno))

    # FunctionDef / ClassDef / AsyncFunctionDef are opaque in Phase 2
    # — modeled as an assignment to a dummy LambdaRef to preserve
    # the name in scope.

    def _lower_FunctionDef(self, stmt: ast.FunctionDef) -> None:
        """Lower a function/async-function definition as an opaque LambdaRef
        assignment, preserving its name in scope (bodies are not lowered here)."""
        arg_names = tuple(arg.arg for arg in stmt.args.args)
        self._emit(Assign(
            lhs=VarLhs(stmt.name),
            rhs=LambdaRef(arg_names=arg_names),
            lineno=stmt.lineno,
        ))

    _lower_AsyncFunctionDef = _lower_FunctionDef

    def _lower_ClassDef(self, stmt: ast.ClassDef) -> None:
        """Lower a class definition as an opaque LambdaRef assignment,
        preserving its name in scope (the class body is not lowered here)."""
        self._emit(Assign(
            lhs=VarLhs(stmt.name),
            rhs=LambdaRef(arg_names=()),
            lineno=stmt.lineno,
        ))

    # Control structures: flattened to produce a debuggable IR at module
    # level. Real control flow is handled by the CFG (Phase 1). Here we
    # emit a Branch (for the condition) + the body in sequence.

    def _lower_If(self, stmt: ast.If) -> None:
        """Lower an `if` statement: emit a Branch for the condition, then
        flatten the body and orelse statements (real control flow is
        handled separately by the CFG, not by this flattened IR)."""
        cond = self._lower_expr(stmt.test)
        self._emit(Branch(condition=cond, lineno=stmt.lineno))
        for s in stmt.body:
            self._lower_stmt(s)
        for s in stmt.orelse:
            self._lower_stmt(s)

    def _lower_While(self, stmt: ast.While) -> None:
        """Lower a `while` statement: emit a Branch for the condition, then
        flatten the body and orelse statements."""
        cond = self._lower_expr(stmt.test)
        self._emit(Branch(condition=cond, lineno=stmt.lineno))
        for s in stmt.body:
            self._lower_stmt(s)
        for s in stmt.orelse:
            self._lower_stmt(s)

    def _lower_For(self, stmt: ast.For) -> None:
        """Lower a `for` statement: materialize `target := iter` as a
        virtual assignment, then flatten the body and orelse statements."""
        # Choice SCA-Phase2: materialize `target := <iter>` at the start of the body
        # as a virtual assignment. Phase 2 will refine this if needed (see spec §2.5).
        iter_rhs = self._lower_expr(stmt.iter)
        self._emit(Assign(
            lhs=self._lower_target(stmt.target),
            rhs=iter_rhs,
            lineno=stmt.lineno,
        ))
        for s in stmt.body:
            self._lower_stmt(s)
        for s in stmt.orelse:
            self._lower_stmt(s)

    _lower_AsyncFor = _lower_For

    def _lower_Try(self, stmt: ast.Try) -> None:
        """Lower a `try/except/else/finally` statement by flattening all
        blocks in sequence; each `except X as name:` handler emits a
        virtual assignment binding `name` to an opaque exception value."""
        for s in stmt.body:
            self._lower_stmt(s)
        for handler in stmt.handlers:
            # `except X as name:` — emit a virtual assignment when name is present
            if handler.name:
                self._emit(Assign(
                    lhs=VarLhs(handler.name),
                    rhs=Const(None),  # opaque exception content
                    lineno=handler.lineno,
                ))
            for s in handler.body:
                self._lower_stmt(s)
        for s in stmt.orelse:
            self._lower_stmt(s)
        for s in stmt.finalbody:
            self._lower_stmt(s)

    def _lower_TryStar(self, stmt) -> None:  # type: ignore[no-untyped-def]
        """Lower `try/except*` (Python 3.11+) identically to plain `try`."""
        self._lower_Try(stmt)

    def _lower_With(self, stmt: ast.With) -> None:
        """Lower `with ctx as x:` as `x := ctx.__enter__(); ...body...; ctx.__exit__(...)`
        (spec §3.4), calling `__exit__` on each context in reverse order."""
        ctx_temps: List[str] = []
        for item in stmt.items:
            ctx_rhs = self._lower_expr(item.context_expr)
            tmp_ctx = self._fresh_temp()
            self._emit(Assign(lhs=VarLhs(tmp_ctx), rhs=ctx_rhs, lineno=stmt.lineno))
            ctx_temps.append(tmp_ctx)
            enter_call = CallRef(
                callee=AttrRef(base=VarRef(tmp_ctx), attr="__enter__"),
            )
            if item.optional_vars:
                self._emit(Assign(
                    lhs=self._lower_target(item.optional_vars),
                    rhs=enter_call,
                    lineno=stmt.lineno,
                ))
            else:
                self._emit(Call(
                    callee=AttrRef(base=VarRef(tmp_ctx), attr="__enter__"),
                    lineno=stmt.lineno,
                ))
        for s in stmt.body:
            self._lower_stmt(s)
        # __exit__ in reverse order (Python convention)
        for tmp_ctx in reversed(ctx_temps):
            self._emit(Call(
                callee=AttrRef(base=VarRef(tmp_ctx), attr="__exit__"),
                args=(Const(None), Const(None), Const(None)),
                lineno=stmt.lineno,
            ))

    _lower_AsyncWith = _lower_With

    def _lower_Match(self, stmt) -> None:  # type: ignore[no-untyped-def]
        """Lower a `match` statement: each case becomes a Branch whose
        condition is, when possible, a semantically equivalent comparison
        (`subject == value` for `case <value>:`), enabling constant
        propagation (`const_eval`) to eliminate dead cases when the
        subject is known at compile time. For more complex patterns
        (`MatchAs`, `MatchOr`, `MatchClass`, guards, ...), falls back to
        `Branch(subject)`, which is opaque but conservative.
        """
        subject = self._lower_expr(stmt.subject)
        for case in stmt.cases:
            pattern = case.pattern
            guard = getattr(case, "guard", None)
            if guard is None and isinstance(pattern, ast.MatchValue):
                value = self._lower_expr(pattern.value)
                condition = Cmp(op="==", left=subject, right=value)
            else:
                condition = subject
            self._emit(Branch(condition=condition, lineno=getattr(case, "lineno", stmt.lineno)))
            for s in case.body:
                self._lower_stmt(s)

    def _lower_Break(self, stmt: ast.Break) -> None:
        """Lower a `break` statement to a Noop — control flow is handled by the CFG."""
        # Break: noop at the IR level; control flow is handled by the CFG.
        self._emit(Noop(lineno=stmt.lineno))

    def _lower_Continue(self, stmt: ast.Continue) -> None:
        """Lower a `continue` statement to a Noop — control flow is handled by the CFG."""
        self._emit(Noop(lineno=stmt.lineno))


# ============================================================================
# Public API
# ============================================================================

def lower_module(module: ast.Module) -> List[IRStmt]:
    """Lower a full Python module into a list of IR statements."""
    return PythonLowerer().lower_module(module)


def lower_expr(expr: ast.expr) -> RHS:
    """Lower a Python expression into an IR RHS (public helper).

    Used in Phase 9 to evaluate the condition of a CFG BRANCH/LOOP node
    in `eval_const`. Lowering may generate auxiliary statements to
    decompose complex sub-expressions, which are ignored here (only the
    final RHS matters for constant evaluation).
    """
    return PythonLowerer()._lower_expr(expr)


def lower_stmts(stmts: List[ast.stmt]) -> List[IRStmt]:
    """Lower a list of Python statements into IR."""
    return PythonLowerer().lower_stmts(stmts)


def lower_stmt(stmt: ast.stmt) -> List[IRStmt]:
    """Lower a single Python statement into IR (may produce multiple IRStmt)."""
    return PythonLowerer().lower_stmt(stmt)
