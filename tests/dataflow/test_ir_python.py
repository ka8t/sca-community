"""Tests du lowering Python AST → IR — Phase 2 du moteur dataflow SCA.

Couvre :
  - Grammaire IR (spec §3.2)
  - Normalisation 3-address (spec §3.3)
  - Cas spéciaux Python (spec §3.4)
  - Cas edge (containers, attributs, subscripts, comprehensions, etc.)

Couverture cible : ≥ 30 cas, comme prévu au plan PLAN-SCA-DATAFLOW.md §5 Phase 2.
"""
from __future__ import annotations

import ast
from typing import List

import pytest

from sca.dataflow.ir import (
    Assign,
    AttrLhs,
    AttrRef,
    BinOp,
    Bool,
    Branch,
    Call,
    CallRef,
    Cmp,
    Const,
    DictRef,
    IRStmt,
    LambdaRef,
    ListRef,
    Noop,
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
    canon_callee,
    canon_lhs,
    canon_rhs,
    pretty_stmt,
    pretty_stmts,
)
from sca.parsers.python_to_ir import (
    PythonLowerer,
    lower_module,
    lower_stmt,
    lower_stmts,
)


# ============================================================================
# Helpers
# ============================================================================

def _lower(src: str) -> List[IRStmt]:
    """Lower un fragment Python source en IR."""
    return lower_module(ast.parse(src))


def _assigns(ir: List[IRStmt]) -> List[Assign]:
    return [s for s in ir if isinstance(s, Assign)]


def _calls(ir: List[IRStmt]) -> List[Call]:
    return [s for s in ir if isinstance(s, Call)]


# ============================================================================
# Assignments simples
# ============================================================================

class TestSimpleAssign:

    def test_var_assign_constant(self):
        ir = _lower("x = 1")
        assert ir == [Assign(lhs=VarLhs("x"), rhs=Const(1), lineno=1)]

    def test_var_assign_var(self):
        ir = _lower("x = y")
        assert ir[0].lhs == VarLhs("x")
        assert ir[0].rhs == VarRef("y")

    def test_attribute_assign(self):
        ir = _lower("obj.attr = 1")
        assert ir[0].lhs == AttrLhs(base=VarRef("obj"), attr="attr")
        assert ir[0].rhs == Const(1)

    def test_subscript_assign(self):
        ir = _lower("d[k] = v")
        a = ir[0]
        assert isinstance(a.lhs, SubscriptLhs)
        assert a.lhs.base == VarRef("d")
        assert a.lhs.key == VarRef("k")

    def test_chained_assign(self):
        """`a = b = expr` → deux assignments avec même RHS."""
        ir = _lower("a = b = source()")
        assigns = _assigns(ir)
        # Le call est stocké dans __t0, puis a := __t0 et b := __t0
        rhs_set = {a.lhs for a in assigns if isinstance(a.lhs, VarLhs) and a.lhs.name in ("a", "b")}
        assert VarLhs("a") in rhs_set
        assert VarLhs("b") in rhs_set


# ============================================================================
# 3-address normalization
# ============================================================================

class Test3Address:

    def test_nested_call_is_linearized(self):
        """`foo(bar(x) + 1)` → 3 statements 3-address."""
        ir = _lower("y = foo(bar(x) + 1)")
        # __t0 := bar(x); __t1 := __t0 + 1; __t2 := foo(__t1); y := __t2
        assert len(ir) == 4
        assigns = _assigns(ir)
        # Vérif chaîne de temporaires
        assert isinstance(assigns[0].rhs, CallRef)
        assert isinstance(assigns[1].rhs, BinOp)
        assert isinstance(assigns[2].rhs, CallRef)

    def test_binop_creates_temp(self):
        ir = _lower("z = a + b * c")
        # __t0 := b * c; __t1 := a + __t0; z := __t1
        assigns = _assigns(ir)
        assert len(assigns) == 3
        # Le dernier doit assigner à `z`
        assert assigns[-1].lhs == VarLhs("z")

    def test_unary_op(self):
        ir = _lower("y = -x")
        assigns = _assigns(ir)
        # __t0 := -x; y := __t0
        assert any(isinstance(a.rhs, UnaryOp) for a in assigns)

    def test_compare_simple(self):
        ir = _lower("b = x < 10")
        assigns = _assigns(ir)
        assert any(isinstance(a.rhs, Cmp) for a in assigns)

    def test_compare_chained(self):
        """`a < b <= c` → Bool(and, [Cmp(<, a, b), Cmp(<=, b, c)])."""
        ir = _lower("ok = a < b <= c")
        # On cherche un Bool(and, [Cmp, Cmp])
        bool_rhs = next(a.rhs for a in _assigns(ir) if isinstance(a.rhs, Bool))
        assert bool_rhs.op == "and"
        assert len(bool_rhs.operands) == 2
        assert all(isinstance(op, Cmp) for op in bool_rhs.operands)


# ============================================================================
# Containers
# ============================================================================

class TestContainers:

    def test_tuple_literal(self):
        ir = _lower("t = (1, 2, 3)")
        last = _assigns(ir)[-1]
        assert isinstance(last.rhs, TupleRef)
        assert len(last.rhs.elements) == 3

    def test_list_literal(self):
        ir = _lower("L = [a, b, c]")
        last = _assigns(ir)[-1]
        assert isinstance(last.rhs, ListRef)
        assert len(last.rhs.elements) == 3

    def test_dict_literal(self):
        ir = _lower("d = {'a': 1, 'b': 2}")
        last = _assigns(ir)[-1]
        assert isinstance(last.rhs, DictRef)
        assert len(last.rhs.items) == 2

    def test_set_literal(self):
        ir = _lower("s = {1, 2, 3}")
        last = _assigns(ir)[-1]
        assert isinstance(last.rhs, SetRef)


# ============================================================================
# Tuple destructuring (spec §3.4)
# ============================================================================

class TestDestructuring:

    def test_tuple_destructuring(self):
        """`a, b = expr` → `__t := expr; a := __t[0]; b := __t[1]`."""
        ir = _lower("a, b = pair()")
        assigns = _assigns(ir)
        # __t0 := pair(); __t1 := __t0; a := __t1[0]; b := __t1[1]
        assert len(assigns) >= 4
        # Le dernier doit être `b := <SubscriptRef of __t1 with key Const(1)>`
        b_assign = assigns[-1]
        assert b_assign.lhs == VarLhs("b")
        assert isinstance(b_assign.rhs, SubscriptRef)
        assert b_assign.rhs.key == Const(1)

    def test_list_destructuring(self):
        ir = _lower("[a, b, c] = triple()")
        assigns = _assigns(ir)
        # 3 assigns aux variables + 2 temps
        names = {a.lhs.name for a in assigns if isinstance(a.lhs, VarLhs)}
        assert {"a", "b", "c"} <= names

    def test_starred_destructuring(self):
        """`a, *rest = xs` → a := xs[0]; *rest := xs."""
        ir = _lower("a, *rest = xs")
        # Le `*rest` est représenté par un StarLhs
        assert any(isinstance(s.lhs, StarLhs) for s in _assigns(ir))


# ============================================================================
# AugAssign (spec §3.4)
# ============================================================================

class TestAugAssign:

    def test_aug_add(self):
        """`a += 1` → `a := a + 1`."""
        ir = _lower("a += 1")
        assert len(ir) == 1
        assign = ir[0]
        assert isinstance(assign, Assign)
        assert assign.lhs == VarLhs("a")
        assert isinstance(assign.rhs, BinOp)
        assert assign.rhs.op == "+"
        assert assign.rhs.left == VarRef("a")
        assert assign.rhs.right == Const(1)

    def test_aug_mul_on_attribute(self):
        ir = _lower("obj.count *= 2")
        assign = ir[0]
        assert isinstance(assign, Assign)
        assert isinstance(assign.lhs, AttrLhs)
        assert isinstance(assign.rhs, BinOp)
        assert assign.rhs.op == "*"


# ============================================================================
# Bool / IfExp / NamedExpr
# ============================================================================

class TestBoolAndConditional:

    def test_bool_and(self):
        ir = _lower("c = a and b")
        bool_rhs = next(a.rhs for a in _assigns(ir) if isinstance(a.rhs, Bool))
        assert bool_rhs.op == "and"
        assert bool_rhs.operands == (VarRef("a"), VarRef("b"))

    def test_bool_or(self):
        ir = _lower("c = a or b")
        bool_rhs = next(a.rhs for a in _assigns(ir) if isinstance(a.rhs, Bool))
        assert bool_rhs.op == "or"

    def test_ternary_modeled_as_ifexp(self):
        """`x if cond else y` → IfExp(cond, then, orelse) depuis Phase 9
        (auparavant Bool(or, [x, y]) — sur-approximation moins précise)."""
        from sca.dataflow.ir import IfExp
        ir = _lower("z = x if cond else y")
        ifexp_rhs = next(a.rhs for a in _assigns(ir) if isinstance(a.rhs, IfExp))
        assert ifexp_rhs.cond == VarRef("cond")
        assert ifexp_rhs.then == VarRef("x")
        assert ifexp_rhs.orelse == VarRef("y")

    def test_walrus(self):
        """`(x := expr)` → assign x + retourne x."""
        ir = _lower("result = (x := source()) + 1")
        names = {a.lhs.name for a in _assigns(ir) if isinstance(a.lhs, VarLhs)}
        assert "x" in names
        assert "result" in names


# ============================================================================
# f-strings (choix SCA-5)
# ============================================================================

class TestFStrings:

    def test_fstring_passthrough(self):
        """f-string : passthrough sur tous les holes, callee = __format__."""
        ir = _lower('msg = f"hello {name}"')
        # Cherche un CallRef avec callee __format__
        callrefs = [a.rhs for a in _assigns(ir) if isinstance(a.rhs, CallRef)]
        format_calls = [c for c in callrefs if isinstance(c.callee, VarRef) and c.callee.name == "__format__"]
        assert len(format_calls) >= 1

    def test_fstring_multiple_holes(self):
        ir = _lower('s = f"{a} and {b}"')
        callrefs = [a.rhs for a in _assigns(ir) if isinstance(a.rhs, CallRef)]
        format_calls = [c for c in callrefs if isinstance(c.callee, VarRef) and c.callee.name == "__format__"]
        # Le f-string a 4 segments (str, hole, str, hole) mais on garde tout.
        assert len(format_calls) == 1
        args = format_calls[0].args
        # Au moins 2 VarRef parmi les args
        assert sum(1 for a in args if isinstance(a, VarRef)) >= 2


# ============================================================================
# await / yield (spec §3.4)
# ============================================================================

class TestAsyncYield:

    def test_await_is_passthrough(self):
        ir = _lower("async def f():\n    x = await foo()")
        # `async def` produit un Assign à LambdaRef opaque (Phase 2).
        # On vérifie juste que ça ne crash pas et que `f` est créé.
        names = {a.lhs.name for a in _assigns(ir) if isinstance(a.lhs, VarLhs)}
        assert "f" in names

    def test_yield_lowered(self):
        # `yield` au top niveau est SyntaxError. Wrap dans une fonction et
        # vérifier que le lowering ne crash pas.
        src = "def gen():\n    yield 1\n    yield 2"
        ir = _lower(src)
        # `def gen` = LambdaRef au module level
        assert any(isinstance(a.rhs, LambdaRef) for a in _assigns(ir))


# ============================================================================
# with (spec §3.4)
# ============================================================================

class TestWithStatement:

    def test_with_single_item(self):
        """`with open(f) as fp:` → `__t := open(f); fp := __t.__enter__()`."""
        ir = _lower("with open('f') as fp:\n    data = fp.read()")
        # On doit voir un assign à `fp` qui vient d'un __enter__
        fp_assign = next(
            (a for a in _assigns(ir) if isinstance(a.lhs, VarLhs) and a.lhs.name == "fp"),
            None,
        )
        assert fp_assign is not None
        # Et un Call à __exit__ en fin
        exit_calls = [
            c for c in _calls(ir)
            if isinstance(c.callee, AttrRef) and c.callee.attr == "__exit__"
        ]
        assert len(exit_calls) == 1

    def test_with_no_target(self):
        """`with ctx():` sans `as` → toujours __enter__/__exit__."""
        ir = _lower("with ctx():\n    foo()")
        enter_calls = [
            c for c in _calls(ir)
            if isinstance(c.callee, AttrRef) and c.callee.attr == "__enter__"
        ]
        exit_calls = [
            c for c in _calls(ir)
            if isinstance(c.callee, AttrRef) and c.callee.attr == "__exit__"
        ]
        assert len(enter_calls) == 1
        assert len(exit_calls) == 1


# ============================================================================
# Calls : args, kwargs, *args, **kwargs
# ============================================================================

class TestCalls:

    def test_call_as_statement(self):
        """`print(x)` (statement) → IR Call (pas Assign)."""
        ir = _lower("print(x)")
        # Cherche un Call avec callee VarRef("print")
        calls = [s for s in ir if isinstance(s, Call) and isinstance(s.callee, VarRef) and s.callee.name == "print"]
        assert len(calls) == 1

    def test_call_with_kwargs(self):
        ir = _lower("r = foo(a, b=1, c=x)")
        callref = next(a.rhs for a in _assigns(ir) if isinstance(a.rhs, CallRef))
        assert len(callref.args) == 1
        assert len(callref.kwargs) == 2
        names = {n for n, _ in callref.kwargs}
        assert names == {"b", "c"}

    def test_call_with_star_args(self):
        ir = _lower("r = foo(*xs, **kw)")
        callref = next(a.rhs for a in _assigns(ir) if isinstance(a.rhs, CallRef))
        # Args contient un Star(double=False), kwargs contient (** , Star)
        assert len(callref.args) == 1
        assert isinstance(callref.args[0], Star)


# ============================================================================
# Lambda / FunctionDef / ClassDef (opaques)
# ============================================================================

class TestOpaques:

    def test_function_def(self):
        ir = _lower("def f(x, y):\n    return x + y")
        f_assign = next((a for a in _assigns(ir) if a.lhs == VarLhs("f")), None)
        assert f_assign is not None
        assert isinstance(f_assign.rhs, LambdaRef)
        assert f_assign.rhs.arg_names == ("x", "y")

    def test_class_def(self):
        ir = _lower("class C:\n    pass")
        c_assign = next((a for a in _assigns(ir) if a.lhs == VarLhs("C")), None)
        assert c_assign is not None
        assert isinstance(c_assign.rhs, LambdaRef)

    def test_lambda_expression(self):
        ir = _lower("f = lambda x: x + 1")
        # f est assigné à un LambdaRef (potentiellement via un temp)
        # Cherche LambdaRef dans n'importe quel RHS
        assert any(isinstance(a.rhs, LambdaRef) for a in _assigns(ir))


# ============================================================================
# Import / ImportFrom
# ============================================================================

class TestImports:

    def test_import_simple(self):
        ir = _lower("import os")
        # `os := __import__('os')`
        a = ir[0]
        assert isinstance(a, Assign)
        assert a.lhs == VarLhs("os")
        assert isinstance(a.rhs, CallRef)

    def test_import_as(self):
        ir = _lower("import os.path as p")
        a = ir[0]
        # Premier symbole du dotted name
        assert isinstance(a.lhs, VarLhs)
        # `os.path as p` → on bind `p`
        # Notre implémentation : utilise asname si fourni
        assert a.lhs.name == "p"

    def test_from_import(self):
        ir = _lower("from os import getenv")
        a = ir[0]
        assert isinstance(a, Assign)
        assert a.lhs == VarLhs("getenv")

    def test_from_import_star_is_noop(self):
        ir = _lower("from os import *")
        assert any(isinstance(s, Noop) for s in ir)


# ============================================================================
# Return / Raise
# ============================================================================

class TestReturnRaise:

    def test_return_value(self):
        # `return` au top-level = SyntaxError, on wrap dans une fonction
        ir = _lower("def f():\n    return 42")
        # `def f` opaque, donc pas de Return dans le module-level IR
        assert not any(isinstance(s, Return) for s in ir)

    def test_return_at_module_level_via_lower_stmt(self):
        """Test direct via lower_stmt qui accepte n'importe quel statement."""
        # Construit un AST Return artificiellement
        ret_stmt = ast.parse("def f():\n    return x").body[0].body[0]
        ir = lower_stmt(ret_stmt)
        assert len(ir) == 1
        assert isinstance(ir[0], Return)
        assert ir[0].value == VarRef("x")

    def test_raise_at_module_level(self):
        ir = _lower("raise ValueError('oops')")
        # `raise` produit un Raise IR
        assert any(isinstance(s, Raise) for s in ir)

    def test_bare_raise(self):
        # Bare raise au top-level = invalide, on wrap dans except
        src = "try:\n    pass\nexcept:\n    raise"
        ir = _lower(src)
        assert any(isinstance(s, Raise) for s in ir)


# ============================================================================
# Comprehensions
# ============================================================================

class TestComprehensions:

    def test_list_comprehension_yields_listref(self):
        ir = _lower("y = [x*x for x in xs]")
        last = _assigns(ir)[-1]
        # y := __tN qui était assigné à un ListRef agrégeant iter + elt
        # On cherche un ListRef quelque part dans le chemin du taint
        # ListRef peut être dans rhs directement ou via le dernier temp
        assert isinstance(last.rhs, (VarRef, ListRef))

    def test_dict_comprehension(self):
        ir = _lower("d = {k: v for k, v in pairs}")
        # Cherche un DictRef
        # (peut être noyé dans un temp, mais le test vérifie qu'on ne crash pas)
        names = {a.lhs.name for a in _assigns(ir) if isinstance(a.lhs, VarLhs)}
        assert "d" in names


# ============================================================================
# Slicing / Subscripts
# ============================================================================

class TestSlicing:

    def test_simple_subscript(self):
        ir = _lower("y = a[i]")
        assigns = _assigns(ir)
        # Le dernier doit être y := <SubscriptRef ou VarRef>
        # Le SubscriptRef est dans le RHS direct (pas linéarisé en temp).
        last = assigns[-1]
        assert last.lhs == VarLhs("y")

    def test_attribute_chain(self):
        ir = _lower("y = a.b.c")
        last = _assigns(ir)[-1]
        # AttrRef chaîné
        assert isinstance(last.rhs, AttrRef)


# ============================================================================
# Canonicalisation
# ============================================================================

class TestCanonicalisation:

    def test_canon_lhs_var(self):
        assert canon_lhs(VarLhs("x")) == "x"

    def test_canon_lhs_attr(self):
        assert canon_lhs(AttrLhs(base=VarRef("obj"), attr="attr")) == "obj.attr"

    def test_canon_lhs_attr_nested(self):
        nested = AttrLhs(base=AttrRef(VarRef("a"), "b"), attr="c")
        assert canon_lhs(nested) == "a.b.c"

    def test_canon_lhs_subscript_const(self):
        s = SubscriptLhs(base=VarRef("a"), key=Const(0))
        assert canon_lhs(s) == "a[0]"

    def test_canon_lhs_subscript_var(self):
        s = SubscriptLhs(base=VarRef("a"), key=VarRef("k"))
        assert canon_lhs(s) == "a[*]"

    def test_canon_callee_simple(self):
        assert canon_callee(VarRef("foo")) == "foo"

    def test_canon_callee_dotted(self):
        sub = AttrRef(base=VarRef("subprocess"), attr="run")
        assert canon_callee(sub) == "subprocess.run"

    def test_canon_callee_deep(self):
        deep = AttrRef(
            base=AttrRef(base=VarRef("a"), attr="b"),
            attr="c",
        )
        assert canon_callee(deep) == "a.b.c"

    def test_canon_callee_unknown_for_callref(self):
        cr = CallRef(callee=VarRef("get_obj"))
        # On utilise CallRef comme base d'un AttrRef
        method = AttrRef(base=cr, attr="method")
        assert "<call>" in canon_callee(method)


# ============================================================================
# Pretty printing (smoke test, pas de régression)
# ============================================================================

class TestPretty:

    def test_pretty_simple_assign(self):
        ir = _lower("x = 1")
        out = pretty_stmts(ir)
        assert "x" in out
        assert "1" in out

    def test_pretty_call(self):
        ir = _lower("y = foo(a, b)")
        out = pretty_stmts(ir)
        assert "foo" in out


# ============================================================================
# Robustesse
# ============================================================================

class TestRobustness:

    def test_lower_module_rejects_non_module(self):
        with pytest.raises(TypeError):
            lower_module(ast.parse("x = 1").body[0])  # type: ignore[arg-type]

    def test_empty_module(self):
        ir = _lower("")
        assert ir == []

    def test_pass_statement(self):
        ir = _lower("pass")
        assert ir == [Noop(lineno=1)]

    def test_global_and_nonlocal_noop(self):
        # `nonlocal x` au top-level est SyntaxError, juste global
        ir = _lower("def f():\n    global x")
        # `def f` est opaque, donc on ne voit pas le `global x` au top-level
        assert any(isinstance(a, Assign) and a.lhs == VarLhs("f") for a in ir)

    def test_delete_statement(self):
        ir = _lower("del x")
        assigns = _assigns(ir)
        # `del x` → `x := None`
        assert any(a.lhs == VarLhs("x") and a.rhs == Const(None) for a in assigns)


# ============================================================================
# Cohérence : tout RHS lowered doit être un type RHS valide
# ============================================================================

class TestTypeCoherence:

    @pytest.mark.parametrize("src", [
        "x = 1",
        "x = a + b",
        "x = foo(bar(y))",
        "x = a.b.c",
        "x = a[b]",
        "x = (1, 2, 3)",
        "x = [1, 2]",
        "x = {1: 2}",
        "x = a and b or c",
        "x = a if cond else b",
        "x = -a",
        "x = a < b",
    ])
    def test_all_assigns_have_valid_rhs(self, src):
        from sca.dataflow.ir import IfExp, RHS as RHSType
        ir = _lower(src)
        for stmt in ir:
            if isinstance(stmt, Assign):
                # Vérifier que rhs est l'un des sous-types de RHS
                # (typing.Union ne supporte pas isinstance, on utilise les types concrets)
                valid_types = (Const, VarRef, AttrRef, SubscriptRef, CallRef,
                               BinOp, UnaryOp, Cmp, Bool,
                               TupleRef, ListRef, DictRef, SetRef,
                               LambdaRef, Star, IfExp)
                assert isinstance(stmt.rhs, valid_types), (
                    f"rhs is {type(stmt.rhs).__name__} in IR of: {src}"
                )
