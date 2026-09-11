# CLEAN: Safe alternative to eval - no dynamic code execution
# Expected: Should NOT trigger "Eval/Exec dangereux" detection

from flask import request

ALLOWED_OPS = {"+": lambda a, b: a + b, "-": lambda a, b: a - b}

def process_formula():
    op = request.args.get("op")
    a = float(request.args.get("a", 0))
    b = float(request.args.get("b", 0))
    if op in ALLOWED_OPS:
        return {"result": ALLOWED_OPS[op](a, b)}
    return {"error": "Invalid operator"}
