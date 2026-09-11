# VULNERABLE: Dangerous eval/exec with user input
# Expected: Should trigger "Eval/Exec dangereux" detection (HIGH severity)

from flask import request

def process_formula():
    result = eval(request.args.get("formula"))
    return {"result": result}
