# @audit-fixture
# @rule: taint_codeinj
# @category: security
# @expected: clean
from flask import request
import ast
@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    result = ast.literal_eval(expr)
