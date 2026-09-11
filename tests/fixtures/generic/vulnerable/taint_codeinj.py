# @audit-fixture
# @rule: taint_codeinj
# @category: security
# @expected: detected
from flask import request
@app.route("/run")
def run():
    code = request.args.get("code")
    eval(code)
