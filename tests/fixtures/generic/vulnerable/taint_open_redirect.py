# @audit-fixture
# @rule: taint_open_redirect
# @category: security
# @expected: detected
from flask import request, redirect
@app.route("/go")
def go():
    url = request.args.get("url")
    return redirect(url)
