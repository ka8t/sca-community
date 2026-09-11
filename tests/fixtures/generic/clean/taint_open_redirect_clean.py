# @audit-fixture
# @rule: taint_open_redirect
# @category: security
# @expected: clean
from flask import request, redirect, url_for
@app.route("/go")
def go():
    return redirect(url_for("home"))
