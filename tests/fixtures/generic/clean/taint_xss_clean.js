// @audit-fixture
// @rule: taint_xss
// @category: security
// @expected: clean
from flask import request
from markupsafe import escape
@app.route("/hello")
def hello():
    name = escape(request.args.get("name"))
    return f"<h1>Hello {name}</h1>"
