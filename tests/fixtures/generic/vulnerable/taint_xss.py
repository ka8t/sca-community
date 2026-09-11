# @audit-fixture
# @rule: taint_xss
# @category: security
# @expected: detected
from flask import request, Markup
@app.route("/hello")
def hello():
    name = request.args.get("name")
    return Markup(f"<h1>Hello {name}</h1>")
