# @audit-fixture
# @rule: taint_sqli
# @category: security
# @expected: detected
from flask import request
@app.route("/users")
def users():
    name = request.args.get("name")
    db.execute(f"SELECT * FROM users WHERE name = '{name}'")
