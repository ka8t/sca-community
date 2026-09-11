<?php
// @audit-fixture
// @rule: taint_sqli
// @category: security
// @expected: clean
from flask import request
@app.route("/users")
def users():
    name = request.args.get("name")
    db.execute("SELECT * FROM users WHERE name = %s", (name,))
