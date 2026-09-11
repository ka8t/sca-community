# @audit-fixture
# @rule: taint_ldap
# @category: security
# @expected: detected
from flask import request
import ldap
@app.route("/search")
def search():
    user = request.args.get("user")
    conn.search_s("dc=example", ldap.SCOPE_SUBTREE, f"(uid={user})")
