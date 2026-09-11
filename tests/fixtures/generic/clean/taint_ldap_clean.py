# @audit-fixture
# @rule: taint_ldap
# @category: security
# @expected: clean
from flask import request
import ldap
@app.route("/search")
def search():
    user = ldap.filter.escape_filter_chars(request.args.get("user"))
    conn.search_s("dc=example", ldap.SCOPE_SUBTREE, f"(uid={user})")
