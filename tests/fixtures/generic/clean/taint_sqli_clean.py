# @audit-fixture
# @rule: taint_sqli
# @expected: clean
def get_user(user_id):
    db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
