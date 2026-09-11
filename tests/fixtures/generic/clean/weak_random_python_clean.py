# @audit-fixture
# @rule: weak_random_python
# @category: security
# @expected: clean
import secrets
def generate_token():
    return secrets.token_hex(32)
