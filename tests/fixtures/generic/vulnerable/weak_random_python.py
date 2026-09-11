# @audit-fixture
# @rule: weak_random_python
# @category: security
# @expected: detected
import random
def generate_token():
    return random.randint(100000, 999999)
