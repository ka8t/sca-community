# @audit-fixture
# @rule: weak_crypto
# @category: security
# @expected: clean
import hashlib
def h(data): return hashlib.sha256(data.encode()).hexdigest()
