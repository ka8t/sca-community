# @audit-fixture
# @rule: insecure_deserialize_call
# @category: security
# @expected: detected
import pickle
data = pickle.loads(request.data)
