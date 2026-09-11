# @audit-fixture
# @rule: taint_deserialization
# @category: security
# @expected: detected
import pickle
from flask import request
@app.route("/load")
def load():
    data = request.data
    obj = pickle.loads(data)
