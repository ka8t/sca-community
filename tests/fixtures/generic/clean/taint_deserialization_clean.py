# @audit-fixture
# @rule: taint_deserialization
# @category: security
# @expected: clean
import json
from flask import request
@app.route("/load")
def load():
    data = request.data
    obj = json.loads(data)
