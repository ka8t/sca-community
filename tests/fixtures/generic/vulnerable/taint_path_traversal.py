# @audit-fixture
# @rule: taint_path_traversal
# @category: security
# @expected: detected
from flask import request
@app.route("/file")
def get_file():
    path = request.args.get("path")
    return open(path).read()
