# @audit-fixture
# @rule: taint_path_traversal
# @category: security
# @expected: clean
import os
from flask import request
@app.route("/file")
def get_file():
    path = os.path.realpath(os.path.join("/safe", request.args.get("path")))
    if not path.startswith("/safe"):
        abort(403)
    return open(path).read()
