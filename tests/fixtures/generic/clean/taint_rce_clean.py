# @audit-fixture
# @rule: taint_rce
# @category: security
# @expected: clean
import subprocess, shlex
from flask import request
@app.route("/run")
def run():
    cmd = shlex.quote(request.args.get("cmd"))
    subprocess.call(["echo", cmd])
