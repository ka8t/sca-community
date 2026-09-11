# @audit-fixture
# @rule: taint_rce
# @category: security
# @expected: detected
import subprocess
from flask import request
@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    subprocess.call(cmd, shell=True)
