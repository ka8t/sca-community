# @audit-fixture
# @rule: xss_flask_reflected
# @category: security
# @expected: detected
# VULNERABLE: construction reponse par concatenation (XSS reflechi) (CWE-79)
from flask import request
def render():
    RESPONSE = "<html>"
    RESPONSE += request.args.get("name", "")
    return RESPONSE
