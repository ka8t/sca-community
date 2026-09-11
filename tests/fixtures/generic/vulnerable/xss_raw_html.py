# @audit-fixture
# @rule: xss_raw_html
# @category: security
# @expected: detected
# VULNERABLE: rendu HTML brut d'une entrée utilisateur (CWE-79)
from flask import request

def render():
    user_input = request.args.get("name", "")
    return Html.Raw(user_input)
