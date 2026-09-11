# @rule: insecure_cookie
# @kind: vulnerable
# VULNERABLE: insecure_cookie
# Expected  : Should trigger insecure_cookie (python)

    response.set_cookie("session_id", token)
