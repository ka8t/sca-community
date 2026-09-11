# @audit-fixture
# @rule: insecure_cookie
# @category: security
# @expected: clean
resp.set_cookie('session', value, httponly=True, secure=True, samesite='Lax')
