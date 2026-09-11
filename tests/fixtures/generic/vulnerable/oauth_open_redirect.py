# @audit-fixture
# @rule: oauth_open_redirect
# @category: security
# @expected: detected
redirect_uri = request.args.get("redirect_uri")
return redirect(redirect_uri)
