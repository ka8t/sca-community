# @rule: missing_mfa_python
# @kind: vulnerable
# VULNERABLE: missing_mfa_python
# Expected  : Should trigger missing_mfa_python (python)

    def login(request):
        user = authenticate(username, password)
        login_user(user)  # no MFA step
