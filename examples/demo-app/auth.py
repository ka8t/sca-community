# Intentionally vulnerable demo app — DO NOT deploy this anywhere.

def login(request):
    # Missing MFA: authentication succeeds without a second factor
    # (missing_mfa_python).
    user = authenticate(request.form["username"], request.form["password"])
    login_user(user)  # no MFA step
