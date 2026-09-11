# @audit-fixture
# @rule: missing_mfa_python
# @category: security
# @expected: detected

from django.contrib.auth import authenticate, login

# Authentication without MFA
def login_view(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        return redirect('/dashboard')
