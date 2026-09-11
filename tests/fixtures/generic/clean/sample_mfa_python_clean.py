# @audit-fixture
# @rule: missing_mfa_python
# @category: security
# @expected: clean

import pyotp
from django.contrib.auth import authenticate, login

# Authentication WITH MFA (pyotp)
def login_view(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if user is not None:
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(request.POST['otp_code']):
            login(request, user)
            return redirect('/dashboard')
