<?php
// @audit-fixture
// @rule: missing_mfa_php
// @category: security
// @expected: detected

use Illuminate\Support\Facades\Auth;

// Authentication without MFA
class LoginController
{
    public function login(Request $request)
    {
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            return redirect('/dashboard');
        }
    }
}
