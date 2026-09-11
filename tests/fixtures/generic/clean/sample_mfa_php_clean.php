<?php
// @audit-fixture
// @rule: missing_mfa_php
// @category: security
// @expected: clean

use Illuminate\Support\Facades\Auth;
use PragmaRX\Google2FA\Google2FA;

// Authentication WITH MFA (google2fa)
class LoginController
{
    public function login(Request $request)
    {
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $google2fa = new Google2FA();
            if ($google2fa->verifyKey($request->user()->google2fa_secret, $request->otp_code)) {
                return redirect('/dashboard');
            }
        }
    }
}
