<?php
// @audit-fixture
// @rule: missing_mfa_php
// @category: security
// @expected: clean
if (Auth::attempt($credentials)) {
    $verified = Google2FA::verifyKey($user->google2fa_secret, $request->otp);
}
