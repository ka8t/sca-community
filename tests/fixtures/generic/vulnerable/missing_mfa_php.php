<?php
// @audit-fixture
// @category: security
// @expected: detected
// VULNERABLE: Auth::attempt sans MFA (CWE-308)
class LoginController {
    public function login($credentials) {
        return Auth::attempt($credentials);
    }
}
