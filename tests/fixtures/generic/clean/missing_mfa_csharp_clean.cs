// @audit-fixture
// @rule: missing_mfa_csharp
// @category: security
// @expected: clean
var result = await _signInManager.PasswordSignInAsync(email, password, false, false);
if (result.RequiresTwoFactor) {
    var twoFa = await _signInManager.TwoFactorSignInAsync("Authenticator", code, false, false);
}
