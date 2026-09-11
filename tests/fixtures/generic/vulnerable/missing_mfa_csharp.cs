// @audit-fixture
// @category: security
// @expected: detected
// VULNERABLE: PasswordSignInAsync sans 2FA (CWE-308)
public class AccountController {
    public object Login(object signInManager, string user, string pass) {
        return signInManager.PasswordSignInAsync(user, pass, false, false);
    }
}
