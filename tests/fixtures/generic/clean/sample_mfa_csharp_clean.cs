// @audit-fixture
// @rule: missing_mfa_csharp
// @category: security
// @expected: clean

using Microsoft.AspNetCore.Identity;

// Authentication WITH MFA (TwoFactor)
public class AuthService
{
    private readonly SignInManager<IdentityUser> _signInManager;

    public async Task Login(string email, string password, string code)
    {
        var result = await _signInManager.PasswordSignInAsync(email, password, false, false);
        if (result.RequiresTwoFactor)
        {
            var twoFactorResult = await _signInManager.TwoFactorSignInAsync("Authenticator", code, false, false);
        }
    }
}
