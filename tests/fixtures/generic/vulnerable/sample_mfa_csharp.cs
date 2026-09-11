// @audit-fixture
// @rule: missing_mfa_csharp
// @category: security
// @expected: detected

using Microsoft.AspNetCore.Identity;

// Authentication without MFA
public class AuthService
{
    private readonly SignInManager<IdentityUser> _signInManager;

    public async Task Login(string email, string password)
    {
        var result = await _signInManager.PasswordSignInAsync(email, password, false, false);
    }
}
