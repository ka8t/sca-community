// @audit-fixture
// @rule: missing_mfa_java
// @category: security
// @expected: clean

import org.springframework.security.authentication.AuthenticationManager;
import dev.samstevens.totp.code.CodeVerifier;

// Authentication WITH MFA (TOTP)
public class AuthService {
    private AuthenticationManager authenticationManager;
    private CodeVerifier totpVerifier;

    public void login(String username, String password, String totpCode) {
        authenticationManager.authenticate(null);
        if (totpVerifier.isValidCode(secret, totpCode)) {
            // grant access
        }
    }
}
