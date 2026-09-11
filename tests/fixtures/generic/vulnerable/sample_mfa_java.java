// @audit-fixture
// @rule: missing_mfa_java
// @category: security
// @expected: detected

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

// Authentication without MFA
public class AuthService {
    private AuthenticationManager authenticationManager;

    public void login(String username, String password) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );
    }
}
