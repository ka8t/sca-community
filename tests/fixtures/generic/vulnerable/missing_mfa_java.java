// @audit-fixture
// @category: security
// @expected: detected
// VULNERABLE: authenticate sans MFA (CWE-308)
public class AuthService {
    public Object login(Object manager, String user, String pass) {
        return manager.authenticate(new UsernamePasswordAuthenticationToken(user, pass));
    }
    public class UsernamePasswordAuthenticationToken {
        public UsernamePasswordAuthenticationToken(String u, String p) {}
    }
}
