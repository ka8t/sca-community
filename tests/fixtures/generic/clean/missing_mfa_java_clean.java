// @audit-fixture
// @rule: missing_mfa_java
// @category: security
// @expected: clean
authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user, pass));
if (requiresTwoFactor(user)) {
    var verified = googleAuthenticator.authorize(user.getSecret(), code);
}
