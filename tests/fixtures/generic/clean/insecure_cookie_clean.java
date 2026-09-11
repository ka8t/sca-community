// @audit-fixture
// @rule: insecure_cookie
// @category: security
// @expected: clean
Cookie cookie = new Cookie("session", value);
cookie.setHttpOnly(true);
cookie.setSecure(true);
response.addCookie(cookie);
