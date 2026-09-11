// @audit-fixture
// @rule: insecure_cookie_flag
// @category: security
// @expected: clean
Cookie cookie = new Cookie("session_id", "abc123");
cookie.setSecure(true);
cookie.setHttpOnly(true);
response.addCookie(cookie);
