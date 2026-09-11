// @audit-fixture
// @rule: insecure_cookie
// @category: security
// @expected: clean
Response.Cookies.Append("session", value, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
