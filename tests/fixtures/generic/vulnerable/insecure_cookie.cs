// @audit-fixture
// @rule: insecure_cookie
// @kind: vulnerable
// VULNERABLE: Response.Cookies.Append sans CookieOptions{ Secure=true, HttpOnly=true }
using Microsoft.AspNetCore.Mvc;

public class LoginController : Controller {
    public IActionResult Login() {
        Response.Cookies.Append("session", "abc123");
        return Ok();
    }
}
