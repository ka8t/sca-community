// @audit-fixture
// @rule: taint_open_redirect
// @expected: detected
public class AccountController : Controller {
    public IActionResult Login() {
        return Redirect(Request.Query["returnUrl"]);
    }
}
