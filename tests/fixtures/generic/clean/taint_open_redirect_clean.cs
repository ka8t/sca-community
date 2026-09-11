// @audit-fixture
// @rule: taint_open_redirect
// @category: security
// @expected: clean
public class AccountController : Controller {
    public IActionResult Login() {
        var returnUrl = Request.Query["returnUrl"].ToString();
        if (!Url.IsLocalUrl(returnUrl)) returnUrl = "/";
        return Redirect(returnUrl);
    }
}
