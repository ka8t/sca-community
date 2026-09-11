// @audit-fixture
// @category: security
// @expected: detected
// VULNERABLE: Redirect avec URL utilisateur (CWE-601)
public class HomeController {
    public object Login(System.Web.HttpRequest Request) {
        return Redirect(Request.QueryString["returnUrl"]);
    }
    object Redirect(object url) { return null; }
}
