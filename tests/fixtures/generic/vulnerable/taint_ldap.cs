// @audit-fixture
// @rule: taint_ldap
// @expected: detected
using System.DirectoryServices;
public class AuthController : Controller {
    public IActionResult Login() {
        var user = Request.Form["user"];
        var searcher = new DirectorySearcher();
        searcher.Filter = "(uid=" + user + ")";
        var result = searcher.FindOne();
        return Ok(result != null);
    }
}
