// @audit-fixture
// @rule: taint_xss
// @category: security
// @expected: clean
using System.Web;
public class HomeController : Controller {
    public IActionResult Index() {
        var name = HttpUtility.HtmlEncode(Request.Query["name"]);
        Response.Write(name);
        return View();
    }
}
