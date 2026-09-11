// @audit-fixture
// @rule: taint_xss
// @expected: detected
public class HomeController : Controller {
    public IActionResult Index() {
        var name = Request.Query["name"];
        Response.Write(name);
        return View();
    }
}
