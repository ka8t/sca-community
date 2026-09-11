// @audit-fixture
// @rule: taint_codeinj
// @category: security
// @expected: clean
public class ScriptController : Controller {
    private static readonly string[] ALLOWED = { "report", "status" };
    public IActionResult Run() {
        var op = Request.Query["op"].ToString();
        if (!ALLOWED.Contains(op)) return BadRequest();
        return Ok();
    }
}
