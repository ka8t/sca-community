// @audit-fixture
// @rule: taint_rce
// @category: security
// @expected: clean
using System.Diagnostics;
public class CommandController : Controller {
    private static readonly string[] ALLOWED = { "report", "status" };
    public IActionResult Run() {
        var cmd = Request.Query["cmd"].ToString();
        if (!ALLOWED.Contains(cmd)) return Forbid();
        Process.Start(cmd);
        return Ok();
    }
}
