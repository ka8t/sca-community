// @audit-fixture
// @rule: taint_rce
// @expected: detected
using System.Diagnostics;
public class CommandController : Controller {
    public IActionResult Run() {
        var cmd = Request.Query["cmd"];
        Process.Start("cmd.exe", "/c " + cmd);
        return Ok();
    }
}
