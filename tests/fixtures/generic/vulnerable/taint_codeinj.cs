// @audit-fixture
// @rule: taint_codeinj
// @expected: detected
using Microsoft.CodeAnalysis.CSharp.Scripting;
public class ScriptController : Controller {
    public async Task<IActionResult> Run() {
        var result = await CSharpScript.EvaluateAsync(Request.Query["code"]);
        return Ok(result);
    }
}
