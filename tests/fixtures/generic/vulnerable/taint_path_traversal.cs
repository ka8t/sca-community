// @audit-fixture
// @rule: taint_path_traversal
// @expected: detected
public class FileController : Controller {
    public IActionResult Download() {
        var file = Request.Query["file"];
        var content = System.IO.File.ReadAllText(file);
        return Content(content);
    }
}
