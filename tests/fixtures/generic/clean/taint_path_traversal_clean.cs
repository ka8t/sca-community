// @audit-fixture
// @rule: taint_path_traversal
// @category: security
// @expected: clean
public class FileController : Controller {
    public IActionResult Download() {
        var baseDir = @"C:\data\";
        var safe = Path.GetFullPath(Path.Combine(baseDir, Request.Query["file"]));
        if (!safe.StartsWith(baseDir)) return Forbid();
        var content = System.IO.File.ReadAllText(safe);
        return Content(content);
    }
}
