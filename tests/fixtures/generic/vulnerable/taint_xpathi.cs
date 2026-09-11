// @audit-fixture
// @rule: taint_xpathi
// @expected: detected
using System.Xml;
public class XmlController : Controller {
    public IActionResult Search() {
        var nodes = doc.SelectNodes("//user[@name='" + Request.Query["name"] + "']");
        return Ok(nodes?.Count);
    }
}
