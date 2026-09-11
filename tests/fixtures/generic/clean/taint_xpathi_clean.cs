// @audit-fixture
// @rule: taint_xpathi
// @category: security
// @expected: clean
using System.Xml;
using System.Text.RegularExpressions;
public class XmlController : Controller {
    public IActionResult Search() {
        var name = Regex.Replace(Request.Query["name"].ToString(), @"[^\w]", "");
        var nodes = doc.SelectNodes("//user[@name='" + name + "']");
        return Ok(nodes?.Count);
    }
}
