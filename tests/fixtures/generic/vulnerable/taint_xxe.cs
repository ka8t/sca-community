// @audit-fixture
// @rule: taint_xxe
// @expected: detected
using System.Xml.Linq;
public class XmlController : Controller {
    public IActionResult Parse() {
        var doc = XDocument.Parse(Request.Body.ToString());
        return Ok();
    }
}
