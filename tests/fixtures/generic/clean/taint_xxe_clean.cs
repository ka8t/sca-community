// @audit-fixture
// @rule: taint_xxe
// @category: security
// @expected: clean
using System.Xml;
using System.Xml.Linq;
public class XmlController : Controller {
    public IActionResult Parse() {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        var doc = XDocument.Load(XmlReader.Create(new StringReader(body), settings));
        return Ok();
    }
}
