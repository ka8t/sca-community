// @audit-fixture
// @rule: taint_xpathi
// @expected: detected
import javax.xml.xpath.*;
public class XPathServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String result = xpath.evaluate("//user[@name='" + request.getParameter("name") + "']", doc);
    }
}
