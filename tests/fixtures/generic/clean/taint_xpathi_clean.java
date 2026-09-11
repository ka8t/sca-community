// @audit-fixture
// @rule: taint_xpathi
// @category: security
// @expected: clean
import javax.xml.xpath.*;
public class XPathServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Utiliser XPathVariableResolver pour des requêtes paramétrées
        String name = request.getParameter("name").replaceAll("[^\\w]", "");
        String result = xpath.evaluate("//user[@name='" + name + "']", doc);
    }
}
