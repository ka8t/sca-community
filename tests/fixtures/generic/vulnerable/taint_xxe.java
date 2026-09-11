// @audit-fixture
// @rule: taint_xxe
// @expected: detected
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.*;

public class XmlController {
    public void parse(HttpServletRequest request) throws Exception {
        String xml = request.getParameter("xml");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(new org.xml.sax.InputSource(new java.io.StringReader(xml)));
    }
}
