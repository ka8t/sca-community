// @audit-fixture
// @rule: taint_xss
// @category: security
// @expected: clean
import javax.servlet.http.*;
import org.owasp.esapi.ESAPI;
public class XssServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = ESAPI.encoder().encodeForHTML(request.getParameter("name"));
        response.getWriter().println("<h1>Hello " + name + "</h1>");
    }
}
