// @audit-fixture
// @rule: taint_xss
// @expected: detected
import javax.servlet.http.*;
public class XssServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        response.getWriter().println("<h1>Hello " + name + "</h1>");
    }
}
