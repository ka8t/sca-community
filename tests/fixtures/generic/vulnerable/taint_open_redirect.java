// @audit-fixture
// @rule: taint_open_redirect
// @expected: detected
import javax.servlet.http.*;
public class LoginServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        response.sendRedirect(next);
    }
}
