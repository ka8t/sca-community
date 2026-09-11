// @audit-fixture
// @rule: taint_open_redirect
// @category: security
// @expected: clean
import javax.servlet.http.*;
public class LoginServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        if (!isValidRedirectUrl(next)) next = "/home";
        response.sendRedirect(next);
    }
}
