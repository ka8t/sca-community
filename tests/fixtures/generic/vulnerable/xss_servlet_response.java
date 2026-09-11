// @audit-fixture
// @rule: xss_servlet_response
// @category: security
// @expected: detected

package com.example.vulnerable;

import javax.servlet.http.*;

public class EchoServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("name");
        try {
            response.getWriter().println("<h1>Hello " + param + "</h1>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
