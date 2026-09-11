// @audit-fixture
// @rule: insecure_cookie_flag
// @category: security
// @expected: detected

package com.example.vulnerable;

import javax.servlet.http.*;

public class CookieController extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = new Cookie("session_id", "abc123");
        cookie.setSecure(false);
        response.addCookie(cookie);
    }
}
