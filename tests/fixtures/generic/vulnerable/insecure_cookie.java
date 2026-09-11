// @audit-fixture
// @rule: insecure_cookie
// @kind: vulnerable
// VULNERABLE: new Cookie sans appel setSecure / setHttpOnly / setSameSite (CWE-614)
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet {
    public void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Cookie cookie = new Cookie("session", "abc123");
        resp.addCookie(cookie);
    }
}
