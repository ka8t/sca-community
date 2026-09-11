// Fixture clean : cookie Java avec setHttpOnly et setSecure
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class AuthController {
    public void login(HttpServletResponse response) {
        Cookie cookie = new Cookie("session_id", "abc123");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
