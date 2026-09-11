// @audit-fixture
// @rule: taint_sqli
// @expected: detected
import javax.servlet.http.HttpServletRequest;
import java.sql.*;

public class UserController {
    public void findUser(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
