// @audit-fixture
// @rule: taint_ldap
// @expected: detected
import javax.servlet.http.HttpServletRequest;
import javax.naming.directory.*;

public class LdapController {
    public void search(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        DirContext ctx = new InitialDirContext();
        ctx.search("dc=example", "(uid=" + user + ")", null);
    }
}
