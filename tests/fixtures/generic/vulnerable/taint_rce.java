// @audit-fixture
// @rule: taint_rce
// @expected: detected
import javax.servlet.http.HttpServletRequest;

public class CmdController {
    public void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
