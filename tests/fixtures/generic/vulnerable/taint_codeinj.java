// @audit-fixture
// @rule: taint_codeinj
// @expected: detected
import javax.script.*;
public class EvalServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        engine.eval(request.getParameter("code"));
    }
}
