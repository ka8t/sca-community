// @audit-fixture
// @rule: taint_xss
// @category: security
// @expected: clean
// Sinks a nom generique (println/format) sur un recepteur qui n'ecrit
// jamais dans la reponse HTTP -- System.out (console) et String.format
// (construction de chaine, pas d'ecriture). Doit rester clean meme avec
// une donnee utilisateur en entree (cf. faux positifs JeecgBoot 2026-08-04).
import javax.servlet.http.*;
public class DebugServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        System.out.println("Debug: received name=" + name);
        System.err.printf("name=%s%n", name);
        String cacheKey = String.format("user:%s", name);
    }
}
