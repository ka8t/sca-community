// @audit-fixture
// @rule: taint_codeinj
// @category: security
// @expected: clean
public class EvalServlet extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("report", "status");
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String op = request.getParameter("op");
        if (!ALLOWED.contains(op)) { response.sendError(400); return; }
        // Exécuter l'opération depuis une liste blanche
    }
}
