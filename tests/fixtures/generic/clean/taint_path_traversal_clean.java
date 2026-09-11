// @audit-fixture
// @rule: taint_path_traversal
// @category: security
// @expected: clean
import javax.servlet.http.*;
import java.nio.file.*;
public class FileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String base = "/data";
        Path safe = Paths.get(base).resolve(request.getParameter("file")).normalize();
        if (!safe.startsWith(base)) { response.sendError(403); return; }
        byte[] data = Files.readAllBytes(safe);
        response.getOutputStream().write(data);
    }
}
