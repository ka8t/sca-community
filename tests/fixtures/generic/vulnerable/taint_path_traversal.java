// @audit-fixture
// @rule: taint_path_traversal
// @expected: detected
import javax.servlet.http.*;
import java.nio.file.*;
public class FileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String file = request.getParameter("file");
        byte[] data = Files.readAllBytes(Paths.get("/data/" + file));
        response.getOutputStream().write(data);
    }
}
