// Fixture vulnérable : path traversal Java — fichier ouvert avec entrée utilisateur
import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class FileController {
    public byte[] download(HttpServletRequest request) throws Exception {
        String path = request.getParameter("path");
        File file = new File(path);
        return java.nio.file.Files.readAllBytes(file.toPath());
    }

    // Multi-ligne : new File sur plusieurs lignes
    public byte[] downloadMultiline(HttpServletRequest request) throws Exception {
        String path = request.getParameter("path");
        File file = new File(
            path
        );
        return java.nio.file.Files.readAllBytes(file.toPath());
    }
}
