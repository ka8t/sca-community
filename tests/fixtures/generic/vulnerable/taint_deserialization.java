// @audit-fixture
// @rule: taint_deserialization
// @expected: detected
import javax.servlet.http.HttpServletRequest;
import java.io.*;

public class LoadController {
    public void load(HttpServletRequest request) throws Exception {
        byte[] data = request.getInputStream().readAllBytes();
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
    }
}
