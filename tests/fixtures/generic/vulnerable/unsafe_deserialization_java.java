// @audit-fixture
// @rule: unsafe_deserialization_java
// @category: security
// @expected: detected
// VULNERABLE: ObjectInputStream.readObject() sur stream HTTP (CWE-502)
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class PayloadHandler {
    public Object processUpload(HttpServletRequest request) throws Exception {
        var stream = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(stream);
        Object obj = ois.readObject();
        return obj;
    }
}
