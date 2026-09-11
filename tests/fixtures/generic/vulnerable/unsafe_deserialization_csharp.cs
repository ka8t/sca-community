// @audit-fixture
// @rule: unsafe_deserialization_csharp
// @category: security
// @expected: detected
// VULNERABLE: BinaryFormatter.Deserialize sur stream HTTP (CWE-502)
using System.Runtime.Serialization.Formatters.Binary;

public class PayloadHandler {
    public object ProcessUpload() {
        var stream = Request.Body;
        var obj = new BinaryFormatter().Deserialize(stream);
        return obj;
    }
}
