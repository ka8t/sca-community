// @audit-fixture
// @rule: taint_deserialization
// @expected: detected
using System.Runtime.Serialization.Formatters.Binary;
public class DataController : Controller {
    public IActionResult Load() {
        var formatter = new BinaryFormatter();
        var obj = formatter.Deserialize(Request.Body);
        return Ok(obj);
    }
}
