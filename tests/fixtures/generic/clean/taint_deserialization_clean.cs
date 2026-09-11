// @audit-fixture
// @rule: taint_deserialization
// @category: security
// @expected: clean
using Newtonsoft.Json;
public class DataController : Controller {
    public IActionResult Load() {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
        var data = JsonConvert.DeserializeObject<MyDto>(new StreamReader(Request.Body).ReadToEnd(), settings);
        return Ok(data);
    }
}
