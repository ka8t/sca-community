// @audit-fixture
// @rule: taint_sqli
// @expected: detected
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class UserController : Controller {
    public void Find() {
        var name = Request["name"];
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
        cmd.ExecuteReader();
    }
}
