// @audit-fixture
// @rule: taint_sqli
// @expected: not detected
import javax.ws.rs.*;
import java.sql.*;
@Path("/users")
public class UserResource {
    @GET
    @Path("/search")
    public String search(@QueryParam("q") String query) throws Exception {
        Connection conn = getConnection();
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, query);
        return ps.executeQuery().toString();
    }
}
