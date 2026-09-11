// @audit-fixture
// @rule: hardcoded_connection_string
// @category: security
// @expected: clean

    var conn = new SqlConnection(ConfigurationManager.ConnectionStrings["AppDb"].ConnectionString);
