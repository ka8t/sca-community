// @rule: hardcoded_connection_string
// @kind: vulnerable
// VULNERABLE: hardcoded_connection_string
// Expected  : Should trigger hardcoded_connection_string (csharp)

    var conn = new SqlConnection("Server=db;Database=app;User Id=sa;Password=Pass@word1;");
