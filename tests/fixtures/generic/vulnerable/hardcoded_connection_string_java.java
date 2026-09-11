// @rule: hardcoded_connection_string_java
// @kind: vulnerable
// VULNERABLE: hardcoded_connection_string_java
// Expected  : Should trigger hardcoded_connection_string_java (java)

Connection conn = DriverManager.getConnection("jdbc:mysql://db/app", "root", "secret123");
