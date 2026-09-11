// @audit-fixture
// @rule: hardcoded_connection_string_java
// @category: security
// @expected: clean

String password = System.getenv("DB_PASSWORD");
Connection conn = DriverManager.getConnection(System.getenv("DB_URL"), "app_service", password);
