<?php
// @audit-fixture
// @rule: hardcoded_connection_string_php
// @category: security
// @expected: clean

$pdo = new PDO(getenv('DB_DSN'), getenv('DB_USER'), getenv('DB_PASSWORD'));
