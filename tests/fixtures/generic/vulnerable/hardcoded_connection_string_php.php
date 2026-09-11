<?php
// @rule: hardcoded_connection_string_php
// @kind: vulnerable
// VULNERABLE: hardcoded_connection_string_php
// Expected  : Should trigger hardcoded_connection_string_php (php)

$pdo = new PDO("mysql:host=localhost;dbname=app", "root", "secret123");
