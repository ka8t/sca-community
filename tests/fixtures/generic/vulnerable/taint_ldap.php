<?php
// @audit-fixture
// @rule: taint_ldap
// @expected: detected
$conn = ldap_connect("ldap://localhost");
$user = $_GET['user'];
$results = ldap_search($conn, "dc=example,dc=com", "(uid=" . $user . ")");
