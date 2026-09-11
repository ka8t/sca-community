<?php
// @audit-fixture
// @rule: taint_ldap
// @category: security
// @expected: clean
$conn = ldap_connect("ldap://localhost");
$user = ldap_escape($_GET['user'], '', LDAP_ESCAPE_FILTER);
$results = ldap_search($conn, "dc=example,dc=com", "(uid=" . $user . ")");
