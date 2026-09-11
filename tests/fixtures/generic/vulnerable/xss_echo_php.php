<?php
// @audit-fixture
// @rule: xss_echo_php
// @category: security
// @expected: detected
// VULNERABLE: echo direct de $_GET sans escape - XSS reflectee (CWE-79)
echo $_GET['name'];
