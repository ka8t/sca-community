<?php
// @audit-fixture
// @rule: taint_xss
// @expected: detected
$name = $_GET['name'];
echo "<h1>Hello " . $name . "</h1>";
