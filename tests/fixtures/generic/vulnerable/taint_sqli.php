<?php
// @audit-fixture
// @rule: taint_sqli
// @expected: detected
$name = $_GET['name'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
