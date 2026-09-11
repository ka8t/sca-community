<?php
// @audit-fixture
// @rule: taint_codeinj
// @category: security
// @expected: clean
$allowed = ['report', 'status'];
$op = $_POST['op'];
if (!in_array($op, $allowed, true)) { http_response_code(400); exit; }
// Exécuter depuis la liste blanche
