<?php
// @audit-fixture
// @rule: taint_path_traversal
// @expected: detected
$file = $_GET['file'];
echo file_get_contents('/var/data/' . $file);
