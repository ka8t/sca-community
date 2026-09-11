<?php
// @audit-fixture
// @rule: taint_path_traversal
// @category: security
// @expected: clean
$file = basename($_GET['file']);
echo file_get_contents('/var/data/' . $file);
