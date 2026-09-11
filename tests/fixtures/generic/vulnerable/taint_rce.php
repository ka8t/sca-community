<?php
// @audit-fixture
// @rule: taint_rce
// @expected: detected
$cmd = $_GET['cmd'];
system($cmd);
