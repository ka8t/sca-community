<?php
// @audit-fixture
// @rule: taint_codeinj
// @expected: detected
$code = $_POST['code'];
eval($code);
