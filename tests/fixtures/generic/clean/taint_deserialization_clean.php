<?php
// @audit-fixture
// @rule: taint_deserialization
// @category: security
// @expected: clean
$data = $_POST['data'];
$obj = json_decode($data);
var_dump($obj);
