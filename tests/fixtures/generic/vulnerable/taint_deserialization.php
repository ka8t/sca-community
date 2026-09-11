<?php
// @audit-fixture
// @rule: taint_deserialization
// @expected: detected
$data = $_POST['data'];
$obj = unserialize($data);
var_dump($obj);
