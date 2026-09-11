<?php
// @audit-fixture
// @rule: taint_xxe
// @expected: detected
$xml = simplexml_load_string($_POST['xml']);
var_dump($xml);
