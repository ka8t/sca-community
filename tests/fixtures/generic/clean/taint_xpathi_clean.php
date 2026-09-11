<?php
// @audit-fixture
// @rule: taint_xpathi
// @category: security
// @expected: clean
$dom = new DOMDocument();
$dom->loadXML($xmlData);
$xpath = new DOMXPath($dom);
$name = preg_replace('/[^\w]/', '', $_GET['name']);
$results = $xpath->query("//user[@name='$name']");
