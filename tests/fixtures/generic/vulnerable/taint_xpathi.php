<?php
// @audit-fixture
// @rule: taint_xpathi
// @expected: detected
$dom = new DOMDocument();
$dom->loadXML($xmlData);
$xpath = new DOMXPath($dom);
$results = $xpath->query("//user[@name='" . $_GET['name'] . "']");
