<?php
// @audit-fixture
// @rule: taint_xxe
// @category: security
// @expected: clean
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($_POST['xml'], 'SimpleXMLElement', LIBXML_NONET);
var_dump($xml);
