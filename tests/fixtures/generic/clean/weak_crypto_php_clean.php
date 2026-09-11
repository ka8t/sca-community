<?php
// @audit-fixture
// @rule: weak_crypto_php
// @category: security
// @expected: clean
$hash = hash("sha256", $data);
