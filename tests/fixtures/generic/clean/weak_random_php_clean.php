<?php
// @audit-fixture
// @rule: weak_random_php
// @category: security
// @expected: clean
$token = bin2hex(random_bytes(32));
