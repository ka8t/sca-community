<?php
// @audit-fixture
// @rule: insecure_cookie
// @category: security
// @expected: clean
setcookie('session', $value, ['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);
