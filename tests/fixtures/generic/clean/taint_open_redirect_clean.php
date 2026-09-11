<?php
// @audit-fixture
// @rule: taint_open_redirect
// @category: security
// @expected: clean
$next = $_GET['next'];
if (!filter_var($next, FILTER_VALIDATE_URL) || parse_url($next, PHP_URL_HOST) !== $_SERVER['HTTP_HOST']) {
    $next = '/';
}
header('Location: ' . $next);
