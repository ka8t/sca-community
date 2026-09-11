<?php
// @audit-fixture
// @rule: taint_open_redirect
// @expected: detected
$next = $_GET['next'];
header('Location: ' . $next);
