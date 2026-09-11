<?php
// @audit-fixture
// @rule: unsafe_deserialization_php
// @category: security
// @expected: clean
$data = json_decode($input, true);
