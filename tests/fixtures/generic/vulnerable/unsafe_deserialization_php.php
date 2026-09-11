<?php
// @audit-fixture
// @rule: unsafe_deserialization_php
// @category: security
// @expected: detected
// VULNERABLE: unserialize() sur input HTTP (CWE-502)

function process_payload() {
    $data = $_POST['payload'];
    $obj = unserialize($data);
    return $obj;
}
