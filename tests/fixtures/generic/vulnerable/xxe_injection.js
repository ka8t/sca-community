// @audit-fixture
// @rule: xxe_injection
// @category: security
// @expected: detected
// VULNERABLE: parse XML user input avec DOMParser sans desactiver entites (CWE-611)
const doc = (new DOMParser()).parseFromString(req.body, 'text/xml');
