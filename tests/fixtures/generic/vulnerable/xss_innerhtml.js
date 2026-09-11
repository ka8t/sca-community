// @audit-fixture
// @rule: xss_innerhtml
// @category: security
// @expected: detected
// VULNERABLE: XSS via innerHTML depuis input utilisateur (CWE-79)

function displayUser(req, res) {
    const name = req.query.name;
    document.getElementById("name").innerHTML = name;
}
