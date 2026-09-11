// @audit-fixture
// @rule: insecure_cookie
// @kind: vulnerable
// VULNERABLE: cookie sans httpOnly/secure/sameSite — accessible en JS (XSS)
//             et envoyé en HTTP non chiffré (CWE-614).
const express = require("express");
const app = express();
app.post("/login", (req, res) => {
    res.cookie("session", "abc123");
    res.send("OK");
});
