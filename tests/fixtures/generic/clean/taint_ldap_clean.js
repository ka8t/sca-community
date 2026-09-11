// @audit-fixture
// @rule: taint_ldap
// @category: security
// @expected: clean
const ldap = require("ldapjs");
const express = require("express");
const app = express();
app.post("/auth", (req, res) => {
    const user = ldap.escapeFilter(req.body.user);
    const client = ldap.createClient({ url: "ldap://localhost" });
    client.search("dc=example,dc=com", { filter: "(uid=" + user + ")" }, (err, r) => {
        res.json({ ok: !err });
    });
});
