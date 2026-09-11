// @audit-fixture
// @rule: taint_ldap
// @expected: detected
const ldap = require("ldapjs");
const express = require("express");
const app = express();
app.post("/auth", (req, res) => {
    const user = req.body.user;
    const client = ldap.createClient({ url: "ldap://localhost" });
    client.search("dc=example,dc=com", { filter: "(uid=" + user + ")" }, (err, r) => {
        res.json({ ok: !err });
    });
});
