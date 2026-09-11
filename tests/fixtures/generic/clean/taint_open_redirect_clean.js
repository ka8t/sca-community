// @audit-fixture
// @rule: taint_open_redirect
// @category: security
// @expected: clean
const express = require("express");
const app = express();
const ALLOWED = ["example.com"];
app.get("/login", (req, res) => {
    const next = req.query.next;
    const url = new URL(next);
    if (!ALLOWED.includes(url.host)) return res.redirect("/");
    res.redirect(url.toString());
});
