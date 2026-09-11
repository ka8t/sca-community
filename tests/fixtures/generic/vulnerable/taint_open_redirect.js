// @audit-fixture
// @rule: taint_open_redirect
// @expected: detected
const express = require("express");
const app = express();
app.get("/login", (req, res) => {
    const next = req.query.next;
    res.redirect(next);
});
