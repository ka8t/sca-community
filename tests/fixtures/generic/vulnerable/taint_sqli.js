// @audit-fixture
// @rule: taint_sqli
// @expected: detected
const express = require("express");
const app = express();
app.get("/users", (req, res) => {
    const name = req.query.name;
    db.query("SELECT * FROM users WHERE name = '" + name + "'");
});
