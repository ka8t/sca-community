// @audit-fixture
// @rule: taint_rce
// @expected: detected
const { execSync } = require("child_process");
const express = require("express");
const app = express();
app.get("/run", (req, res) => {
    const cmd = req.query.cmd;
    execSync(cmd);
});
