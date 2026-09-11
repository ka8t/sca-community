// @audit-fixture
// @rule: taint_path_traversal
// @expected: detected
const fs = require("fs");
const express = require("express");
const app = express();
app.get("/file", (req, res) => {
    const path = req.query.path;
    const data = fs.readFileSync(path, "utf-8");
    res.send(data);
});
