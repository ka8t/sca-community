// @audit-fixture
// @rule: taint_deserialization
// @expected: detected
const serialize = require("node-serialize");
const express = require("express");
const app = express();
app.post("/load", (req, res) => {
    const data = req.body.data;
    const obj = serialize.unserialize(data);
    res.json(obj);
});
