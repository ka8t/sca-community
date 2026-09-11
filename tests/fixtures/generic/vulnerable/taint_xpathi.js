// @audit-fixture
// @rule: taint_xpathi
// @expected: detected
const xpath = require('xpath');
const express = require('express');
const app = express();
app.get('/users', (req, res) => {
    const name = req.query.name;
    const nodes = xpath.select("//user[@name='" + name + "']", doc);
    res.json(nodes);
});
