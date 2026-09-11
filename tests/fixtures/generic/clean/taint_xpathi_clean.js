// @audit-fixture
// @rule: taint_xpathi
// @category: security
// @expected: clean
const xpath = require('xpath');
const express = require('express');
const app = express();
app.get('/users', (req, res) => {
    const select = xpath.useNamespaces({});
    const nodes = select("//user[@name=$name]", doc, null, { name: req.query.name });
    res.json(nodes);
});
