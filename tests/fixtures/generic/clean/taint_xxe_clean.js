// @audit-fixture
// @rule: taint_xxe
// @category: security
// @expected: clean
const { parseXml } = require('libxmljs2');
const express = require('express');
const app = express();
app.post('/parse', (req, res) => {
    const doc = parseXml(req.body.xml, { noent: false, nonet: true });
    res.json({ ok: true });
});
