// @audit-fixture
// @rule: taint_xxe
// @expected: detected
const express = require('express');
const app = express();
app.post('/parse', (req, res) => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(req.body.xml, 'text/xml');
    res.json({ ok: true });
});
