// @audit-fixture
// @rule: taint_codeinj
// @category: security
// @expected: clean
const express = require('express');
const app = express();
const ALLOWED = { add: (a, b) => a + b, mul: (a, b) => a * b };
app.post('/run', (req, res) => {
    const fn = ALLOWED[req.body.op];
    if (!fn) return res.status(400).json({ error: 'Invalid op' });
    res.json({ result: fn(req.body.a, req.body.b) });
});
