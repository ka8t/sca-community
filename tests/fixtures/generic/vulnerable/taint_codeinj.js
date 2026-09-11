// @audit-fixture
// @rule: taint_codeinj
// @expected: detected
const express = require('express');
const app = express();
app.post('/run', (req, res) => {
    const result = eval(req.body.code);
    res.json({ result });
});
