// @audit-fixture
// @rule: open_redirect
// @category: security
// @expected: detected
app.get("/redirect", (req, res) => {
    res.redirect(req.query.url);
});
