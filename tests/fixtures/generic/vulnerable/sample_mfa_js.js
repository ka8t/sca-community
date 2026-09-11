// @audit-fixture
// @rule: missing_mfa_javascript
// @category: security
// @expected: detected

const passport = require('passport');
const jwt = require('jsonwebtoken');

// Authentication without MFA
function login(req, res) {
    passport.authenticate('local', function(err, user) {
        const token = jwt.sign({ id: user.id }, 'secret');
        res.json({ token });
    })(req, res);
}
