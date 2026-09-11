// @audit-fixture
// @rule: missing_mfa_javascript
// @category: security
// @expected: clean

const passport = require('passport');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');

// Authentication WITH MFA (speakeasy)
function login(req, res) {
    passport.authenticate('local', function(err, user) {
        const verified = speakeasy.totp.verify({
            secret: user.otpSecret,
            encoding: 'base32',
            token: req.body.otpCode
        });
        if (verified) {
            const token = jwt.sign({ id: user.id }, 'secret');
            res.json({ token });
        }
    })(req, res);
}
