// @audit-fixture
// @rule: missing_mfa_javascript
// @category: security
// @expected: clean
const speakeasy = require('speakeasy');
passport.authenticate('local', (err, user) => {
    const verified = speakeasy.totp.verify({ secret: user.otpSecret, token: req.body.otp });
});
