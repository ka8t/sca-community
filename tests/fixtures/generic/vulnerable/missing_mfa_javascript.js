// @audit-fixture
// @category: security
// @expected: detected
// VULNERABLE: passport.authenticate sans 2FA (CWE-308)
const passport = require("passport");
function login(req, res) {
    return passport.authenticate("local")(req, res);
}
