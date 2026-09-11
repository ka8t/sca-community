// @audit-fixture
// @rule: insecure_random
// @category: security
// @expected: clean
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
