// @audit-fixture
// @rule: insecure_cookie
// @category: security
// @expected: clean
res.cookie('session', value, { httpOnly: true, secure: true, sameSite: 'lax' });
