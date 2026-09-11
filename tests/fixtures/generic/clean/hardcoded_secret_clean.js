// @audit-fixture
// @rule: hardcoded_secret
// @category: security
// @expected: clean
const API_KEY = process.env.API_KEY;
const DB_URL = process.env.DATABASE_URL;
