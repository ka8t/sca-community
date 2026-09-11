// @audit-fixture
// @rule: hardcoded_secret
// @category: security
// @expected: detected
// VULNERABLE: API key Stripe hardcodee (CWE-798)
const API_KEY = "sk_live_abc123def456ghi789jkl012mno345pq";
