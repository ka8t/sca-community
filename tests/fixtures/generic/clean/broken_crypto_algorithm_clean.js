// @audit-fixture
// @rule: broken_crypto_algorithm
// @category: security
// @expected: clean

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
