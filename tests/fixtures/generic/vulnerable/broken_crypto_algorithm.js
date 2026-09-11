// @rule: broken_crypto_algorithm
// @kind: vulnerable
// VULNERABLE: broken_crypto_algorithm
// Expected  : Should trigger broken_crypto_algorithm (javascript)

    const cipher = crypto.createCipher("des", key);
