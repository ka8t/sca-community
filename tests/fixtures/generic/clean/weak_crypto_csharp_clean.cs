// @audit-fixture
// @rule: weak_crypto_csharp
// @category: security
// @expected: clean
using System.Security.Cryptography;
var hash = SHA256.HashData(data);
