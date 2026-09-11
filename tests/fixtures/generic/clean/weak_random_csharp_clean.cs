// @audit-fixture
// @rule: weak_random_csharp
// @category: security
// @expected: clean
using System.Security.Cryptography;
var bytes = RandomNumberGenerator.GetBytes(32);
