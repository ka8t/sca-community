// @rule: weak_crypto_csharp
// @kind: vulnerable
// VULNERABLE: weak_crypto_csharp
// Expected  : Should trigger weak_crypto_csharp (csharp)

    var hash = MD5.Create().ComputeHash(data);
