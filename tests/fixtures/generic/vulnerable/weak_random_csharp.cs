// @rule: weak_random_csharp
// @kind: vulnerable
// VULNERABLE: weak_random_csharp
// Expected  : Should trigger weak_random_csharp (csharp)

    var r = new Random().Next();
