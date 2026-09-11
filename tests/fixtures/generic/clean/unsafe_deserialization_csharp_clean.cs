// @audit-fixture
// @rule: unsafe_deserialization_csharp
// @category: security
// @expected: clean
var data = JsonSerializer.Deserialize<MyClass>(jsonString);
