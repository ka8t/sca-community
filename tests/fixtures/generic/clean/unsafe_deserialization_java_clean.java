// @audit-fixture
// @rule: unsafe_deserialization_java
// @category: security
// @expected: clean
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
// Fixed: use activateDefaultTyping with validator
