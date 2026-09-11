// @audit-fixture
// @rule: weak_crypto_java
// @category: security
// @expected: clean
import java.security.MessageDigest;
MessageDigest md = MessageDigest.getInstance("SHA-256");
