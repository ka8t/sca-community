// @audit-fixture
// @rule: weak_random_java
// @category: security
// @expected: clean
import java.security.SecureRandom;
SecureRandom sr = new SecureRandom();
int token = sr.nextInt();
