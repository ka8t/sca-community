// @audit-fixture
// @rule: weak_crypto_java
// @category: security
// @expected: detected
// VULNERABLE: MD5 (algorithme cryptographique faible) (CWE-327)
import java.security.MessageDigest;
public class Hasher {
    public byte[] hash(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
