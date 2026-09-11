// @rule: weak_random_java
// @kind: vulnerable
// VULNERABLE: weak_random_java
// Expected  : Should trigger weak_random_java (java)

    int token = new Random().nextInt();
