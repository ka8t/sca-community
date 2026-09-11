// @rule: insecure_cookie
// @kind: vulnerable
// VULNERABLE: insecure_cookie
// Expected  : Should trigger insecure_cookie (php)

    setcookie("sid", $val);
