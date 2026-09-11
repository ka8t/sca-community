// @rule: open_redirect_php
// @kind: vulnerable
// VULNERABLE: open_redirect_php
// Expected  : Should trigger open_redirect_php (php)

    header("Location: " . $_GET["url"]);
