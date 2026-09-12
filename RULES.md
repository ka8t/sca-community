# Rule catalog

52 rules across 3 categories — auto-generated from the `.sca` files in `sca/rules/builtin/`. **Do not edit by hand**, regenerate with:

```bash
python3 scripts/generate_rules_catalog.py
```

## cicd (4)

| Rule | Language | Severity | CWE / WCAG | Description |
|---|---|---|---|---|
| `ci_docker_privileged` | yaml | HIGH | CWE-269 | Running a CI/CD container with privileged mode grants full access to the host kernel, devices, and namespaces — equivalent to root on the host system. |
| `docker_latest_tag` | yaml | LOW | CWE-1357 | Using the :latest Docker image tag in CI/CD pipelines causes unpredictable builds as the referenced image may change without notice, potentially introducing breaking changes or vulnerabilities. |
| `hardcoded_secret_cicd` | yaml | CRITICAL | CWE-798 | A secret value (password, token, API key) is hardcoded directly in the CI/CD configuration file and will be exposed to all repository contributors and forks. |
| `unpinned_action_version` | yaml | MEDIUM | CWE-1357 | GitHub Action referenced by branch/tag instead of SHA allows supply chain attacks if the action is compromised. |

## security (44)

| Rule | Language | Severity | CWE / WCAG | Description |
|---|---|---|---|---|
| `broken_crypto_algorithm` | javascript | HIGH | CWE-327 | DES, 3DES (Triple DES), RC2, RC4, and Blowfish are cryptographically broken or obsolete algorithms — DES has a 56-bit key trivially brute-forceable, RC4 has known statistical biases, and RC2 has known attacks. Using them provides no meaningful confidentiality protection (CWE-327). |
| `dockerfile_copy_all` | dockerfile | MEDIUM | CWE-732 | COPY . . copies the entire build context including potential secrets (.env, credentials, SSH keys). |
| `dockerfile_root_user` | dockerfile | HIGH | CWE-250 | Container runs as root user by default, increasing blast radius if compromised (CWE-250). |
| `dockerfile_unpinned_base` | dockerfile | MEDIUM | CWE-1357 | Base image without version tag (FROM node) pulls latest, causing non-reproducible builds and potential supply chain issues. |
| `hardcoded_connection_string` | csharp | HIGH | CWE-259, CWE-321, CWE-798 | A hardcoded database connection string containing credentials (Password=, PWD=, User Id=) embeds plaintext credentials in the source code — visible in version control history, compiled assemblies via decompilation, and cannot be rotated without a code change (CWE-259, CWE-321, CWE-798). |
| `hardcoded_connection_string_java` | java | HIGH | CWE-798 | A JDBC connection uses a hardcoded password literal or a URL with embedded credentials. Credentials hardcoded in source code appear in version control history and can be extracted by anyone with repository access (CWE-798). |
| `hardcoded_connection_string_php` | php | HIGH | CWE-798 | A database connection uses a hardcoded password literal as a direct argument. Credentials in source code appear in version control history, deployment artifacts, and can be extracted by anyone with code access (CWE-798). |
| `hardcoded_secret` | javascript | HIGH | CWE-798 | Plain text secrets in code can be exposed via Git repository. |
| `hardcoded_secret` | python | HIGH | CWE-798 | Plain text secrets in code can be exposed via Git repository. |
| `inline_event_handler_html` | html | MEDIUM | CWE-79 | on* attributes in HTML execute JavaScript directly, vulnerable to XSS (CWE-79). |
| `insecure_cookie` | csharp | MEDIUM | CWE-614 | Cookies without HttpOnly are accessible via JavaScript (XSS). Without Secure, they are sent over unencrypted HTTP (CWE-614, OWASP A05). |
| `insecure_cookie` | javascript | MEDIUM | CWE-614 | Cookies without HttpOnly are accessible via JavaScript (XSS). Without Secure, they are sent over unencrypted HTTP (CWE-614, OWASP A05). |
| `insecure_cookie` | php | MEDIUM | CWE-614 | Cookies without HttpOnly are accessible via JavaScript (XSS). Without Secure, they are sent over unencrypted HTTP (CWE-614, OWASP A05). |
| `insecure_cookie` | python | MEDIUM | CWE-614 | Cookies without HttpOnly are accessible via JavaScript (XSS). Without Secure, they are sent over unencrypted HTTP (CWE-614, OWASP A05). |
| `insecure_cookie_flag` | java | MEDIUM | CWE-614 | Cookie with Secure flag set to false is transmitted over unencrypted HTTP connections (CWE-614). |
| `insecure_random` | javascript | MEDIUM | CWE-330, CWE-338 | Math.random() is predictable and must not be used for tokens, OTPs or keys. |
| `missing_mfa_csharp` | csharp | MEDIUM | CWE-308 | Authentication without multi-factor authentication exposes accounts to credential theft (CWE-308). |
| `missing_mfa_java` | java | MEDIUM | CWE-308 | Authentication without multi-factor authentication exposes accounts to credential theft (CWE-308). |
| `missing_mfa_javascript` | javascript | MEDIUM | CWE-308 | Authentication without multi-factor authentication exposes accounts to credential theft (CWE-308). |
| `missing_mfa_php` | php | MEDIUM | CWE-308 | Authentication without multi-factor authentication exposes accounts to credential theft (CWE-308). |
| `missing_mfa_python` | python | MEDIUM | CWE-308 | Authentication without multi-factor authentication exposes accounts to credential theft (CWE-308). |
| `missing_sri` | html | LOW | CWE-353 | External scripts or stylesheets loaded without integrity attribute can be tampered with if the CDN is compromised (CWE-353). |
| `prototype_pollution` | javascript | HIGH | CWE-1321 | Object.assign or __proto__ with user data allows modifying the global prototype and injecting properties (CWE-1321). |
| `taint_codeinj` | python | HIGH | CWE-94 | An attacker can execute arbitrary Python code on the server. |
| `taint_deserialization` | python | HIGH | CWE-502 | An attacker can achieve remote code execution by sending crafted serialized objects. |
| `taint_ldap` | python | HIGH | CWE-90 | An attacker can modify LDAP queries to bypass authentication or extract data. |
| `taint_open_redirect` | python | HIGH | CWE-601 | An attacker can redirect users to a malicious site via a crafted URL. |
| `taint_path_traversal` | python | HIGH | CWE-22, CWE-23, CWE-73 | An attacker can read or write arbitrary files outside the intended directory. |
| `taint_rce` | python | HIGH | CWE-78 | An attacker can execute arbitrary commands on the server. |
| `taint_sqli` | python | HIGH | CWE-89 | An attacker can read, modify, or delete database records. |
| `taint_xpathi` | python | HIGH | CWE-643 | An attacker can manipulate XPath queries to bypass authentication or extract XML data. |
| `taint_xss` | python | HIGH | CWE-79 | An attacker can inject malicious scripts that execute in other users' browsers. |
| `taint_xxe` | python | HIGH | CWE-611 | An attacker can read local files, perform SSRF, or cause denial of service via malicious XML. |
| `unsafe_deserialization_csharp` | csharp | HIGH | CWE-502 | BinaryFormatter and TypeNameHandling.All allow arbitrary code running via crafted payloads. |
| `unsafe_deserialization_java` | java | HIGH | CWE-502 | ObjectInputStream.readObject() without validation allows arbitrary code running. |
| `unsafe_deserialization_php` | php | HIGH | CWE-502 | unserialize() with untrusted data allows PHP Object Injection attacks. |
| `weak_crypto` | python | HIGH | CWE-327 | MD5 and SHA1 are vulnerable to collisions and must not be used for secure hashing. |
| `weak_crypto_csharp` | csharp | HIGH | CWE-327 | MD5, SHA1, DES, TripleDES and ECB mode are cryptographically broken. |
| `weak_crypto_java` | java | HIGH | CWE-327 | MD5 and SHA-1 are cryptographically broken — vulnerable to collision attacks. |
| `weak_crypto_php` | php | HIGH | CWE-327 | md5()/sha1() are cryptographically broken — vulnerable to collision and rainbow table attacks. |
| `weak_random_csharp` | csharp | MEDIUM | CWE-330 | System.Random is predictable — tokens, sessions, and keys generated with it can be guessed. |
| `weak_random_java` | java | MEDIUM | CWE-330 | java.util.Random is predictable — tokens, sessions, and keys generated with it can be guessed. |
| `weak_random_php` | php | MEDIUM | CWE-330 | rand()/mt_rand() are predictable — tokens and keys generated with them can be guessed. |
| `weak_random_python` | python | MEDIUM | CWE-330 | random module is not cryptographically secure; predictable values enable attacks. |

## ux (4)

| Rule | Language | Severity | CWE / WCAG | Description |
|---|---|---|---|---|
| `focus_outline_removed` | html | MEDIUM | 2.4.7 | Removing the outline prevents keyboard users from seeing which element has focus. |
| `html_no_lang` | html | MEDIUM | 3.1.1 | Screen readers cannot determine the page language, affecting pronunciation. |
| `img_no_alt` | html | MEDIUM | 1.1.1 | Images without alternative text are inaccessible to screen readers and visually impaired users. |
| `missing_doctype` | html | LOW | 4.1.1 | Browser renders in quirks mode, causing inconsistent layout and behavior. |

