"""Registre des fixtures de test — source de vérité fixture ↔ règle.

Format : key → (filename, target_path, rule_key)
"""

# =============================================================================
# LISTE DES FIXTURES DISPONIBLES
# Format: "key": ("filename", "target_path", "rule_name")
# =============================================================================

# --- SECURITY ---
VULNERABLE_FIXTURES = {
    # Remap taint : fixtures multi-langage détectées par les règles taint_* /
    # pattern dédiées. Le moteur n'émet jamais de règle « nue » du nom de la
    # fixture ; la détection passe par taint_* (dataflow) ou la règle pattern
    # propre à la langue (ex. ssrf_python, insecure_cookie).
    "insecure_cookie_js_file": ("insecure_cookie_js.js", "src/js/auth.js", "insecure_cookie"),
    "open_redirect_csharp": ("open_redirect_csharp.cs", "src/AppController.cs", "taint_open_redirect"),
    "open_redirect_php": ("open_redirect_php.php", "src/app.php", "taint_open_redirect"),
    "xss_echo_php": ("xss_echo_php.php", "src/echo.php", "taint_xss"),
    "xss_raw_html_csharp": ("xss_raw_html.cs", "src/HomeController.cs", "taint_xss"),
    "xss_raw_html_py": ("xss_raw_html.py", "src/service.py", "taint_xss"),
    "xxe_injection_js": ("xxe_injection.js", "src/js/parser.js", "taint_xxe"),
    "unsafe_deserialization_py": ("unsafe_deserialization.py", "src/service.py", "taint_deserialization"),
    # Security
    "xss_innerhtml": ("xss_innerhtml.js", "src/js/app.js", "taint_xss"),
    "hardcoded_password": ("hardcoded_password.py", "src/config.py", "hardcoded_secret"),
    "hardcoded_api_key": ("hardcoded_api_key.py", "src/config.py", "hardcoded_secret"),
    "hardcoded_aws_key": ("hardcoded_aws_key.py", "src/config.py", "hardcoded_secret"),
    "hardcoded_github_token": ("hardcoded_github_token.py", "src/config.py", "hardcoded_secret"),
    "hardcoded_stripe_key": ("hardcoded_stripe_key.js", "src/js/app.js", "hardcoded_secret"),
    "hardcoded_slack_token": ("hardcoded_slack_token.py", "src/config.py", "hardcoded_secret"),
    "hardcoded_pem_key": ("hardcoded_pem_key.py", "src/config.py", "hardcoded_secret"),
    "dangerous_eval": ("dangerous_eval.py", "src/service.py", "taint_codeinj"),
    "weak_crypto": ("weak_crypto.py", "src/service.py", "weak_crypto"),
    "unvalidated_input": ("unvalidated_input.py", "src/service.py", "taint_rce"),
    "insecure_random": ("insecure_random.js", "src/js/app.js", "insecure_random"),
    # Supply-chain (TanStack/Mistral npm attack, May 2026)
    # Architecture
    # UI
    # UX
    "img_no_alt": ("img_no_alt.html", "src/index.html", "img_no_alt"),
    "focus_outline_removed": ("focus_outline_removed.js", "src/js/app.js", "focus_outline_removed"),
    # Maintenance
    # UX (suite)
    # Security (suite)
    # Dependencies
    # Dependencies — Java/C#/PHP
    # Java — Security
    "java_unsafe_deser": ("sample_java.java", "src/VulnerableController.java", "unsafe_deserialization_java"),
    "java_weak_crypto": ("sample_java.java", "src/VulnerableController.java", "weak_crypto_java"),
    "java_weak_random": ("sample_java.java", "src/VulnerableController.java", "weak_random_java"),
    # Java — Architecture
    # Java — Maintenance
    # C# — Security
    "csharp_unsafe_deser": ("sample_csharp.cs", "src/VulnerableController.cs", "unsafe_deserialization_csharp"),
    "csharp_weak_crypto": ("sample_csharp.cs", "src/VulnerableController.cs", "weak_crypto_csharp"),
    "csharp_weak_random": ("sample_csharp.cs", "src/VulnerableController.cs", "weak_random_csharp"),
    # C# — Architecture
    # C# — Maintenance
    # PHP — Security
    "php_unsafe_deser": ("sample_php.php", "src/VulnerableController.php", "unsafe_deserialization_php"),
    "php_weak_crypto": ("sample_php.php", "src/VulnerableController.php", "weak_crypto_php"),
    "php_weak_random": ("sample_php.php", "src/VulnerableController.php", "weak_random_php"),
    # PHP — Architecture
    # PHP — Maintenance
    # PHP — Blade XSS
    # Frontend XSS
    # ORM/SQL Injection — Python
    # ORM/SQL Injection — Java
    # ORM/SQL Injection — C#
    # ORM/SQL Injection — PHP
    # ORM/SQL Injection — JS
    # MFA
    "mfa_python": ("sample_mfa_python.py", "src/auth.py", "missing_mfa_python"),
    "mfa_java": ("sample_mfa_java.java", "src/AuthController.java", "missing_mfa_java"),
    "mfa_csharp": ("sample_mfa_csharp.cs", "src/AuthController.cs", "missing_mfa_csharp"),
    "mfa_javascript": ("sample_mfa_js.js", "src/js/auth.js", "missing_mfa_javascript"),
    "mfa_php": ("sample_mfa_php.php", "src/AuthController.php", "missing_mfa_php"),
    # Deprecated APIs (multi-lang)
    # GDPR
    # CI/CD
    "cicd_unpinned_action": ("sample_cicd_vulnerable.yml", "src/.github/workflows/ci.yml", "unpinned_action_version"),
    "hardcoded_secret_cicd": ("hardcoded_secret_cicd.yml", "src/.github/workflows/ci.yml", "hardcoded_secret_cicd"),
    "docker_latest_tag": ("docker_latest_tag.yml", "src/.gitlab-ci.yml", "docker_latest_tag"),
    "ci_docker_privileged": ("ci_docker_privileged.yml", "src/.gitlab-ci.yml", "ci_docker_privileged"),
    # Dockerfile
    "dockerfile_vuln": ("sample_dockerfile", "Dockerfile", "dockerfile_root_user"),
    # i18n / Hardcoded UI strings
    # SSRF
    # Path Traversal
    "path_traversal_python": ("path_traversal_python.py", "src/service.py", "taint_path_traversal"),
    "path_traversal_java": ("path_traversal_java.java", "src/FileController.java", "taint_path_traversal"),
    "path_traversal_csharp": ("path_traversal_csharp.cs", "src/FileController.cs", "taint_path_traversal"),
    "path_traversal_javascript": ("path_traversal_javascript.js", "src/js/files.js", "taint_path_traversal"),
    # Framework security — Django
    # Framework security — Flask
    # Framework security — Express
    # Insecure cookies
    "insecure_cookie_python": ("insecure_cookie.py", "src/views.py", "insecure_cookie"),
    "insecure_cookie_java": ("insecure_cookie.java", "src/AuthController.java", "insecure_cookie"),
    "insecure_cookie_csharp": ("insecure_cookie.cs", "src/AuthController.cs", "insecure_cookie"),
    "insecure_cookie_js": ("insecure_cookie.js", "src/js/auth.js", "insecure_cookie"),
    "insecure_cookie_php": ("insecure_cookie.php", "src/auth.php", "insecure_cookie"),
    # LDAP injection
    "ldap_injection_python": ("ldap_injection_python.py", "src/ldap_service.py", "taint_ldap"),
    # ISO 27001 — nouvelles règles
    # ASVS — Groupe A : Injection avancée
    # ASVS — Groupe B : Injection secondaire
    # ASVS — Groupe C : Headers de sécurité
    # ASVS — Groupe D : Frontend avancé
    "missing_sri": ("missing_sri.html", "src/index.html", "missing_sri"),
    # ASVS — Groupe E : API et GraphQL
    # ASVS — Groupe F : Upload fichiers
    # ASVS — Groupe G : Authentification
    # ASVS — Groupe H : Tokens JWT
    # ASVS — Groupe I : Cryptographie
    # ASVS — Groupe J : Logging
    # Architecture — DB dans contrôleur
    # Security — LDAP / XXE
    # Security — Dockerfile
    "dockerfile_root_user": ("dockerfile_root_user", "Dockerfile", "dockerfile_root_user"),
    # UX — HTML
    "missing_doctype": ("missing_doctype.html", "src/index.html", "missing_doctype"),
    # Fixtures générées automatiquement
    "taint_sqli_csharp": ("taint_sqli.cs", "src/service.cs", "taint_sqli"),
    "dockerfile_copy_all": ("dockerfile_copy_all", "Dockerfile", "dockerfile_copy_all"),
    "dockerfile_unpinned_base": ("dockerfile_unpinned_base", "Dockerfile", "dockerfile_unpinned_base"),
    "inline_event_handler_html": ("inline_event_handler_html.html", "src/index.html", "inline_event_handler_html"),
    "html_no_lang": ("html_no_lang.html", "src/index.html", "html_no_lang"),
    "taint_deserialization_java": ("taint_deserialization.java", "src/service.java", "taint_deserialization"),
    "taint_ldap_java": ("taint_ldap.java", "src/service.java", "taint_ldap"),
    "taint_rce_java": ("taint_rce.java", "src/service.java", "taint_rce"),
    "taint_sqli_java": ("taint_sqli.java", "src/service.java", "taint_sqli"),
    "taint_xxe_java": ("taint_xxe.java", "src/service.java", "taint_xxe"),
    "taint_sqli_jakarta": ("taint_sqli_jakarta.java", "src/UserResource.java", "taint_sqli"),
    "open_redirect": ("open_redirect.js", "src/js/app.js", "taint_open_redirect"),
    "prototype_pollution": ("prototype_pollution.js", "src/js/app.js", "prototype_pollution"),
    "taint_deserialization_javascript": ("taint_deserialization.js", "src/js/app.js", "taint_deserialization"),
    "taint_path_traversal_javascript": ("taint_path_traversal.js", "src/js/app.js", "taint_path_traversal"),
    "taint_rce_javascript": ("taint_rce.js", "src/js/app.js", "taint_rce"),
    "taint_sqli_javascript": ("taint_sqli.js", "src/js/app.js", "taint_sqli"),
    "taint_xss_javascript": ("taint_xss.js", "src/js/app.js", "taint_xss"),
    "taint_rce_php": ("taint_rce.php", "src/service.php", "taint_rce"),
    "taint_sqli_php": ("taint_sqli.php", "src/service.php", "taint_sqli"),
    "insecure_deserialize_call": ("insecure_deserialize_call.py", "src/service.py", "taint_deserialization"),
    "oauth_open_redirect": ("oauth_open_redirect.py", "src/service.py", "taint_open_redirect"),
    "taint_codeinj": ("taint_codeinj.py", "src/service.py", "taint_codeinj"),
    "taint_deserialization_python": ("taint_deserialization.py", "src/service.py", "taint_deserialization"),
    "taint_ldap_python": ("taint_ldap.py", "src/service.py", "taint_ldap"),
    "taint_open_redirect": ("taint_open_redirect.py", "src/service.py", "taint_open_redirect"),
    "taint_path_traversal_python": ("taint_path_traversal.py", "src/service.py", "taint_path_traversal"),
    "taint_rce_python": ("taint_rce.py", "src/service.py", "taint_rce"),
    "taint_sqli_python": ("taint_sqli.py", "src/service.py", "taint_sqli"),
    "taint_xpathi": ("taint_xpathi.py", "src/service.py", "taint_xpathi"),
    "taint_xss_python": ("taint_xss.py", "src/service.py", "taint_xss"),
    "taint_xxe_python": ("taint_xxe.py", "src/service.py", "taint_xxe"),
    "weak_random_python": ("weak_random_python.py", "src/service.py", "weak_random_python"),
    "xss_flask_reflected": ("xss_flask_reflected.py", "src/service.py", "taint_xss"),
    "xxe_injection_python": ("xxe_injection_python.py", "src/service.py", "taint_xxe"),
    # OWASP Benchmark — broad Java rules
    "insecure_cookie_flag": ("insecure_cookie_flag.java", "src/CookieController.java", "insecure_cookie_flag"),
    "xss_servlet_response": ("xss_servlet_response.java", "src/EchoServlet.java", "taint_xss"),
    # DATABASE security — vague 1
    # DATABASE security — vague 2
    # DATABASE security — vague 3
    # DATABASE security — vague 4
    # DATABASE security — vague 5
    # DATABASE security — vague 6
    "hardcoded_connection_string_java": ("hardcoded_connection_string_java.java", "src/service.java", "hardcoded_connection_string_java"),
    "hardcoded_connection_string_php": ("hardcoded_connection_string_php.php", "src/service.php", "hardcoded_connection_string_php"),
}

CLEAN_FIXTURES = {
    # Security
    "secret_in_env": ("secret_in_env.py", "src/config.py", "hardcoded_secret"),
    "secret_example": ("secret_example.py", "src/config.py", "hardcoded_secret"),
    "env_aws_key": ("env_aws_key.py", "src/config.py", "hardcoded_secret"),
    "env_github_token": ("env_github_token.py", "src/config.py", "hardcoded_secret"),
    "safe_no_eval": ("safe_no_eval.py", "src/service.py", "taint_codeinj"),
    "strong_crypto": ("strong_crypto.py", "src/service.py", "weak_crypto"),
    "validated_input": ("validated_input.py", "src/service.py", "taint_rce"),
    "secure_random": ("secure_random.js", "src/js/app.js", "insecure_random"),
    # Supply-chain
    # Architecture
    # UI
    # UX
    "img_with_alt": ("img_with_alt.html", "src/index.html", "img_no_alt"),
    "focus_outline_kept": ("focus_outline_kept.js", "src/js/app.js", "focus_outline_removed"),
    # Maintenance
    # UX (suite)
    # Security (suite)
    # Dependencies
    # Java
    # C#
    # PHP
    # Frontend XSS
    # ORM clean
    # MFA clean
    "mfa_python_clean": ("sample_mfa_python_clean.py", "src/auth.py", "missing_mfa_python"),
    "mfa_java_clean": ("sample_mfa_java_clean.java", "src/AuthController.java", "missing_mfa_java"),
    "mfa_csharp_clean": ("sample_mfa_csharp_clean.cs", "src/AuthController.cs", "missing_mfa_csharp"),
    "mfa_javascript_clean": ("sample_mfa_js_clean.js", "src/js/auth.js", "missing_mfa_javascript"),
    "mfa_php_clean": ("sample_mfa_php_clean.php", "src/AuthController.php", "missing_mfa_php"),
    # Deprecated APIs clean
    # GDPR clean
    # CI/CD
    "hardcoded_secret_cicd_clean": ("hardcoded_secret_cicd_clean.yml", "src/.github/workflows/ci.yml", "hardcoded_secret_cicd"),
    "docker_latest_tag_clean": ("docker_latest_tag_clean.yml", "src/.gitlab-ci.yml", "docker_latest_tag"),
    "ci_docker_privileged_clean": ("ci_docker_privileged_clean.yml", "src/.gitlab-ci.yml", "ci_docker_privileged"),
    # Dockerfile clean
    "dockerfile_clean": ("sample_dockerfile_clean", "Dockerfile", "dockerfile_root_user"),
    # i18n / Hardcoded UI strings clean
    # SSRF clean
    # Path Traversal clean
    # Framework security clean — Django
    # Framework security clean — Flask
    # Framework security clean — Express
    # Secure cookies clean
    "secure_cookie_python": ("secure_cookie_python.py", "src/views.py", "insecure_cookie"),
    "secure_cookie_java": ("secure_cookie_java.java", "src/AuthController.java", "insecure_cookie"),
    "secure_cookie_js": ("secure_cookie_js.js", "src/js/auth.js", "insecure_cookie"),
    # LDAP clean
    "ldap_python_clean": ("ldap_python_clean.py", "src/ldap_service.py", "taint_ldap"),
    # ISO 27001 — clean fixtures
    # ASVS — Groupe A : Injection avancée (clean)
    # ASVS — Groupe B : Injection secondaire (clean)
    # ASVS — Groupe C : Headers de sécurité (clean)
    # ASVS — Groupe D : Frontend avancé (clean)
    "script_with_sri": ("script_with_sri.html", "src/index.html", "missing_sri"),
    # ASVS — Groupe E : API et GraphQL (clean)
    # ASVS — Groupe F : Upload fichiers (clean)
    # ASVS — Groupe G : Authentification (clean)
    # ASVS — Groupe H : Tokens JWT (clean)
    # ASVS — Groupe I : Cryptographie (clean)
    # ASVS — Groupe J : Logging (clean)
    # Architecture — DB dans contrôleur (clean)
    # Security — LDAP / XXE (clean)
    # Security — Dockerfile (clean)
    "dockerfile_non_root": ("dockerfile_non_root", "Dockerfile", "dockerfile_root_user"),
    # UX — HTML (clean)
    "with_doctype": ("with_doctype.html", "src/index.html", "missing_doctype"),
    # Fixtures générées automatiquement
    "dockerfile_copy_all_clean": ("dockerfile_copy_all_clean", "Dockerfile", "dockerfile_copy_all"),
    "dockerfile_unpinned_base_clean": ("dockerfile_unpinned_base_clean", "Dockerfile", "dockerfile_unpinned_base"),
    "inline_event_handler_html_clean": ("inline_event_handler_html_clean.html", "src/index.html", "inline_event_handler_html"),
    "html_no_lang_clean": ("html_no_lang_clean.html", "src/index.html", "html_no_lang"),
    "taint_ldap_clean_java": ("taint_ldap_clean.java", "src/service.java", "taint_ldap"),
    "taint_xxe_clean_java": ("taint_xxe_clean.java", "src/service.java", "taint_xxe"),
    "taint_sqli_jakarta_clean": ("taint_sqli_jakarta_clean.java", "src/UserResource.java", "taint_sqli"),
    "prototype_pollution_clean": ("prototype_pollution_clean.js", "src/js/app.js", "prototype_pollution"),
    "taint_path_traversal_clean_javascript": ("taint_path_traversal_clean.js", "src/js/app.js", "taint_path_traversal"),
    "taint_sqli_clean_javascript": ("taint_sqli_clean.js", "src/js/app.js", "taint_sqli"),
    "taint_xss_clean_javascript": ("taint_xss_clean.js", "src/js/app.js", "taint_xss"),
    "taint_rce_clean_php": ("taint_rce_clean.php", "src/service.php", "taint_rce"),
    "taint_sqli_clean_php": ("taint_sqli_clean.php", "src/service.php", "taint_sqli"),
    "taint_codeinj_clean": ("taint_codeinj_clean.py", "src/service.py", "taint_codeinj"),
    "taint_deserialization_clean": ("taint_deserialization_clean.py", "src/service.py", "taint_deserialization"),
    "taint_ldap_clean_python": ("taint_ldap_clean.py", "src/service.py", "taint_ldap"),
    "taint_open_redirect_clean": ("taint_open_redirect_clean.py", "src/service.py", "taint_open_redirect"),
    "taint_path_traversal_clean_python": ("taint_path_traversal_clean.py", "src/service.py", "taint_path_traversal"),
    "taint_rce_clean_python": ("taint_rce_clean.py", "src/service.py", "taint_rce"),
    "taint_sqli_clean_python": ("taint_sqli_clean.py", "src/service.py", "taint_sqli"),
    "taint_xpathi_clean": ("taint_xpathi_clean.py", "src/service.py", "taint_xpathi"),
    "taint_xss_clean_python": ("taint_xss_clean.py", "src/service.py", "taint_xss"),
    "taint_xxe_clean_python": ("taint_xxe_clean.py", "src/service.py", "taint_xxe"),
    "weak_random_python_clean": ("weak_random_python_clean.py", "src/service.py", "weak_random_python"),
    "unsafe_deserialization_csharp_clean": ("unsafe_deserialization_csharp_clean.cs", "src/service.cs", "unsafe_deserialization_csharp"),
    "weak_crypto_csharp_clean": ("weak_crypto_csharp_clean.cs", "src/service.cs", "weak_crypto_csharp"),
    "weak_random_csharp_clean": ("weak_random_csharp_clean.cs", "src/service.cs", "weak_random_csharp"),
    "unsafe_deserialization_java_clean": ("unsafe_deserialization_java_clean.java", "src/service.java", "unsafe_deserialization_java"),
    "weak_crypto_java_clean": ("weak_crypto_java_clean.java", "src/service.java", "weak_crypto_java"),
    "weak_random_java_clean": ("weak_random_java_clean.java", "src/service.java", "weak_random_java"),
    "unsafe_deserialization_php_clean": ("unsafe_deserialization_php_clean.php", "src/service.php", "unsafe_deserialization_php"),
    "weak_crypto_php_clean": ("weak_crypto_php_clean.php", "src/service.php", "weak_crypto_php"),
    "weak_random_php_clean": ("weak_random_php_clean.php", "src/service.php", "weak_random_php"),
    "unpinned_action_version_clean": ("unpinned_action_version_clean.yml", "src/config.yml", "unpinned_action_version"),
    "dangerous_eval_clean2": ("dangerous_eval_clean.py", "src/service.py", "taint_codeinj"),
    "hardcoded_secret_clean2": ("hardcoded_secret_clean.py", "src/service.py", "hardcoded_secret"),
    "img_no_alt_clean2": ("img_no_alt_clean.html", "src/index.html", "img_no_alt"),
    "insecure_random_clean2": ("insecure_random_clean.js", "src/js/app.js", "insecure_random"),
    "unvalidated_input_clean2": ("unvalidated_input_clean.py", "src/service.py", "taint_rce"),
    "weak_crypto_clean2": ("weak_crypto_clean.py", "src/service.py", "weak_crypto"),
    # OWASP Benchmark — broad Java rules (clean)
    "insecure_cookie_flag_clean": ("insecure_cookie_flag_clean.java", "src/service.java", "insecure_cookie_flag"),
    "taint_xss_console_clean": ("taint_xss_console_clean.java", "src/DebugServlet.java", "taint_xss"),
    # DATABASE security — vague 1 (clean)
    # DATABASE security — vague 2 (clean)
    # DATABASE security — vague 3 (clean)
    # DATABASE security — vague 4 (clean)
    # DATABASE security — vague 5 (clean)
    # DATABASE security — vague 6 (clean)
    "hardcoded_connection_string_java_clean": ("hardcoded_connection_string_java_clean.java", "src/service.java", "hardcoded_connection_string_java"),
    "hardcoded_connection_string_php_clean": ("hardcoded_connection_string_php_clean.php", "src/service.php", "hardcoded_connection_string_php"),
}
