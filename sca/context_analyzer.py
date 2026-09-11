"""
Layer 3 — Contextual analysis of a source file.

Determines the file's context (test? ORM? sanitizer? HTTP handler?)
to reinforce or dampen findings from the pattern and taint layers.

Uses only regex checks on the file content — no AST, no external
dependencies. 100% stdlib.
"""
import os
import re
import logging
from typing import Dict

logger = logging.getLogger("sca.context_analyzer")


def analyze_context(filepath: str, content: str) -> Dict[str, bool]:
    """Analyze the context of a source file.

    Returns a dict of boolean signals used by the evidence fuser to adjust
    finding confidence.

    Args:
        filepath: file path (to detect test/mock/fixture)
        content: source file content

    Returns:
        dict of contextual signals
    """
    basename = os.path.basename(filepath).lower()
    dirpath = filepath.lower().replace("\\", "/")

    signals = {}

    # =========================================================================
    # 1. Test / mock / fixture file?
    # =========================================================================
    signals["is_test_file"] = bool(
        any(x in basename for x in ["test_", "_test.", "spec.", "mock", "fixture", "conftest"])
        or any(x in dirpath for x in ["/tests/", "/test/", "/__tests__/", "/spec/",
                                       "/fixtures/", "/mocks/", "/testing/"])
    )

    # =========================================================================
    # 2. ORM / parameterized queries?
    # =========================================================================
    signals["has_orm"] = bool(re.search(
        r"(?:"
        r"from\s+sqlalchemy|from\s+django\.db|from\s+tortoise|from\s+peewee|"
        r"from\s+prisma|from\s+mongoengine|from\s+pony\.orm|"
        r"\.objects\.|\.filter\(|\.query\.|\.select\(|\.where\(|"
        r"@db\.session|Session\(\)"
        r")",
        content
    ))

    # =========================================================================
    # 3. Raw SQL (no ORM)?
    # =========================================================================
    signals["has_raw_sql"] = bool(re.search(
        r"(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\s+",
        content
    )) and not signals["has_orm"]

    # =========================================================================
    # 4. HTTP handler (route, endpoint, view)?
    # =========================================================================
    signals["has_http_handler"] = bool(re.search(
        r"(?:"
        r"@app\.route|@router\.|@api_view|@action\(|"
        r"@blueprint\.route|@bp\.route|"
        r"def\s+\w+\(.*request|async\s+def\s+\w+\(.*request|"
        r"app\.get\(|app\.post\(|app\.put\(|app\.delete\(|"
        r"router\.get\(|router\.post\(|"
        r"@RequestMapping|@GetMapping|@PostMapping|"
        r"\[HttpGet\]|\[HttpPost\]|\[ApiController\]"
        r")",
        content
    ))

    # =========================================================================
    # 5. Input validation?
    # =========================================================================
    signals["has_input_validation"] = bool(re.search(
        r"(?:"
        r"pydantic|marshmallow|cerberus|voluptuous|"
        r"wtforms|django\.forms|"
        r"Schema\(|validate\(|Validator\(|"
        r"@validates|ValidationError|"
        r"Joi\.|yup\.|zod\."
        r")",
        content
    ))

    # =========================================================================
    # 6. Sanitizer / escaping present?
    # =========================================================================
    signals["has_sanitizer"] = bool(re.search(
        r"(?:"
        r"bleach|html\.escape|markupsafe|cgi\.escape|"
        r"escape\(|sanitize\(|clean\(|purify\(|"
        r"parameterize|prepared_statement|"
        r"shlex\.quote|shlex\.split|"
        r"DOMPurify|xss\-clean|helmet|"
        r"mysql\.escape|pg\.escape|"
        r"re\.escape\("
        r")",
        content
    ))

    # =========================================================================
    # 7. Error handling / secure logging?
    # =========================================================================
    signals["has_secure_logging"] = bool(re.search(
        r"(?:"
        r"structlog|json_logger|"
        r"logging\.config|dictConfig|"
        r"sentry_sdk|bugsnag|rollbar|"
        r"sanitize.*log|redact"
        r")",
        content
    ))

    # =========================================================================
    # 8. Authentication / authorization?
    # =========================================================================
    signals["has_auth"] = bool(re.search(
        r"(?:"
        r"login_required|auth_required|permission_required|"
        r"jwt_required|token_required|admin_required|"
        r"@requires_auth|@authenticated|"
        r"IsAuthenticated|IsAdminUser|"
        r"passport\.|express-jwt|"
        r"checkAccess|checkPermission|authorize"
        r")",
        content
    ))

    # =========================================================================
    # 9. Detected framework?
    # =========================================================================
    framework = "unknown"
    if re.search(r"from\s+flask|import\s+flask", content):
        framework = "flask"
    elif re.search(r"from\s+django|import\s+django", content):
        framework = "django"
    elif re.search(r"from\s+fastapi|import\s+fastapi", content):
        framework = "fastapi"
    elif re.search(r"from\s+starlette", content):
        framework = "starlette"
    elif re.search(r"express\(|require\(['\"]express", content):
        framework = "express"
    elif re.search(r"from\s+spring|@SpringBoot", content):
        framework = "spring"
    elif re.search(r"using\s+Microsoft\.AspNetCore", content):
        framework = "aspnet"
    signals["framework"] = framework

    # =========================================================================
    # 10. Configuration / setup file?
    # =========================================================================
    signals["is_config_file"] = bool(
        any(x in basename for x in ["config", "settings", "setup.py",
                                     "manage.py", "__init__", "wsgi", "asgi"])
    )

    return signals


def should_suppress(signals: Dict, rule_category: str = "security") -> bool:
    """Determine whether a finding should be suppressed based on context.

    Returns:
        True if the finding is likely a false positive.
    """
    # Test file → always suppress (deliberately vulnerable code)
    if signals.get("is_test_file"):
        return True

    return False


def confidence_modifier(signals: Dict, rule_key: str, base_confidence: int) -> int:
    """Adjust a finding's confidence based on context.

    Args:
        signals: results from analyze_context()
        rule_key: rule identifier
        base_confidence: initial confidence (from the rule)

    Returns:
        adjusted confidence (0-100)
    """
    modifier = 0

    # --- Bonuses (reinforce detection) ---

    # HTTP handler + raw SQL → strong signal for injection
    if signals.get("has_http_handler") and signals.get("has_raw_sql"):
        if "sql_injection" in rule_key:
            modifier += 15

    # HTTP handler without auth → signal for missing_auth
    if signals.get("has_http_handler") and not signals.get("has_auth"):
        if "missing_auth" in rule_key or "csrf" in rule_key:
            modifier += 10

    # HTTP handler without validation → signal for injection
    if signals.get("has_http_handler") and not signals.get("has_input_validation"):
        if any(x in rule_key for x in ["injection", "traversal", "ssrf", "xss"]):
            modifier += 10

    # --- Penalties (reduce detection) ---

    # ORM present → SQL injection less likely
    if signals.get("has_orm"):
        if "sql_injection" in rule_key:
            modifier -= 25

    # Sanitizer present → XSS/injection less likely
    if signals.get("has_sanitizer"):
        if any(x in rule_key for x in ["xss", "injection", "traversal"]):
            modifier -= 20

    # Input validation → injection less likely
    if signals.get("has_input_validation"):
        if any(x in rule_key for x in ["injection", "traversal", "ssrf"]):
            modifier -= 15

    # Config file → some rules not relevant
    if signals.get("is_config_file"):
        if any(x in rule_key for x in ["file_too_long", "race_condition"]):
            modifier -= 30

    result = base_confidence + modifier
    return max(0, min(100, result))
