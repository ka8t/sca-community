"""
Chargeur de règles déclaratives JSON.

Charge les règles depuis :
1. Le blob chiffré builtin (binaire compilé, si disponible)
2. Les fichiers JSON en clair dans sca/rules/builtin/ (mode développement)
3. Les fichiers JSON custom du client dans audit-rules/ (si présent)

Chaque règle est validée contre le schéma rule_schema.json et la cohérence
chemin-fichier ↔ champs internes (language, category, id).
"""
import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from sca import SCRIPT_DIR

logger = logging.getLogger("sca.rule_loader")

# Allowed languages and categories (mirrors the schema)
VALID_LANGUAGES = {"python", "javascript", "java", "csharp", "php", "yaml", "html", "dockerfile"}
VALID_CATEGORIES = {"security", "arch", "ui", "ux", "maintenance", "cicd", "database", "dependencies"}
VALID_MODES = {"regex", "taint", "regex+taint", "ast", "file_contains", "python_hook"}
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_ID_PATTERN = re.compile(r'^[a-z0-9_]+$')


def load_rules_from_directory(rules_dir: Path, source: str = "json_builtin") -> List[dict]:
    """Load all .sca rules from a <lang>/<cat>/<id>.sca directory tree.

    Args:
        rules_dir: Root directory containing per-language subdirectories.
        source: Origin of the rules ("json_builtin" or "json_custom").

    Returns:
        List of validated rules (dicts enriched with _source and _file_path).
    """
    rules = []
    if not rules_dir.exists() or not rules_dir.is_dir():
        return rules

    # Load .sca files (DSL) — sole format
    for sca_file in sorted(rules_dir.rglob("*.sca")):
        sca_rules = _load_sca_rules(sca_file, rules_dir, source)
        rules.extend(sca_rules)

    return rules


def _load_and_validate_rule(json_file: Path, rules_dir: Path,
                             source: str) -> Optional[dict]:
    """Load, parse, validate, and enrich a JSON rule.

    Returns None if the rule is invalid (error is logged).
    """
    rel_path = json_file.relative_to(rules_dir)
    parts = rel_path.parts  # ex: ('python', 'security', 'ssrf.json')

    # Structural validation of the path (3 levels expected)
    if len(parts) != 3:
        logger.warning("Règle ignorée (chemin invalide, 3 niveaux attendus) : %s", rel_path)
        return None

    path_language = parts[0]
    path_category = parts[1]
    expected_id = json_file.stem

    # Reading and JSON parsing
    try:
        content = json_file.read_text(encoding="utf-8")
        rule = json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning("Règle ignorée (JSON malformé) : %s — %s", rel_path, e)
        return None
    except Exception as e:
        logger.warning("Règle ignorée (erreur lecture) : %s — %s", rel_path, e)
        return None

    # Strip _comment, _doc, etc. fields (prefix _)
    rule = _strip_internal_fields(rule)

    # Validation of required fields
    for field in ("id", "language", "category", "severity", "mode", "message"):
        if field not in rule:
            logger.warning("Règle ignorée (champ requis manquant : '%s') : %s", field, rel_path)
            return None

    # Validation of the id format
    rule_id = rule["id"]
    if not VALID_ID_PATTERN.match(rule_id):
        logger.warning("Règle ignorée (id invalide, doit être [a-z0-9_]+) : %s", rel_path)
        return None

    # Cross-validation path ↔ content
    if rule_id != expected_id:
        logger.warning("Règle ignorée (id '%s' ≠ nom de fichier '%s') : %s", rule_id, expected_id, rel_path)
        return None

    if rule["language"] != path_language:
        logger.warning("Règle ignorée (language '%s' ≠ répertoire '%s') : %s", rule['language'], path_language, rel_path)
        return None

    if rule["category"] != path_category:
        logger.warning("Règle ignorée (category '%s' ≠ répertoire '%s') : %s", rule['category'], path_category, rel_path)
        return None

    # Validation of allowed values
    if rule["language"] not in VALID_LANGUAGES:
        logger.warning("Règle ignorée (langage inconnu : '%s') : %s", rule['language'], rel_path)
        return None

    if rule["category"] not in VALID_CATEGORIES:
        logger.warning("Règle ignorée (catégorie inconnue : '%s') : %s", rule['category'], rel_path)
        return None

    if rule["mode"] not in VALID_MODES:
        logger.warning("Règle ignorée (mode inconnu : '%s') : %s", rule['mode'], rel_path)
        return None

    if rule["severity"] not in VALID_SEVERITIES:
        logger.warning("Règle ignorée (sévérité inconnue : '%s') : %s", rule['severity'], rel_path)
        return None

    # Validation of the message (key 'en' required)
    msg = rule.get("message", {})
    if not isinstance(msg, dict) or "en" not in msg:
        logger.warning("Règle ignorée (message.en manquant) : %s", rel_path)
        return None

    # Conditional validation per mode
    mode = rule["mode"]
    if mode == "regex" and "patterns" not in rule:
        logger.warning("Règle ignorée (mode regex mais pas de 'patterns') : %s", rel_path)
        return None

    if mode == "taint" and ("sources" not in rule or "sinks" not in rule):
        logger.warning("Règle ignorée (mode taint mais sources/sinks manquants) : %s", rel_path)
        return None

    if mode == "regex+taint" and ("patterns" not in rule or "sources" not in rule or "sinks" not in rule):
        logger.warning("Règle ignorée (mode regex+taint mais patterns/sources/sinks manquants) : %s", rel_path)
        return None

    if mode == "ast" and "ast_patterns" not in rule:
        logger.warning("Règle ignorée (mode ast mais pas de 'ast_patterns') : %s", rel_path)
        return None

    if mode == "file_contains" and "file_contains" not in rule:
        logger.warning("Règle ignorée (mode file_contains mais pas de 'file_contains') : %s", rel_path)
        return None

    if mode == "python_hook" and "hook" not in rule:
        logger.warning("Règle ignorée (mode python_hook mais pas de 'hook') : %s", rel_path)
        return None

    # Regex compilation (validation + performance)
    if not _compile_rule_patterns(rule, rel_path):
        return None

    # Enrich with loading metadata
    rule["_source"] = source
    rule["_file_path"] = str(rel_path)

    logger.info("Règle chargée : %s (%s, %s) depuis %s", rule_id, source, mode, rel_path)
    return rule


def _verify_auditai_provenance(rule: dict, sca_source: str, rel_path) -> bool:
    """Verify the AuditAi provenance of a ``.sca`` rule (see
    CONSTRAINTS.md C9, AuditAi/docs/ARCHITECTURE.md §7.2).

    Only applies to rules carrying ``metadata.generated_by ==
    "auditai"`` — no effect on builtin or manually written custom rules
    (see ARCHITECTURE.md §7.3: "no overhead for builtin rules not
    generated by AuditAi"). Returns False (rule to discard) with an
    explicit log message if the signature is missing or invalid, or if
    ``org_id`` doesn't match the current license — never a silent outcome.
    """
    meta = rule.get("metadata", {}) or {}
    rule_id = rule.get("id", "?")

    signature = meta.get("signature", "")
    if not signature:
        logger.warning(
            "Règle .sca ignorée (marqueur AuditAi attendu mais signature absente) : %s",
            rel_path,
        )
        return False

    try:
        from sca.sign import compute_rule_content_hash, verify_ed25519
    except ImportError as exc:
        logger.warning(
            "Règle .sca ignorée (vérification de signature AuditAi indisponible) : %s — %s",
            rel_path, exc,
        )
        return False

    content_hash = compute_rule_content_hash(sca_source)
    if not verify_ed25519(content_hash, signature):
        logger.warning(
            "Règle .sca ignorée (signature AuditAi invalide — fichier modifié manuellement ?) : %s",
            rel_path,
        )
        return False

    from sca.license_facade import get_org_id
    expected_org = get_org_id()
    actual_org = meta.get("org_id", "")
    if not expected_org or actual_org != expected_org:
        logger.warning(
            "Règle .sca ignorée (générée pour un autre client, org_id '%s' != '%s') : %s",
            actual_org, expected_org, rel_path,
        )
        return False

    return True


def _strip_internal_fields(obj):
    """Recursively remove fields prefixed with _ (comments, doc)."""
    if isinstance(obj, dict):
        return {k: _strip_internal_fields(v) for k, v in obj.items()
                if not k.startswith("_")}
    elif isinstance(obj, list):
        return [_strip_internal_fields(item) for item in obj]
    return obj


def _compile_rule_patterns(rule: dict, rel_path) -> bool:
    """Compile all of a rule's regexes. Returns False if any regex is invalid."""
    _compiled = []

    # Regex patterns
    for i, p in enumerate(rule.get("patterns", [])):
        pattern_str = p.get("pattern", "")
        # For context-N scopes, enable DOTALL so `.` matches `\n`
        # and lets patterns span multiple lines.
        scope = p.get("match", "line")
        flags = re.DOTALL if isinstance(scope, str) and scope.startswith("context-") else 0
        try:
            p["_compiled"] = re.compile(pattern_str, flags)
        except re.error as e:
            logger.warning("Règle ignorée (regex invalide dans patterns[%d]) : %s — %s", i, rel_path, e)
            return False

        # Compile the with clause if present (same DOTALL flag for context-N)
        if "with" in p:
            try:
                p["_compiled_with"] = re.compile(p["with"], flags)
            except re.error as e:
                logger.warning("Règle ignorée (regex 'with' invalide dans patterns[%d]) : %s — %s", i, rel_path, e)
                return False

        # Compile pattern-not, pattern-inside, pattern-not-inside
        for neg_key in ("pattern-not", "pattern-inside", "pattern-not-inside"):
            if neg_key in p:
                try:
                    p[f"_compiled_{neg_key}"] = re.compile(p[neg_key], flags)
                except re.error as e:
                    logger.warning("Règle ignorée (regex '%s' invalide dans patterns[%d]) : %s — %s", neg_key, i, rel_path, e)
                    return False

    # Taint sources
    for i, s in enumerate(rule.get("sources", [])):
        try:
            s["_compiled"] = re.compile(s["pattern"])
        except re.error as e:
            logger.warning("Règle ignorée (regex invalide dans sources[%d]) : %s — %s", i, rel_path, e)
            return False

    # Taint sinks
    for i, s in enumerate(rule.get("sinks", [])):
        try:
            s["_compiled"] = re.compile(s["pattern"])
        except re.error as e:
            logger.warning("Règle ignorée (regex invalide dans sinks[%d]) : %s — %s", i, rel_path, e)
            return False

    # file_contains patterns
    fc = rule.get("file_contains", {})
    compiled_has = []
    for i, pattern_str in enumerate(fc.get("has", [])):
        try:
            compiled_has.append(re.compile(pattern_str))
        except re.error as e:
            logger.warning("Règle ignorée (regex invalide dans file_contains.has[%d]) : %s — %s", i, rel_path, e)
            return False
    compiled_not_has = []
    for i, pattern_str in enumerate(fc.get("not_has", [])):
        try:
            compiled_not_has.append(re.compile(pattern_str))
        except re.error as e:
            logger.warning("Règle ignorée (regex invalide dans file_contains.not_has[%d]) : %s — %s", i, rel_path, e)
            return False
    if compiled_has or compiled_not_has:
        fc["_compiled_has"] = compiled_has
        fc["_compiled_not_has"] = compiled_not_has

    # Taint sanitizers
    for i, s in enumerate(rule.get("sanitizers", [])):
        try:
            s["_compiled"] = re.compile(s["pattern"])
        except re.error as e:
            logger.warning("Règle ignorée (regex invalide dans sanitizers[%d]) : %s — %s", i, rel_path, e)
            return False

    # Taint passthroughs (functions that preserve taint)
    for i, p in enumerate(rule.get("passthroughs", [])):
        try:
            p["_compiled"] = re.compile(p["pattern"])
        except re.error as e:
            logger.warning("Règle ignorée (regex invalide dans passthroughs[%d]) : %s — %s", i, rel_path, e)
            return False

    return True


def index_rules_by_language(rules: List[dict]) -> Dict[str, List[dict]]:
    """Index rules by language for fast dispatch."""
    index = {}
    for rule in rules:
        lang = rule["language"]
        if lang not in index:
            index[lang] = []
        index[lang].append(rule)
    return index


def filter_rules_by_tier(rules: List[dict], current_tier: str,
                          available_features: List[str]) -> Tuple[List[dict], List[dict]]:
    """Filter rules by license tier and available features.

    Returns:
        (rules_accepted, rules_rejected) — each element of rejected is
        enriched with a _rejection_reason field.
    """
    tier_order = {"demo": 0, "solo": 1, "team": 2, "enterprise": 3}
    current_level = tier_order.get(current_tier, 0)

    accepted = []
    rejected = []

    for rule in rules:
        requires = rule.get("requires", {})
        min_tier = requires.get("min_tier", "demo")
        required_features = requires.get("features", [])
        required_level = tier_order.get(min_tier, 0)

        if current_level < required_level:
            rule["_rejection_reason"] = f"requires tier '{min_tier}', current is '{current_tier}'"
            rejected.append(rule)
            continue

        missing = [f for f in required_features if f not in available_features]
        if missing:
            rule["_rejection_reason"] = f"missing features: {', '.join(missing)}"
            rejected.append(rule)
            continue

        accepted.append(rule)

    return accepted, rejected


def filter_demo_fallback_rules(rules: List[dict], current_tier: str) -> List[dict]:
    """Restrict builtin rules to the curated demo_fallback subset.

    Applies only when ``current_tier == "demo"`` — either a licensed
    tier=demo client, or the zero-license fallback (cf.
    ``rule_engine.py::_load_demo_fallback``). Independent of
    ``filter_rules_by_tier``/min_tier: a rule can have ``min_tier="demo"``
    (no commercial restriction) without being part of the small
    admin-curated demo set (``SCARule.demo_fallback`` -> ``requires.demo_fallback``
    in the compiled rule).

    Any other tier is returned unchanged (builtin rules stay outside the
    quota for paying tiers, cf. ``_apply_license_gating``).
    """
    if current_tier != "demo":
        return rules
    return [r for r in rules if r.get("requires", {}).get("demo_fallback", False)]


def _load_sca_rules(sca_file: Path, rules_dir: Path, source: str) -> List[dict]:
    """Load and compile rules from a .sca (DSL) file.

    Parses the DSL, compiles it to JSON, validates it, and compiles the
    regexes. Returns a list of validated rules (a file may yield 0+ rules).
    """
    rel_path = sca_file.relative_to(rules_dir)

    try:
        from sca.dsl import compile_sca_to_json
    except ImportError:
        logger.warning("Règle .sca ignorée (package sca.dsl manquant) : %s", rel_path)
        return []

    try:
        sca_source = sca_file.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning("Règle .sca ignorée (erreur lecture) : %s — %s", rel_path, e)
        return []

    try:
        json_rules = compile_sca_to_json(sca_source, str(sca_file))
    except Exception as e:
        logger.warning("Règle .sca ignorée (erreur DSL) : %s — %s", rel_path, e)
        return []

    validated = []
    for rule in json_rules:
        rule_id = rule.get("id", "?")

        # Validation of required fields (same logic as JSON)
        for field in ("id", "language", "category", "severity", "mode", "message"):
            if field not in rule:
                logger.warning("Règle .sca ignorée (champ requis manquant : '%s') : %s#%s", field, rel_path, rule_id)
                break
        else:
            # AuditAi provenance (C9) — only if the rule carries the
            # generated_by=auditai marker, no effect on other rules.
            meta = rule.get("metadata", {}) or {}
            if meta.get("generated_by") == "auditai":
                if not _verify_auditai_provenance(rule, sca_source, f"{rel_path}#{rule_id}"):
                    continue

            # Regex compilation
            if _compile_rule_patterns(rule, f"{rel_path}#{rule_id}"):
                # Compile the file_contains regexes
                fc = rule.get("file_contains", {})
                for pattern_list in (fc.get("has", []), fc.get("not_has", [])):
                    for j, p in enumerate(pattern_list):
                        try:
                            # Store the compiled version alongside
                            re.compile(p)
                        except re.error:
                            pass  # Already validated by the DSL validator

                rule["_source"] = source
                rule["_file_path"] = str(rel_path)
                logger.info("Règle .sca chargée : %s (%s) depuis %s", rule_id, source, rel_path)
                validated.append(rule)

    return validated
