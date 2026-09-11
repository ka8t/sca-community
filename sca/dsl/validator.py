"""
Semantic validator for .sca DSL rules.

Checks field consistency (allowed values, required fields, regex
compilability). Supports automatic mode inference (if `mode` is
absent, the compiler infers it from the blocks present).
"""
import re
from typing import List

from sca.dsl.nodes import (
    FileConditionBlock,
    MatchFileContainsBlock,
    MatchRegexBlock,
    RuleNode,
)
from sca.rule_loader import (
    VALID_CATEGORIES,
    VALID_ID_PATTERN,
    VALID_LANGUAGES,
    VALID_SEVERITIES,
)

# Modes supported by the DSL
VALID_MODES_DSL = {
    "regex", "taint", "regex+taint",
    "ast", "file_contains", "python_hook",
}

# Allowed taint source kinds
VALID_SOURCE_KINDS = {"http", "cli", "env", "stdin", "file", "network"}

# Allowed license tiers
VALID_TIERS = {"demo", "solo", "team", "enterprise"}


def validate_rule(node: RuleNode) -> List[str]:
    """Validate a RuleNode. Returns a list of errors (empty if valid)."""
    errors = []

    # Required fields
    if not node.id:
        errors.append("Identifiant de regle manquant")
    elif not VALID_ID_PATTERN.match(node.id):
        errors.append(f"Identifiant invalide : '{node.id}' "
                       "(attendu : [a-z0-9_]+)")

    if not node.language:
        errors.append("Langage manquant")
    elif node.language not in VALID_LANGUAGES:
        errors.append(f"Langage inconnu : '{node.language}'")

    if node.category and node.category not in VALID_CATEGORIES:
        errors.append(f"Categorie inconnue : '{node.category}'")

    if not node.severity:
        errors.append("Severite manquante")
    elif node.severity not in VALID_SEVERITIES:
        errors.append(f"Severite inconnue : '{node.severity}'")

    # Mode is optional (inferred by the compiler if absent)
    if node.mode and node.mode not in VALID_MODES_DSL:
        errors.append(f"Mode inconnu : '{node.mode}'")

    # English message: required for custom rules, optional for builtin
    # ones (translations live in locales/report/*.json).
    # Validation here is permissive — the rule_engine will fill it in from locales.

    # Confidence within range
    if not 0 <= node.confidence <= 100:
        errors.append(f"Confidence hors plage : {node.confidence} "
                       "(attendu : 0-100)")

    # Validation by mode (explicit or inferred)
    mode = node.mode
    if mode:
        if mode in ("regex", "regex+taint") and not node.match_blocks:
            errors.append(f"Mode '{mode}' requiert au moins un bloc 'match'")
        if mode in ("taint", "regex+taint"):
            if not node.sources:
                errors.append(f"Mode '{mode}' requiert au moins une source")
            if not node.sinks:
                errors.append(f"Mode '{mode}' requiert au moins un sink")
        if mode == "ast" and not node.match_blocks:
            errors.append("Mode 'ast' requiert un bloc 'match ast'")
        if mode == "file_contains" and not node.match_blocks and not node.file_conditions:
            errors.append("Mode 'file_contains' requiert un bloc "
                           "'match file_contains' ou 'requires' (has/not_has)")
        if mode == "python_hook" and not node.hook:
            errors.append("Mode 'python_hook' requiert un 'hook'")
    else:
        # No mode: verify there is at least one executor block
        has_content = (node.match_blocks or node.file_conditions
                       or node.sources or node.sinks or node.hook)
        if not has_content:
            errors.append("La regle doit contenir au moins un bloc "
                           "'match', 'requires' (has/not_has), 'taint', ou 'hook'")

    # Regex validation
    _validate_regex_blocks(node, errors)
    _validate_file_conditions(node, errors)
    _validate_taint_patterns(node, errors)

    # Tier validation
    if node.license.min_tier not in VALID_TIERS:
        errors.append(f"Tier inconnu : '{node.license.min_tier}'")

    # Source kind validation
    for src in node.sources:
        if src.kind not in VALID_SOURCE_KINDS:
            errors.append(f"Kind de source inconnu : '{src.kind}'")

    return errors


def _validate_regex_blocks(node: RuleNode, errors: List[str]):
    """Validate regex compilability in match blocks.

    Blocks with is_text=True are plain text — the regex is validated
    AFTER conversion via _text_to_regex() (not on the raw text).
    """
    from sca.dsl.compiler import _text_to_regex

    for block in node.match_blocks:
        if isinstance(block, MatchRegexBlock):
            pat = _text_to_regex(block.pattern) if block.is_text else block.pattern
            _try_compile(pat, "pattern" if not block.is_text else "text", errors)

            wp = _text_to_regex(block.with_pattern) if block.with_is_text else block.with_pattern
            _try_compile(wp, "with", errors)

            np = _text_to_regex(block.pattern_not) if block.pattern_not_is_text else block.pattern_not
            _try_compile(np, "pattern-not" if not block.pattern_not_is_text else "text-not", errors)

            _try_compile(block.pattern_inside, "pattern-inside", errors)
            _try_compile(block.pattern_not_inside, "pattern-not-inside", errors)
        elif isinstance(block, MatchFileContainsBlock):
            for p in block.has_patterns:
                _try_compile(p, "has", errors)
            for p in block.not_has_patterns:
                _try_compile(p, "not_has", errors)


def _validate_file_conditions(node: RuleNode, errors: List[str]):
    """Validate the regexes in requires blocks (file conditions)."""
    for fc in node.file_conditions:
        for p in fc.has_patterns:
            _try_compile(p, "requires has", errors)
        for p in fc.not_has_patterns:
            _try_compile(p, "requires not_has", errors)


def _validate_taint_patterns(node: RuleNode, errors: List[str]):
    """Validate regex compilability for taint patterns."""
    for src in node.sources:
        _try_compile(src.pattern, "source", errors)
    for snk in node.sinks:
        _try_compile(snk.pattern, "sink", errors)
    for san in node.sanitizers:
        _try_compile(san.pattern, "sanitizer", errors)


def _try_compile(pattern: str, field_name: str, errors: List[str]):
    """Attempt to compile a regex. Appends an error if invalid."""
    if not pattern:
        return
    try:
        re.compile(pattern)
    except re.error as e:
        errors.append(f"Regex invalide dans {field_name} : {e}")
