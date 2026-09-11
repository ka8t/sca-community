"""
.sca DSL compiler → JSON format compatible with rule_loader.py.

Transforms a RuleNode (intermediate AST) into a JSON dict identical
to the format produced by the existing .json files in sca/rules/builtin/.

Automatic mode inference when absent:
  - match_blocks present → regex (or ast if MatchAstBlock)
  - file_conditions present → file_contains
  - sources/sinks present → taint
  - hook present → python_hook
  - Supported combinations: match + file_conditions, match + taint
"""
from typing import Dict, List

from sca.dsl.nodes import (
    FileConditionBlock,
    MatchAstBlock,
    MatchFileContainsBlock,
    MatchRegexBlock,
    RuleNode,
)


def compile_to_json(node: RuleNode) -> dict:
    """Compile a RuleNode into a JSON dict compatible with rule_loader.py."""
    # Infer the mode if absent
    mode = node.mode or _infer_mode(node)

    result = {
        "id": node.id,
        "language": node.language,
        "category": node.category or "security",
        "severity": node.severity,
        "confidence": node.confidence,
        "mode": mode,
        "message": dict(node.message.texts) if node.message.texts else {},
    }

    # Optional i18n fields — if absent, rule_engine fills them in
    # from locales/report/*.json via self._rule(rule_key).
    if node.risk.texts:
        result["risk"] = dict(node.risk.texts)
    if node.solution.texts:
        result["solution"] = dict(node.solution.texts)
    if node.benefit.texts:
        result["benefit"] = dict(node.benefit.texts)
    if node.fix_before:
        result["fix_before"] = node.fix_before
    if node.fix_after:
        result["fix_after"] = node.fix_after

    # Requires (license)
    result["requires"] = {
        "min_tier": node.license.min_tier,
        "features": list(node.license.features),
        "demo_fallback": node.license.demo_fallback,
    }

    # Metadata (compliance)
    meta = {}
    if node.metadata.cwe:
        meta["cwe"] = list(node.metadata.cwe)
    if node.metadata.cve:
        meta["cve"] = list(node.metadata.cve)
    if node.metadata.owasp:
        meta["owasp"] = node.metadata.owasp
    if node.metadata.iso27001:
        meta["iso27001"] = list(node.metadata.iso27001)
    if node.metadata.asvs:
        meta["asvs"] = list(node.metadata.asvs)
    if node.metadata.wcag:
        meta["wcag"] = list(node.metadata.wcag)
    # the rule-generation extension provenance (see CONSTRAINTS.md C9) — empty for any builtin
    # or manually written custom rule.
    if node.metadata.generated_by:
        meta["generated_by"] = node.metadata.generated_by
    if node.metadata.generated_at:
        meta["generated_at"] = node.metadata.generated_at
    if node.metadata.generator_version:
        meta["generator_version"] = node.metadata.generator_version
    if node.metadata.manifest_hash:
        meta["manifest_hash"] = node.metadata.manifest_hash
    if node.metadata.org_id:
        meta["org_id"] = node.metadata.org_id
    if node.metadata.signature:
        meta["signature"] = node.metadata.signature
    if meta:
        result["metadata"] = meta

    # --- Mode-specific content ---

    # Regex patterns
    if mode in ("regex", "regex+taint"):
        result["patterns"] = _compile_regex_blocks(node.match_blocks)

    # Sources, sinks, sanitizers (taint)
    if mode in ("taint", "regex+taint"):
        result["sources"] = [
            {"pattern": s.pattern, "kind": s.kind}
            for s in node.sources
        ]
        result["sinks"] = [
            {"pattern": s.pattern, "arg_index": s.arg_index}
            for s in node.sinks
        ]
        if node.sanitizers:
            result["sanitizers"] = [
                {"pattern": s.pattern}
                for s in node.sanitizers
            ]
        if node.passthroughs:
            result["passthroughs"] = [
                {"pattern": p.pattern}
                for p in node.passthroughs
            ]

    # AST patterns (tree-sitter S-expressions)
    if mode == "ast":
        result["ast_patterns"] = _compile_ast_blocks(node.match_blocks)

    # File contains — from match_blocks (old format) or file_conditions (new)
    if mode == "file_contains" or node.file_conditions:
        fc = _compile_file_conditions(node)
        if fc["has"] or fc["not_has"] or fc.get("min_lines") or fc.get("path_contains") or fc.get("not_path_has_file"):
            result["file_contains"] = fc

    # Python hook
    if mode == "python_hook":
        result["hook"] = node.hook

    return result


def _infer_mode(node: RuleNode) -> str:
    """Infer the execution mode from the blocks present in the rule.

    Priority:
      1. hook present → python_hook
      2. sources/sinks → taint (or regex+taint if match_blocks too)
      3. match_blocks with MatchAstBlock → ast
      4. match_blocks with MatchRegexBlock → regex
      5. file_conditions or MatchFileContainsBlock → file_contains
      6. Default → regex
    """
    if node.hook:
        return "python_hook"

    has_taint = bool(node.sources or node.sinks)
    has_regex = any(isinstance(b, MatchRegexBlock) for b in node.match_blocks)
    has_ast = any(isinstance(b, MatchAstBlock) for b in node.match_blocks)
    has_fc_blocks = any(isinstance(b, MatchFileContainsBlock) for b in node.match_blocks)
    has_fc_conditions = bool(node.file_conditions)

    if has_taint and has_regex:
        return "regex+taint"
    if has_taint:
        return "taint"
    if has_ast:
        return "ast"
    if has_regex:
        return "regex"
    if has_fc_blocks or has_fc_conditions:
        return "file_contains"

    return "regex"


def _text_to_regex(text: str) -> str:
    """Convert plain text into a regex.

    Escapes every special character except:
      - `*`, which is converted to `.*` (wildcard = anything)
    """
    import re
    # Replace * with a unique placeholder
    placeholder = "\x00STAR\x00"
    text = text.replace("*", placeholder)
    # Escape everything
    text = re.escape(text)
    # Restore the * markers as .*
    text = text.replace(re.escape(placeholder), ".*")
    return text


def _compile_regex_blocks(blocks: List) -> List[dict]:
    """Compile MatchRegexBlock instances into a list of JSON pattern entries.

    Blocks with is_text=True are converted from plain text to regex
    via _text_to_regex() (escaping + * → .*).
    """
    patterns = []
    for block in blocks:
        if not isinstance(block, MatchRegexBlock):
            continue

        pattern = _text_to_regex(block.pattern) if block.is_text else block.pattern

        p = {
            "pattern": pattern,
            "match": block.scope,
        }
        if block.with_pattern:
            p["with"] = _text_to_regex(block.with_pattern) if block.with_is_text else block.with_pattern
        if block.pattern_not:
            p["pattern-not"] = _text_to_regex(block.pattern_not) if block.pattern_not_is_text else block.pattern_not
        if block.pattern_inside:
            p["pattern-inside"] = block.pattern_inside
        if block.pattern_not_inside:
            p["pattern-not-inside"] = block.pattern_not_inside
        patterns.append(p)
    return patterns


def _compile_ast_blocks(blocks: List) -> List[dict]:
    """Compile MatchAstBlock instances into a list of JSON AST patterns."""
    patterns = []
    for block in blocks:
        if not isinstance(block, MatchAstBlock):
            continue
        patterns.append({"pattern": block.pattern})
    return patterns


def _compile_file_conditions(node: RuleNode) -> dict:
    """Compile file conditions (file_conditions + match file_contains).

    Merges the two sources:
    - node.file_conditions (new format: `requires` block with has/not_has)
    - node.match_blocks entries of type MatchFileContainsBlock (old format: `match file_contains`)
    """
    result = {"has": [], "not_has": [], "scope": "file"}

    # Old format: match file_contains
    for block in node.match_blocks:
        if isinstance(block, MatchFileContainsBlock):
            result["has"].extend(block.has_patterns)
            result["not_has"].extend(block.not_has_patterns)
            result["scope"] = block.scope

    # New format: requires (file conditions)
    for fc in node.file_conditions:
        result["has"].extend(fc.has_patterns)
        result["not_has"].extend(fc.not_has_patterns)
        if fc.path_contains:
            result["path_contains"] = list(fc.path_contains)
        if fc.not_path_has_file:
            result["not_path_has_file"] = list(fc.not_path_has_file)
        if fc.min_lines > 0:
            result["min_lines"] = fc.min_lines
        if fc.scope != "file":
            result["scope"] = fc.scope

    return result
