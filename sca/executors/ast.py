"""
AST executor — S-expression queries via tree-sitter.

Tree-sitter is optional. If unavailable, AST rules are skipped.
"""
import logging

logger = logging.getLogger("sca.executors.ast")


def execute_rules(runner, rules: list, language: str):
    """Run AST rules against every file of the given language."""
    try:
        from sca import treesitter_engine
    except ImportError:
        logger.info("[ast] tree-sitter indisponible — regles AST skippees")
        return

    if treesitter_engine is None or not treesitter_engine.has_treesitter():
        logger.info("[ast] tree-sitter non installe — regles AST skippees")
        return

    if not hasattr(runner, "_ts_manager"):
        runner._ts_manager = treesitter_engine.TreeSitterManager()

    if not runner._ts_manager.has_language(language):
        logger.info("[ast] Grammaire indisponible pour '%s'", language)
        return

    files = runner._get_files_for_language(language)

    for filepath in files:
        tree = runner._ts_manager.parse_file(filepath, language)
        if tree is None:
            continue

        for rule in rules:
            _execute_ast_rule(runner, rule, filepath, tree, language)


def _execute_ast_rule(runner, rule: dict, filepath: str, tree, language: str):
    """Run a single AST rule's patterns against an already-parsed tree, emitting a finding per match."""
    rule_id = rule["id"]
    msg = runner._resolve_i18n(rule.get("message", {}))
    risk = runner._resolve_i18n(rule.get("risk", {}))
    solution = runner._resolve_i18n(rule.get("solution", {}))
    benefit = runner._resolve_i18n(rule.get("benefit", {}))

    for pattern_entry in rule.get("ast_patterns", []):
        pattern = pattern_entry.get("pattern")
        if not pattern:
            continue

        try:
            matches = runner._ts_manager.query(tree, language, pattern)
        except ValueError as e:
            logger.warning("[ast] Query invalide dans %s : %s", rule_id, e)
            continue
        except Exception as e:
            logger.warning("[ast] Erreur query %s sur %s : %s", rule_id, filepath, e)
            continue

        for match in matches:
            node = match.get("node")
            if node is None:
                continue

            line_num = runner._ts_manager.get_node_line(node)

            if runner._finding_exists(filepath, line_num, rule_id):
                continue

            code = runner._get_line_content(filepath, line_num)

            runner._add_finding(
                rule["category"].upper(), msg, filepath, line_num, code,
                rule["severity"], risk, solution, benefit,
                confidence=rule.get("confidence", 80), rule_key=rule_id,
            )

            cat_key = rule["category"].upper()
            if cat_key in runner.categories:
                for f in runner.categories[cat_key].findings:
                    if f.file == runner._rel(filepath) and f.line == line_num and f.rule_key == rule_id:
                        f.rule_source = rule.get("_source", "json_builtin")
                        break
