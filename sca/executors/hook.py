"""
python_hook executor — calls Python functions for detection.

The hook is identified by a `"module.function"` path. The module is
imported via importlib, then the function is called with (runner, filepath, lines).
"""
import importlib
import logging

logger = logging.getLogger("sca.executors.hook")


def execute(runner, rule: dict, filepath: str, all_lines: list):
    """Run a rule's Python hook function against a file, recording each returned finding."""
    hook_path = rule.get("hook")
    if not hook_path or "." not in hook_path:
        return

    module_name, func_name = hook_path.rsplit(".", 1)

    try:
        hook_module = importlib.import_module(module_name)
    except Exception as e:
        logger.warning("Hook module '%s' introuvable : %s", module_name, e)
        return

    hook_fn = getattr(hook_module, func_name, None)
    if hook_fn is None:
        logger.warning("Hook '%s' introuvable dans %s", func_name, module_name)
        return

    try:
        results = hook_fn(runner, filepath, all_lines)
    except Exception as e:
        logger.warning("Hook '%s' a echoue sur %s: %s", hook_path, filepath, e)
        return

    rule_id = rule["id"]
    msg = runner._resolve_i18n(rule.get("message", {}))
    risk = runner._resolve_i18n(rule.get("risk", {}))
    solution = runner._resolve_i18n(rule.get("solution", {}))
    benefit = runner._resolve_i18n(rule.get("benefit", {}))

    for line_num, code, confidence in results:
        if runner._finding_exists(filepath, line_num, rule_id):
            continue

        runner._add_finding(
            rule["category"].upper(), msg, filepath, line_num, code,
            rule["severity"], risk, solution, benefit,
            confidence=confidence, rule_key=rule_id,
        )

        cat_key = rule["category"].upper()
        if cat_key in runner.categories:
            for f in runner.categories[cat_key].findings:
                if f.file == runner._rel(filepath) and f.line == line_num and f.rule_key == rule_id:
                    f.rule_source = rule.get("_source", "json_builtin")
                    break
